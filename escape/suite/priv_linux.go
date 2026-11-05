// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A canary or a resolver on a port below 1024 needs root on the test host,
// which the suite does not have on a hosted runner, where sudo answers
// without a password. So the payload binds it as root and hands the
// descriptor over: the judge stays what it is, and root ran one bind.

// privileged binds network/addr as root, through sudo, and returns the
// listener (tcp) or packet conn (udp) for it.
func privileged(network, addr, payload string) (net.Listener, net.PacketConn, error) {
	dir, err := os.MkdirTemp("", "escape-bind-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "fd")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()
	cmd := exec.Command("sudo", "-n", payload, "bind", network, addr, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("bind %s %s needs root, and sudo -n failed: %v: %s", network, addr, err, bytes.TrimSpace(out))
	}
	ln.SetDeadline(time.Now().Add(2 * time.Second))
	c, err := ln.AcceptUnix()
	if err != nil {
		return nil, nil, fmt.Errorf("bind %s %s as root: no descriptor came back: %w", network, addr, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	oob := make([]byte, 64)
	_, oobn, _, _, err := c.ReadMsgUnix(make([]byte, 1), oob)
	if err != nil {
		return nil, nil, fmt.Errorf("bind %s %s as root: read the descriptor: %w", network, addr, err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err == nil && len(msgs) != 1 {
		err = fmt.Errorf("%d control messages", len(msgs))
	}
	var fds []int
	if err == nil {
		fds, err = syscall.ParseUnixRights(&msgs[0])
	}
	if err == nil && len(fds) != 1 {
		err = fmt.Errorf("%d descriptors", len(fds))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("bind %s %s as root: the descriptor: %w", network, addr, err)
	}
	f := os.NewFile(uintptr(fds[0]), network)
	defer f.Close()
	if strings.HasPrefix(network, "udp") {
		pc, err := net.FilePacketConn(f)
		return nil, pc, err
	}
	l, err := net.FileListener(f)
	return l, nil, err
}

// Bind is the payload as root on the test host: it binds network/addr,
// sends the descriptor to the judge waiting at the unix socket path, and
// exits 0. Any failure is one line on stderr and exit 1.
func Bind(network, addr, path string) int {
	f, err := bindFile(network, addr)
	var c net.Conn
	if err == nil {
		if c, err = net.Dial("unix", path); err == nil {
			_, _, err = c.(*net.UnixConn).WriteMsgUnix([]byte{0}, syscall.UnixRights(int(f.Fd())), nil)
			c.Close()
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bind:", err)
		return 1
	}
	return 0
}

// bindFile binds network/addr and returns the socket as a file.
func bindFile(network, addr string) (*os.File, error) {
	if strings.HasPrefix(network, "udp") {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			return nil, err
		}
		defer pc.Close()
		return pc.(*net.UDPConn).File()
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return ln.(*net.TCPListener).File()
}

// Hold is the payload as the holder of a session's own network namespace,
// started in a fresh one (`unshare -n`) as root: it brings the loopback
// device up with addr, dials the judge at path, says its pid, and binds
// whatever the judge asks for, one "network address" line at a time, each
// answered with "ok" and the socket over SCM_RIGHTS, or with a line saying
// why not, until the judge hangs up. The product runs in /proc/<pid>/ns/net
// meanwhile.
func Hold(path, addr string) int {
	ip4 := net.ParseIP(addr).To4()
	lo, err := net.InterfaceByName("lo")
	switch {
	case ip4 == nil:
		err = fmt.Errorf("%q is not an IPv4 address", addr)
	case err == nil:
		if err = loopbackUp(lo.Name); err == nil {
			err = addrRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, lo.Index, ip4)
		}
	}
	var c net.Conn
	if err == nil {
		c, err = net.Dial("unix", path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netns:", err)
		return 1
	}
	defer c.Close()
	uc := c.(*net.UnixConn)
	fmt.Fprintf(uc, "pid %d\n", os.Getpid())
	sc := bufio.NewScanner(uc)
	for sc.Scan() {
		network, a, _ := strings.Cut(sc.Text(), " ")
		f, err := bindFile(network, a)
		if err != nil {
			fmt.Fprintf(uc, "%v\n", err)
			continue
		}
		uc.WriteMsgUnix([]byte("ok\n"), syscall.UnixRights(int(f.Fd())), nil)
		f.Close()
	}
	return 0
}

// loopbackUp brings the interface up, as `ip link set lo up` does.
func loopbackUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
