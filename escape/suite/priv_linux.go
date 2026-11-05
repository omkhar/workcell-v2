// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	"golang.org/x/sys/unix"
)

// A canary or a resolver on a port below 1024 needs root on the test host,
// which the suite does not have on a hosted runner, where sudo answers
// without a password. So the payload binds it as root and hands the
// descriptor over (sandbox.RootBind): the judge stays what it is, and root
// ran one bind. The same payload, entered as root into a session's own
// network namespace, binds the judge's canaries there.

// privileged binds network/addr in the host's own network as root, through
// the payload (sandbox.RootBind).
func privileged(network, addr, payload string) (net.Listener, net.PacketConn, error) {
	return sandbox.RootBind(network, addr, payload, 0)
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
// device up with addr, dials the judge at path, says its pid, and stays
// until the judge hangs up. The product runs in /proc/<pid>/ns/net
// meanwhile, and the judge's canaries are bound there through the same
// payload (sandbox.RootBind).
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
	fmt.Fprintf(c, "pid %d\n", os.Getpid())
	io.Copy(io.Discard, c)
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
