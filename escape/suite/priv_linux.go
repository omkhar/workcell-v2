// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
	var f *os.File
	var err error
	if strings.HasPrefix(network, "udp") {
		var pc net.PacketConn
		if pc, err = net.ListenPacket(network, addr); err == nil {
			f, err = pc.(*net.UDPConn).File()
		}
	} else {
		var ln net.Listener
		if ln, err = net.Listen(network, addr); err == nil {
			f, err = ln.(*net.TCPListener).File()
		}
	}
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
