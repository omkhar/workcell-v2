// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// rawConn is one end of the channel as a raw descriptor. The duplicate of the
// init's connection shares its file description, so nothing here changes a
// flag on it; every write polls first and gives up after a wait.
type rawConn struct{ fd int }

func (c *rawConn) close() { unix.Close(c.fd) }

// write sends all of b, waiting at most wait for the peer to take it.
func (c *rawConn) write(b []byte, wait time.Duration) error {
	by := time.Now().Add(wait)
	for len(b) > 0 {
		left := time.Until(by)
		if left <= 0 {
			return errors.New("the host stopped taking bytes")
		}
		fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLOUT}}
		if _, err := unix.Poll(fds, int(left/time.Millisecond)+1); err != nil && err != unix.EINTR {
			return err
		}
		n, err := unix.Write(c.fd, b)
		switch {
		case err == unix.EAGAIN || err == unix.EINTR:
			continue
		case err != nil:
			return err
		}
		b = b[n:]
	}
	return nil
}

// channelPeer is the host end as the guest's socket names it: cid and port
// for vsock:<cid>:<port>, path for unix:<path>.
type channelPeer struct {
	vsock     bool
	cid, port uint32
	path      string
}

func parsePeer(addr string) (channelPeer, error) {
	kind, rest, ok := strings.Cut(addr, ":")
	if !ok {
		return channelPeer{}, errors.New("channel address " + addr + ": want kind:address")
	}
	switch kind {
	case "unix":
		return channelPeer{path: rest}, nil
	case "vsock":
		cid, port, ok := strings.Cut(rest, ":")
		c, err1 := strconv.ParseUint(cid, 10, 32)
		p, err2 := strconv.ParseUint(port, 10, 32)
		if !ok || err1 != nil || err2 != nil {
			return channelPeer{}, fmt.Errorf("vsock address %q: want cid:port", rest)
		}
		return channelPeer{vsock: true, cid: uint32(c), port: uint32(p)}, nil
	}
	return channelPeer{}, errors.New("channel address " + addr + ": unknown kind")
}

func (p channelPeer) sockaddr() unix.Sockaddr {
	if p.vsock {
		return &unix.SockaddrVM{CID: p.cid, Port: p.port}
	}
	return &unix.SockaddrUnix{Name: p.path}
}

func (p channelPeer) matches(sa unix.Sockaddr) bool {
	switch sa := sa.(type) {
	case *unix.SockaddrVM:
		return p.vsock && sa.CID == p.cid && sa.Port == p.port
	case *unix.SockaddrUnix:
		return !p.vsock && sa.Name == p.path
	}
	return false
}

// stealChannel takes a duplicate of the channel connection that pid 1 holds,
// as root with CAP_SYS_PTRACE may (pidfd_getfd), found among its descriptors
// by the peer it is connected to. What is written on it is indistinguishable
// from what the init writes.
func stealChannel(addr string) (*rawConn, error) {
	peer, err := parsePeer(addr)
	if err != nil {
		return nil, err
	}
	pidfd, err := unix.PidfdOpen(1, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open(1): %w", err)
	}
	defer unix.Close(pidfd)
	var seen []string
	for n := 0; n < 256; n++ {
		fd, err := unix.PidfdGetfd(pidfd, n, 0)
		if err != nil {
			if n == 0 && err != unix.EBADF {
				return nil, fmt.Errorf("pidfd_getfd(1, 0): %w", err)
			}
			continue
		}
		sa, err := unix.Getpeername(fd)
		if err == nil && peer.matches(sa) {
			return &rawConn{fd: fd}, nil
		}
		if err == nil {
			seen = append(seen, fmt.Sprintf("%d:%T", n, sa))
		}
		unix.Close(fd)
	}
	return nil, fmt.Errorf("pid 1 holds no socket connected to %s (connected sockets: %v)", addr, seen)
}

// dialChannel opens a fresh connection to the host end at addr.
func dialChannel(addr string) (*rawConn, error) {
	peer, err := parsePeer(addr)
	if err != nil {
		return nil, err
	}
	family := unix.AF_UNIX
	if peer.vsock {
		family = unix.AF_VSOCK
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Connect(fd, peer.sockaddr()); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	return &rawConn{fd: fd}, nil
}
