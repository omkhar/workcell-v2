// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// dialVsock connects to <cid>:<port> over AF_VSOCK, as a guest reaches the
// host end of a vsock channel.
func dialVsock(addr string) (net.Conn, error) {
	cid, port, ok := strings.Cut(addr, ":")
	c, err1 := strconv.ParseUint(cid, 10, 32)
	p, err2 := strconv.ParseUint(port, 10, 32)
	if !ok || err1 != nil || err2 != nil {
		return nil, fmt.Errorf("vsock address %q: want cid:port", addr)
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: uint32(c), Port: uint32(p)}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("vsock connect %s: %w", addr, err)
	}
	f := os.NewFile(uintptr(fd), "vsock")
	defer f.Close()
	return net.FileConn(f)
}
