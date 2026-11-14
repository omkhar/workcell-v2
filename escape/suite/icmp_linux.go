// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"errors"
	"net"
	"os"
	"syscall"
)

// icmpProbe sends an ICMPv4 echo request to args[0] with the token args[1] as its payload, on a raw socket (root) or a ping socket, and waits 3 seconds
// for an echo reply that carries the token back.
func icmpProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	ip := net.ParseIP(args[0]).To4()
	if ip == nil {
		return Result{Status: "error", Detail: "want an IPv4 address"}
	}
	raw := true
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		raw = false
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	}
	if err != nil {
		return Result{Status: "error", Detail: "no ICMP socket: " + err.Error()}
	}
	defer syscall.Close(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 3})
	token := []byte(args[1])
	to := &syscall.SockaddrInet4{Addr: [4]byte(ip)}
	if err := syscall.Sendto(fd, icmpEcho(uint16(os.Getpid()), 1, token), 0, to); err != nil {
		return Result{Status: "unreachable", Detail: err.Error()}
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return Result{Status: "timeout", Detail: "no echo reply from " + args[0]}
			}
			return Result{Status: "unreachable", Detail: err.Error()}
		}
		if payload, ok := icmpReply(buf[:n], raw); ok && bytes.Equal(payload, token) {
			return Result{Status: "echo-reply", Detail: "from " + args[0]}
		}
	}
}
