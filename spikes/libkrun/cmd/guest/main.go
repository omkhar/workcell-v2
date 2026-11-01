// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command guest is the exec target inside the spike's microVM. It mounts the
// shared directory, tries the host loopback probe, talks to the host over
// vsock, writes the echo back to the shared directory and exits 7.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const exitCode = 7

func main() {
	code := exitCode
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guest:", err)
		code = 1
	}
	if os.Getpid() == 1 { // no init.krun: report the code to the VMM the way it does
		if fd, err := unix.Open("/", unix.O_RDONLY, 0); err == nil {
			_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), 0x7602, uintptr(code))
		}
		unix.Sync()
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	}
	os.Exit(code)
}

func run() error {
	if err := unix.Mount("work", "/work", "virtiofs", 0, ""); err != nil {
		return fmt.Errorf("mount work: %w", err)
	}
	token, err := os.ReadFile("/work/from-host.txt")
	if err != nil {
		return err
	}
	probe, err := os.ReadFile("/work/probe.txt")
	if err != nil {
		return err
	}
	loopback := "err"
	if c, err := net.DialTimeout("tcp", strings.TrimSpace(string(probe)), 2*time.Second); err == nil {
		loopback = "ok"
		_ = c.Close()
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: 5000}); err != nil {
		return fmt.Errorf("vsock connect: %w", err)
	}
	conn := os.NewFile(uintptr(fd), "vsock")
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "hello %s loopback=%s\n", strings.TrimSpace(string(token)), loopback); err != nil {
		return err
	}
	echo, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read echo: %w", err)
	}
	return os.WriteFile("/work/from-guest.txt", []byte(echo), 0o644)
}
