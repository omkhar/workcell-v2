// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command guest is PID 1 of the test guest for internal/vmm/firecracker. It dials
// the host over vsock, says hello, waits until the host hangs up and reboots,
// which with reboot=k on the command line ends the Firecracker process (the exit
// path the U-101 spike measured). It never returns: a PID 1 that exits panics the
// kernel. The kernel's built-in initramfs provides /dev/console as fds 0 to 2.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const port = 5000 // the host listens on <vsock>_5000

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "guest:", err)
	}
	for {
		fmt.Fprintln(os.Stderr, "guest: reboot:", unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART))
		time.Sleep(time.Second)
	}
}

func run() error {
	conn, err := connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := fmt.Fprintln(conn, "hello"); err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, conn) // until the host hangs up
	return err
}

// connect dials the host (CID 2). The device may still be probing when the
// guest starts, so it retries for 5 s.
func connect() (*os.File, error) {
	var err error
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		var fd int
		if fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			continue
		}
		if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err == nil {
			return os.NewFile(uintptr(fd), "vsock"), nil
		}
		_ = unix.Close(fd)
	}
	return nil, fmt.Errorf("vsock connect: %w", err)
}
