// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/omkhar/workcell/v2/internal/fileserve"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// mountFUSE makes /workspace the host's own tree (ADR-005, mount mode): it opens /dev/fuse,
// dials the host's file service and mounts, and from then on a copier carries the kernel's raw
// requests out and the host's raw replies back. The init parses none of it; the host checks all
// of it (A1).
func mountFUSE() error {
	if err := os.MkdirAll("/workspace", 0o755); err != nil {
		return err
	}
	if err := unix.Mknod("/dev/fuse", unix.S_IFCHR|0o666, int(unix.Mkdev(10, 229))); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("mknod /dev/fuse: %w", err)
	}
	dev, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/fuse: %w", err)
	}
	host, err := dial(fileserve.Port, 5*time.Second)
	if err != nil {
		_ = unix.Close(dev)
		return err
	}
	opts := "fd=" + strconv.Itoa(dev) + ",rootmode=40000,user_id=0,group_id=0,max_read=" + strconv.Itoa(fileserve.MaxWrite)
	if err := unix.Mount("workcell", "/workspace", "fuse", unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
		_ = unix.Close(dev)
		_ = host.Close()
		return fmt.Errorf("mount fuse: %w", err)
	}
	go copyFUSE(dev, host)
	return nil
}

// copyFUSE is the whole guest side of the mount: each read of dev is one request and goes to
// the host as one frame, and each frame back is one reply, written to dev in one write. It
// ends when the mount is gone, which the read reports as ENODEV, or when the host's stream
// does, in which case it aborts the mount itself, so that no process waits on a reply that
// will never come. dev is touched by raw syscalls from these two goroutines alone: an
// *os.File would put it in the runtime's poller, and the init never touches its own mount
// through the os package (ADR-005).
func copyFUSE(dev int, host *os.File) {
	c := wire.New(host, frameLimit)
	replied := make(chan struct{})
	go func() {
		defer close(replied)
		for {
			f, err := c.ReadFrame()
			if err != nil {
				fmt.Fprintln(os.Stderr, "workcell-init: workspace: host:", err)
				abortFUSE()
				return
			}
			_, _ = unix.Write(dev, f.Payload) // ENOENT: the kernel dropped the request meanwhile
		}
	}()
	// A request is at most 80 bytes plus MaxWrite, and the kernel refuses a read buffer smaller
	// than that, so one request always fits one frame.
	buf := make([]byte, wire.MaxPayload)
	for {
		n, err := unix.Read(dev, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			if !errors.Is(err, unix.ENODEV) {
				fmt.Fprintln(os.Stderr, "workcell-init: workspace: read /dev/fuse:", err)
			}
			break
		}
		if err := c.WriteFrame(wire.Frame{Type: fileserve.FrameType, Payload: buf[:n]}); err != nil {
			fmt.Fprintln(os.Stderr, "workcell-init: workspace: host:", err)
			break
		}
	}
	abortFUSE()
	_ = host.Close() // ends the reply loop, if the host had not
	<-replied
	_ = unix.Close(dev) // the last reference: the kernel drops the connection if it had not
}

// abortFUSE ends the connection behind /workspace: a forced unmount is how the kernel is told
// to fail every request in flight, so a process waiting on the host gets ECONNABORTED and
// every later call ENOTCONN, and the copier's read ends with ENODEV. Where no FUSE mount is
// there, as in clone mode, it does nothing that matters: an idle ext4 workspace is unmounted,
// a busy one stays. Guest root may hide the mount from this (A1); the host ends the VM
// from outside regardless.
func abortFUSE() {
	_ = unix.Unmount("/workspace", unix.MNT_FORCE)
}
