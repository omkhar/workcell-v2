// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// rootDevice is the device named by the last root= on the kernel command line, or "" if
// there is none. The host wrote the command line (A1 lets the init trust it).
func rootDevice(cmdline string) string {
	dev := ""
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "root="); ok && strings.HasPrefix(v, "/dev/") {
			dev = v
		}
	}
	return dev
}

// switchRoot makes the image on dev the root of everything that runs from here on. The
// image is mounted read-only and an overlay on a tmpfs takes every write, so nothing a
// session writes outlives the VM (I7). The pseudo filesystems move across and the init
// chroots into the overlay; it is a static binary already in memory, so it needs no re-exec.
func switchRoot(dev string) error {
	for _, d := range []string{"/ro", "/rw", "/new"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount(dev, "/ro", "ext4", unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount %s: %w", dev, err)
	}
	if err := unix.Mount("tmpfs", "/rw", "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount tmpfs for the overlay: %w", err)
	}
	for _, d := range []string{"/rw/upper", "/rw/work"} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount("overlay", "/new", "overlay", 0, "lowerdir=/ro,upperdir=/rw/upper,workdir=/rw/work"); err != nil {
		return fmt.Errorf("mount overlay: %w", err)
	}
	for _, d := range []string{"/dev", "/proc", "/sys"} { // /dev/pts goes with /dev
		if err := os.MkdirAll("/new"+d, 0o755); err != nil {
			return err
		}
		if err := unix.Mount(d, "/new"+d, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", d, err)
		}
	}
	if err := unix.Chroot("/new"); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}
	return unix.Chdir("/")
}
