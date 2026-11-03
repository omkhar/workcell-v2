// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
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

// diskMiB is the writable-space cap in the last workcell.disk= on the kernel command line, or 0
// for none. It sizes the tmpfs mounts; it is a courtesy so that the guest sees ENOSPC at the
// cap. The host's memory cap is what holds, since a tmpfs lives in guest RAM (A1).
func diskMiB(cmdline string) int {
	mib := 0
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "workcell.disk="); ok {
			if n, err := strconv.ParseUint(v, 10, 31); err == nil {
				mib = int(n)
			}
		}
	}
	return mib
}

// ports is the list in the last workcell.ports= on the kernel command line: the TCP ports the
// init relays to the host (ADR-003), none when there is no list or it is empty. The host wrote
// it (A1); an entry that is not a port is an error, so that the console says so.
func ports(cmdline string) ([]uint16, error) {
	var ps []uint16
	for _, f := range strings.Fields(cmdline) {
		v, ok := strings.CutPrefix(f, "workcell.ports=")
		if !ok {
			continue
		}
		ps = nil
		if v == "" {
			continue
		}
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.ParseUint(s, 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("workcell.ports: %q is not a port", s)
			}
			ps = append(ps, uint16(n))
		}
	}
	return ps, nil
}

// tmpfsSize is the mount option that caps a tmpfs at mib MiB, or nothing when mib is 0.
func tmpfsSize(mib int) string {
	if mib == 0 {
		return ""
	}
	return "size=" + strconv.Itoa(mib) + "m"
}

// switchRoot makes the image on dev the root of everything that runs from here on. The
// image is mounted read-only and an overlay on a tmpfs takes every write, so nothing a
// session writes outlives the VM (I7). The pseudo filesystems move across and the init
// chroots into the overlay; it is a static binary already in memory, so it needs no re-exec.
func switchRoot(dev string, disk int) error {
	for _, d := range []string{"/ro", "/rw", "/new"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := unix.Mount(dev, "/ro", "ext4", unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount %s: %w", dev, err)
	}
	if err := unix.Mount("tmpfs", "/rw", "tmpfs", 0, tmpfsSize(disk)); err != nil {
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
