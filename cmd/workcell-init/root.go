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
func rootDevice(cmdline string) string { return device(cmdline, "root=") }

// workspaceDevice is the device named by the last workcell.workspace= on the command line,
// or "" if there is none: the copy of the repository (clone mode, ADR-002).
func workspaceDevice(cmdline string) string { return device(cmdline, "workcell.workspace=") }

// mounted reports whether the last workcell.mount= on the command line is 1: mount mode
// (ADR-005), in which /workspace is the host's own tree, served by the host over vsock, and
// no workspace disk is passed.
func mounted(cmdline string) bool { return value(cmdline, "workcell.mount=") == "1" }

// layer is one provider layer the host attached: the agent's name and the read-only drive
// that holds its image, mounted read-only at /opt/<name> so that no session changes it (I7).
type layer struct{ name, dev string }

// layers is every workcell.layer=<agent>:<device> on the kernel command line, in order. The
// host wrote the line (A1); an entry that is not a plain name and a device is skipped.
func layers(cmdline string) []layer {
	var ls []layer
	for _, f := range strings.Fields(cmdline) {
		v, ok := strings.CutPrefix(f, "workcell.layer=")
		name, dev, cut := strings.Cut(v, ":")
		if ok && cut && name != "" && !strings.ContainsAny(name, "/.") && strings.HasPrefix(dev, "/dev/") {
			ls = append(ls, layer{name, dev})
		}
	}
	return ls
}

// cache is one dependency cache the host attached: its name, the drive that holds its image
// and whether the host attached the drive writable.
type cache struct {
	name, dev string
	rw        bool
}

// caches is every workcell.cache=<name>:<device>:<ro|rw> on the kernel command line, in order. The
// host wrote the line (A1); an entry that is not a plain name, a device and a mode is skipped.
func caches(cmdline string) []cache {
	var cs []cache
	for _, f := range strings.Fields(cmdline) {
		v, ok := strings.CutPrefix(f, "workcell.cache=")
		parts := strings.Split(v, ":")
		if ok && len(parts) == 3 && parts[0] != "" && !strings.ContainsAny(parts[0], "/.") &&
			strings.HasPrefix(parts[1], "/dev/") && (parts[2] == "ro" || parts[2] == "rw") {
			cs = append(cs, cache{parts[0], parts[1], parts[2] == "rw"})
		}
	}
	return cs
}

// value is what the last key on the kernel command line says, "" if there is none. The host
// wrote the line (A1).
func value(cmdline, key string) string {
	v := ""
	for _, f := range strings.Fields(cmdline) {
		if s, ok := strings.CutPrefix(f, key); ok {
			v = s
		}
	}
	return v
}

func device(cmdline, key string) string {
	if v := value(cmdline, key); strings.HasPrefix(v, "/dev/") {
		return v
	}
	return ""
}

// diskMiB is the writable-space cap in the last workcell.disk= on the kernel command line, or 0
// for none. It sizes the tmpfs mounts; it is a courtesy so that the guest sees ENOSPC at the
// cap. The host's memory cap is what holds, since a tmpfs lives in guest RAM (A1).
func diskMiB(cmdline string) int {
	if n, err := strconv.ParseUint(value(cmdline, "workcell.disk="), 10, 31); err == nil {
		return int(n)
	}
	return 0
}

// ports is the list in the last workcell.ports= on the kernel command line: the TCP ports the
// init relays to the host (ADR-003), none when there is no list or it is empty. The host wrote
// it (A1); an entry that is not a port is an error, so that the console says so.
func ports(cmdline string) ([]uint16, error) {
	v := value(cmdline, "workcell.ports=")
	if v == "" {
		return nil, nil
	}
	var ps []uint16
	for _, s := range strings.Split(v, ",") {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("workcell.ports: %q is not a port", s)
		}
		ps = append(ps, uint16(n))
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

// mountWorkspace mounts the device that holds the repository read-write at /workspace.
func mountWorkspace(dev string) error {
	if err := os.MkdirAll("/workspace", 0o755); err != nil {
		return err
	}
	if err := unix.Mount(dev, "/workspace", "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount %s: %w", dev, err)
	}
	return nil
}

// mountLayer mounts the layer read-only at /opt/<name>, in the root overlay. The drive is
// read-only on the host, which is what holds (A1); the flag here only says so to the guest.
func mountLayer(l layer) error {
	dir := "/opt/" + l.name
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return unix.Mount(l.dev, dir, "ext4", unix.MS_RDONLY, "")
}

// mountCache puts the cache at /cache/<name>, in the root overlay. A writable drive is mounted as
// it is, and what the session writes stays in the image. A read-only one is mounted read-only
// under an overlay on a tmpfs: the session may write freely and none of it outlives the VM
// (I7), while the image, which the host attached read-only, is never changed (A1).
func mountCache(c cache, disk int) error {
	dir, base := "/cache/"+c.name, "/cache-ro/"+c.name
	for _, d := range []string{dir, base + "/lower", base + "/rw"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if c.rw {
		return unix.Mount(c.dev, dir, "ext4", 0, "")
	}
	if err := unix.Mount(c.dev, base+"/lower", "ext4", unix.MS_RDONLY, ""); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", base+"/rw", "tmpfs", 0, tmpfsSize(disk)); err != nil {
		return err
	}
	for _, d := range []string{"/upper", "/work"} {
		if err := os.Mkdir(base+"/rw"+d, 0o755); err != nil {
			return err
		}
	}
	return unix.Mount("overlay", dir, "overlay", 0, "lowerdir="+base+"/lower,upperdir="+base+"/rw/upper,workdir="+base+"/rw/work")
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
