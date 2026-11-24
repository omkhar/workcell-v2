// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// dataDir is where the pinned artifacts live: $XDG_DATA_HOME/workcell, or ~/.local/share/workcell. update and doctor fill it; run only reads it.
func dataDir() (string, error) { return xdgDir("XDG_DATA_HOME", ".local", "share") }

// xdgDir is workcell's directory under the variable, else under the path beneath the home directory, on every OS alike.
// A relative variable is ignored, as the XDG spec says, and a relative home is an error: neither may name a tree under cwd (I13).
func xdgDir(env string, home ...string) (string, error) {
	if x := os.Getenv(env); filepath.IsAbs(x) {
		return filepath.Join(x, "workcell"), nil
	}
	h, err := os.UserHomeDir()
	if err == nil && !filepath.IsAbs(h) {
		err = fmt.Errorf("home directory %q is not an absolute path", h)
	}
	return filepath.Join(append(append([]string{h}, home...), "workcell")...), err
}

// holds is the error for a directory that holds, or lies inside, workcell's data or config directory, named: a session there would carry the audit key, other
// sessions, their records and the images into the guest, and pull would write the guest's versions back (I7, I9, I13). So is a directory that holds the VMM
// directory of a running session (vmm, under its TMPDIR): the sockets there would lie in the guest's view, or under a pull, for the guest to swap for a link to any host socket of the operator's (I1, I4, I7). A stale record refuses nothing.
func holds(dir string) error {
	data, err := dataDir()
	table, terr := mountTable() // the kernel's own list of mounts: unreadable, the layout cannot be judged, so the error refuses (C65)
	if err = cmp.Or(err, terr); err != nil {
		return err
	}
	config, _ := xdgDir("XDG_CONFIG_HOME", ".config") // fails only as dataDir does
	rows := mounts(string(table))
	for _, held := range []string{data, config} {
		if within(dir, held) || within(held, dir) { // neither need exist yet
			return fmt.Errorf("%q lies inside or holds workcell's own directory %s, which no session may see: use another directory", dir, held)
		}
		if m := aliased(rows, resolved(dir), resolved(held)); m != "" {
			return fmt.Errorf("%q holds the mount point %s, a second name of workcell's own directory %s, of a directory above it or of one inside it, which no session may see: unmount it or use another directory", dir, m, held)
		}
	}
	l, err := list(filepath.Join(data, "sessions"))
	for _, s := range l {
		b, _ := os.ReadFile(filepath.Join(data, "sessions", s.id, "vmm")) // none before boot
		for _, tmp := range strings.Split(string(b), "\n") {
			if s.state == "running" && tmp != "" && within(dir, tmp) {
				return fmt.Errorf("%q holds %s, the VMM directory of the running session %s, whose sockets no guest may see and no pull may write over: wait for it or workcell stop %s first", dir, tmp, s.id, s.id)
			}
		}
	}
	return err
}

// within says whether p is dir itself or lies under it, both resolved: the relation holds and session's temp-directory check share. The kernel judges by identity, not spelling: a bind mount (a firmlink on macOS) gives dir a second name that Rel never relates, so p's ancestors are also compared by inode.
func within(dir, p string) bool {
	if rel, err := filepath.Rel(resolved(dir), resolved(p)); err == nil && filepath.IsLocal(rel) { // "." or below
		return true
	}
	d, err := os.Stat(dir) // absent: dir holds nothing yet
	for q, up := resolved(p), ""; err == nil && q != up; q, up = filepath.Dir(q), q {
		if s, err := os.Stat(q); err == nil && os.SameFile(s, d) {
			return true
		}
	}
	return false
}

// resolved is p absolute, with its symlinks followed: where p does not exist yet, the longest prefix that does is followed and the rest appended.
func resolved(p string) string {
	p, _ = filepath.Abs(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	} else if d := filepath.Dir(p); d != p { // not the root
		return filepath.Join(resolved(d), filepath.Base(p))
	}
	return p
}

// mount is one row of the kernel's mount table: the filesystem's device (major:minor), the path of the mount's root within that filesystem, and the mount point.
type mount struct{ dev, root, point string }

// mounts parses the kernel's mount table, /proc/self/mountinfo: a row per mount, holding the mount ID, its parent, the device, the root, the mount point and more, each a field, with a space, tab, newline or backslash in a path written as octal (\040).
func mounts(table string) (rows []mount) {
	esc := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(table, "\n") {
		if f := strings.Fields(line); len(f) > 4 {
			rows = append(rows, mount{f[2], esc.Replace(f[3]), esc.Replace(f[4])})
		}
	}
	return rows
}

// under says whether p is dir or lies beneath it, by spelling alone: for the kernel's own paths, which are clean already.
func under(dir, p string) bool { return strings.HasPrefix(p+"/", strings.TrimSuffix(dir, "/")+"/") }

// aliased is the mount point at or beneath dir, if any, that is a second name of held, of a directory above it or of one inside it, both resolved. within() cannot relate the two names, since a bind mount is neither a symlink nor an ancestor; the kernel knows a mount by its filesystem's device and its root within it (C65).
func aliased(rows []mount, dir, held string) string {
	var on mount // the mount held lies on: the one with the longest mount point above it, the last of them where one covers another
	for _, m := range rows {
		if under(m.point, held) && len(m.point) >= len(on.point) {
			on = m
		}
	}
	held = filepath.Join(on.root, strings.TrimPrefix(held, on.point)) // held as a path within its filesystem
	for _, m := range rows {
		if under(dir, m.point) && m.dev == on.dev && (under(m.root, held) || under(held, m.root)) {
			return m.point
		}
	}
	return ""
}

// artifacts are the files a session boots from, and the directory they are in: the kernel,
// the initramfs, the root image and, where the backend is a program (vmmBinary), that too.
// run adds the provider layers (findLayers) and the caches (openCaches); pull and bench boot without them.
type artifacts struct {
	binary, kernel, initrd, image, dir string
	layers                             []vmm.Layer
	caches                             []vmm.Cache
}

// required names the files the backend here needs in the data directory, the VMM first.
func required() []string {
	names := []string{"vmlinux", "initrd.cpio", "root.ext4"}
	if vmmBinary != "" {
		names = append([]string{vmmBinary}, names...)
	}
	return names
}

// loadArtifacts is findArtifacts of the data directory.
func loadArtifacts() (artifacts, error) {
	dir, err := dataDir()
	if err != nil {
		return artifacts{}, err
	}
	return findArtifacts(dir)
}

// findArtifacts names the files in dir and says which one is missing, if any.
func findArtifacts(dir string) (artifacts, error) {
	a := artifacts{kernel: filepath.Join(dir, "vmlinux"), initrd: filepath.Join(dir, "initrd.cpio"), image: filepath.Join(dir, "root.ext4"), dir: dir}
	if vmmBinary != "" {
		a.binary = filepath.Join(dir, vmmBinary)
	}
	for _, n := range required() {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return a, fmt.Errorf("%s is missing", filepath.Join(dir, n))
		}
	}
	return a, nil
}
