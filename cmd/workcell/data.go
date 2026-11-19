// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// dataDir is where the pinned artifacts live: $XDG_DATA_HOME/workcell, or ~/.local/share/workcell.
// update and doctor fill it; run only reads it.
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

// holds is the error for a directory that holds, or lies inside, workcell's data or config directory, named: a session there would carry the
// audit key, other sessions, their records and the images into the guest, and pull would write the guest's versions back (I7, I9, I13).
func holds(dir string) error {
	data, err := dataDir()
	if err != nil {
		return err
	}
	config, _ := xdgDir("XDG_CONFIG_HOME", ".config") // fails only as dataDir does
	for _, held := range []string{data, config} {
		if within(dir, held) || within(held, dir) { // neither need exist yet
			return fmt.Errorf("%s lies inside or holds workcell's own directory %s, which no session may see: use another directory", dir, held)
		}
	}
	return nil
}

// within says whether p is dir itself or lies under it, both resolved: the relation holds and session's temp-directory check share.
func within(dir, p string) bool {
	rel, err := filepath.Rel(resolved(dir), resolved(p))
	return err == nil && filepath.IsLocal(rel) // "." or below
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
