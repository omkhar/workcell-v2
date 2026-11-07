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
func xdgDir(env string, home ...string) (string, error) {
	if x := os.Getenv(env); x != "" {
		return filepath.Join(x, "workcell"), nil
	}
	h, err := os.UserHomeDir()
	return filepath.Join(append(append([]string{h}, home...), "workcell")...), err
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
	a := artifacts{
		kernel: filepath.Join(dir, "vmlinux"),
		initrd: filepath.Join(dir, "initrd.cpio"),
		image:  filepath.Join(dir, "root.ext4"),
		dir:    dir,
	}
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
