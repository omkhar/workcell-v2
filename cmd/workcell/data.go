// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// dataDir is where the pinned artifacts live: $XDG_DATA_HOME/workcell, or
// ~/.local/share/workcell. update and doctor fill it; run only reads it.
func dataDir() (string, error) {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "workcell"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "workcell"), nil
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
