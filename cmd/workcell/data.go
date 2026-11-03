// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"
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

// artifacts are the four files a session boots from, and the directory they are in.
type artifacts struct{ firecracker, kernel, initrd, image, dir string }

// findArtifacts names the files in dir and says which one is missing, if any.
func findArtifacts(dir string) (artifacts, error) {
	a := artifacts{
		firecracker: filepath.Join(dir, "firecracker"),
		kernel:      filepath.Join(dir, "vmlinux"),
		initrd:      filepath.Join(dir, "initrd.cpio"),
		image:       filepath.Join(dir, "root.ext4"),
		dir:         dir,
	}
	for _, p := range []string{a.firecracker, a.kernel, a.initrd, a.image} {
		if _, err := os.Stat(p); err != nil {
			return a, fmt.Errorf("%s is missing", p)
		}
	}
	return a, nil
}
