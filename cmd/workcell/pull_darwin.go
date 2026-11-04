// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package main

import "golang.org/x/sys/unix"

// The three opens of a path the guest chose, beneath a directory the host holds open (R6):
// relative to the descriptor, and O_NOFOLLOW_ANY refuses a symlink in any component. The
// manifest admits no absolute path and no ".." (checkPath), so the path stays beneath.

// openDir opens the directory rel beneath root, or root itself for "".
func dirBeneath(root int, rel string) (int, error) {
	if rel == "" {
		rel = "."
	}
	return unix.Openat(root, rel, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW_ANY|unix.O_CLOEXEC, 0)
}

// createFile makes the file name in the directory open as dir, which must not exist yet.
func createBeneath(dir int, name string, mode uint32) (int, error) {
	return unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW_ANY|unix.O_CLOEXEC, mode)
}

// openFile opens the file rel beneath root for reading.
func fileBeneath(root int, rel string) (int, error) {
	return unix.Openat(root, rel, unix.O_RDONLY|unix.O_NOFOLLOW_ANY|unix.O_CLOEXEC, 0)
}
