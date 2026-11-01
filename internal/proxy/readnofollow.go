// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: rootio/nofollow.go

package proxy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// readFileNoFollow reads one regular file of at most limit bytes. It opens
// each directory from "/" relative to the one before it, and the file last,
// all with O_NOFOLLOW, so a symlink anywhere on the path is refused (R6).
func readFileNoFollow(path, label string, limit int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "darwin" { // /var, /etc and /tmp are symlinks into /private there
		for _, prefix := range []string{"/var", "/etc", "/tmp"} {
			if abs == prefix || strings.HasPrefix(abs, prefix+"/") {
				abs = "/private" + abs
				break
			}
		}
	}
	dir, name := filepath.Split(abs)
	if name == "" {
		return nil, fmt.Errorf("%s must name a file: %s", label, abs)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.Trim(dir, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("open %s: %s: %w", label, abs, err)
		}
		fd = next
	}
	leaf, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	_ = unix.Close(fd)
	if err != nil {
		return nil, fmt.Errorf("open %s: %s: %w", label, abs, err)
	}
	file := os.NewFile(uintptr(leaf), abs)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file: %s", label, abs)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the byte limit of %d: %s", label, limit, abs)
	}
	return data, nil
}
