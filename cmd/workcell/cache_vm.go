// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/workspace"
	"golang.org/x/sys/unix"
)

// openCaches readies the caches a session asked for: each image named, a missing one made when
// the session may write it, and each locked for the life of the session, so that readers
// share, one writer excludes all, and no reader sees an image another guest is writing.
// free is the room a new image has. release closes the locks; it is never nil, and the
// caller calls it when the session ends, or now if err is set.
func openCaches(data string, want []vmm.Cache, free int64) (got []vmm.Cache, release func(), err error) {
	var locks []*os.File
	release = func() {
		for _, f := range locks {
			f.Close()
		}
	}
	for _, c := range want {
		c.Image = cachePath(data, c.Name)
		if _, err := os.Stat(c.Image); !c.Writable && errors.Is(err, fs.ErrNotExist) {
			return nil, release, fmt.Errorf("cache %s does not exist yet; create it with --cache %[1]s:rw", c.Name)
		}
		lock, err := lockCache(filepath.Dir(c.Image), c)
		if err != nil {
			return nil, release, err
		}
		locks = append(locks, lock)
		if _, err := os.Stat(c.Image); c.Writable && errors.Is(err, fs.ErrNotExist) {
			if err := createCache(c.Image, free); err != nil {
				return nil, release, err
			}
		}
		got = append(got, c)
	}
	return got, release, nil
}

// lockCache takes the lock of c in dir without waiting: shared for a reader, exclusive for a
// writer. Closing the file releases it. A lock that is taken is a refusal that says which.
func lockCache(dir string, c vmm.Cache) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, c.Name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how, busy := unix.LOCK_SH, "cache %s is in use read-write by another session"
	if c.Writable {
		how, busy = unix.LOCK_EX, "cache %s is in use by another session; wait, or run without :rw"
	}
	for {
		err = unix.Flock(int(f.Fd()), how|unix.LOCK_NB)
		if err != unix.EINTR {
			break
		}
	}
	if err == unix.EWOULDBLOCK {
		err = fmt.Errorf(busy, c.Name)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// createCache makes an empty image at image with the writer the workspace uses, under a
// temporary name in its directory, so that a half-written image is never attached.
func createCache(image string, free int64) error {
	tmp, err := os.MkdirTemp(filepath.Dir(image), "new")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	built := filepath.Join(tmp, "image") // inside the empty directory it is the image of: Export leaves it out
	if _, err := workspace.Export(context.Background(), tmp, built, free); err != nil {
		return fmt.Errorf("create the cache image: %w", err)
	}
	return os.Rename(built, image)
}
