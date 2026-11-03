// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"errors"
	"fmt"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// pull answers a Pull with a picture of /workspace as it is: the manifest from guest.Walk,
// then the bytes of each file in that order, then an Exit. The host judges all of it (A1):
// the init enforces nothing. A send that fails means the host is gone, and that error
// comes back; a tree that cannot be read is reported to the host.
func pull(s *server) error {
	root, err := unix.Open("/workspace", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return s.send(guest.TypeExit, guest.EncodeExit(guest.Exit{Err: "open /workspace: " + err.Error()}))
	}
	defer unix.Close(root)
	t := &tree{s: s, root: root}
	fd, err := unix.Dup(root)
	if err == nil {
		err = guest.Walk(fd, t.entry)
	}
	if err == nil {
		err = t.send(guest.TypeEntry, nil)
	}
	for i := 0; err == nil && i < len(t.files); i++ {
		err = t.file(t.files[i])
	}
	switch {
	case t.lost != nil:
		return t.lost
	case err != nil:
		return s.send(guest.TypeExit, guest.EncodeExit(guest.Exit{Err: err.Error()}))
	}
	return s.send(guest.TypeExit, guest.EncodeExit(guest.Exit{}))
}

type tree struct {
	s     *server
	root  int
	files []guest.Entry // the regular files with bytes to send, in manifest order
	lost  error         // the first send that failed: the host is gone
}

func (t *tree) send(typ uint8, payload []byte) error {
	if t.lost == nil {
		t.lost = t.s.send(typ, payload)
	}
	return t.lost
}

func (t *tree) entry(e guest.Entry) error {
	if e.Kind == guest.KindFile && e.Size > 0 {
		t.files = append(t.files, e)
	}
	return t.send(guest.TypeEntry, guest.EncodeEntry(e))
}

// file sends exactly e.Size bytes of the file at e.Path, opened beneath the root without
// following any link, so that the bytes are those of the file the manifest described.
func (t *tree) file(e guest.Entry) error {
	fd, err := unix.Openat2(t.root, e.Path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return fmt.Errorf("open %s: %w", e.Path, err)
	}
	defer unix.Close(fd)
	buf := make([]byte, wire.MaxPayload)
	for left := e.Size; left > 0; {
		n, err := unix.Read(fd, buf[:min(left, int64(len(buf)))])
		if err == nil && n == 0 {
			err = errors.New("shorter than it was")
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Path, err)
		}
		if err := t.send(guest.TypeData, buf[:n]); err != nil {
			return err
		}
		left -= int64(n)
	}
	return nil
}
