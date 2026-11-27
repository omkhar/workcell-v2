// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

// C87 (I12, R6): compare parks in the open of a name its walk judged a regular file when a FIFO that
// no writer holds takes that name before sameBytes opens it, so `workcell diff` hangs with its session lock.
// The fix unit S-F73 moved this file here from escape/_pending/S-F73/.

package main

import (
	"cmp"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"golang.org/x/sys/unix"
)

func TestC87CompareFIFOReturns(t *testing.T) {
	t.Run("unheld", func(t *testing.T) { c87(t, false) }) // no writer holds the FIFO: the open parks
	t.Run("held", func(t *testing.T) { c87(t, true) })    // a writer holds it and writes nothing: the read parks
}

func c87(t *testing.T, held bool) {
	dir := t.TempDir()
	a, b, fifo := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "f")
	root, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err = cmp.Or(err, os.WriteFile(a, []byte("x"), 0o644), os.WriteFile(b, []byte("x"), 0o644), unix.Mkfifo(fifo, 0o644)); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	w := -1 // the writer, when held: a passing non-blocking reader lets its O_WRONLY open return at once
	if held {
		var r int
		if r, err = unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK, 0); err == nil {
			w, err = unix.Open(fifo, unix.O_WRONLY, 0)
			unix.Close(r)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { unix.Close(w) }()
	m, wfd := &manifest{}, 0 // the guest's tree is the host's as it is now, walked on its own descriptor (a dup would share the offset compare's walk reads from)
	if wfd, err = unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0); err == nil {
		err = guest.Walk(wfd, func(e guest.Entry) error { m.entries = append(m.entries, e); return nil })
	}
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	data := func(int) (_ []byte, err error) { // a's byte is asked for after the walk judged b and before b is opened: the FIFO takes b's name then
		once.Do(func() { err = os.Rename(fifo, b) })
		return []byte("x"), err
	}
	done := make(chan error, 1)
	go func() { _, err := compare(root, m, data, io.Discard); done <- err }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Errorf("compare is still parked 3s after a FIFO (writer held: %v) took a regular file's name: workcell diff hangs (I12)", held)
		if !held { // give the parked open a writer; closing the writer then ends the read either way, so nothing is left behind
			w, _ = unix.Open(b, unix.O_WRONLY, 0)
		}
		unix.Close(w)
		w = -1
		<-done
	}
}
