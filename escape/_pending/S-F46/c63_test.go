// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C63 of S-1013, sweep 2 (hardening, the second order of C56), parked for S-F46, which moves this file to cmd/workcell/c63_test.go.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestC63PullHoldsNoLock (I1, I4, I7, I12): a pull boots a VM for an ended session without taking its lock, so while the pull runs the session reads as not
// running, and the refusal C56 holds for a mount session whose directory holds a running session's VMM directory does not see the pull's live one.
func TestC63PullHoldsNoLock(t *testing.T) {
	repo, data := t.TempDir(), filepath.Join(t.TempDir(), "workcell")
	t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	c19Data(t, data, repo)
	fifo := filepath.Join(data, "sessions", idOld, "inodes") // fetch reads it after newest and before boot, and waits there for a writer
	must(holdSession(filepath.Dir(fifo))).Close()            // the session ended: its lock file exists and is free
	must(0, syscall.Mkfifo(fifo, 0o600))
	t.Chdir(repo)
	done := make(chan error, 1)
	go func() { _, err := fetch(".", func(int, *manifest, source) error { return nil }); done <- err }()
	bound := time.AfterFunc(10*time.Second, func() { panic("fetch has not opened inodes in 10s") }) // it returned or parked before them, and the open below would wait for good
	fd := must(syscall.Open(fifo, syscall.O_WRONLY, 0))                                             // returns once fetch has opened inodes to read: after newest, before boot
	bound.Stop()
	up, err := running(filepath.Dir(fifo)) // what a mount session begun now, in a directory that holds the pull's temp directory, asks before its boot
	must(syscall.Write(fd, []byte("100")))
	_, _ = syscall.Close(fd), <-done // "100" then EOF: the pull goes on to boot, where it ends with the dummy VMM
	if !up || err != nil {
		t.Errorf("running(%s) = %v, %v while a pull of %s runs between its session lookup and its boot: the pull holds no lock, so a mount session of a directory that holds its VMM directory is not refused (I1, I4, I7, I12)", filepath.Dir(fifo), up, err, repo)
	}
}
