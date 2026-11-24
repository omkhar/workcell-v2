// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C61 of S-1013, sweep 2 (I1), parked for S-F44, which moves this file to cmd/workcell/c61_test.go.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestC61CloneExportFollowsARenamedWorkingDirectory (I1; I5, I7, I9 by the target chosen): session takes the working directory by name, judges and records that name, and
// the clone export opens the same name again. Guest root of a mount session on a proper ancestor renames the directory away in between and puts a symlink to any host directory
// under its name, so the image exports a directory outside every export. Deterministic: holds reads every session's vmm after Getwd, so a FIFO there parks it until the writer opens.
func TestC61CloneExportFollowsARenamedWorkingDirectory(t *testing.T) {
	work, outside, data := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "workcell")
	proj, canary := filepath.Join(work, "proj"), []byte(rand.Text())
	must(0, os.Mkdir(proj, 0o700))
	must(0, os.WriteFile(filepath.Join(outside, "id_ed25519"), canary, 0o600))
	t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	a, fifo := c19Data(t, data, "/elsewhere"), filepath.Join(mkSession(t, filepath.Join(data, "sessions"), idNew, "/elsewhere"), "vmm") // the mount session on work runs: lock held, its vmm a FIFO
	defer must(holdSession(filepath.Dir(fifo))).Close()
	must(0, syscall.Mkfifo(fifo, 0o600))
	t.Chdir(proj)
	go func() { // its guest, root on work
		defer must(os.OpenFile(fifo, os.O_WRONLY, 0)).Close() // the open returns once session has opened the FIFO for reading, inside holds, after Getwd; the close at the end lets holds go on
		must(0, os.Rename(proj, filepath.Join(work, "x")))
		must(0, os.Symlink(outside, proj))
	}()
	session([]string{"true"}, limits{DiskMiB: 16}, false, a, nil, nil)    // the operator's clone session of proj: without a VM it ends at boot, after the export
	for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // the new session, whatever its id
		if img, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && e.Name() != idNew && bytes.Contains(img, canary) {
			t.Errorf("the clone session of %s exported %s, where a link under that name pointed by the time of the export: a key outside every export is in the guest's image (I1)", proj, outside)
		}
	}
}
