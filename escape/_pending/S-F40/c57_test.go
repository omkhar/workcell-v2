// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C57 of S-1008 (I10). Fix unit S-F40 first moves this file to
// cmd/workcell/c57_test.go, as this comment says.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
)

// TestPullGrowthCapEntries is I10 on the pull path: a directory or symlink entry carries no file bytes but costs the
// host a block and an inode, so against limit bytes at most limit/4096 plus slack of them may land, as in mount mode (C18).
func TestPullGrowthCapEntries(t *testing.T) {
	const limit, tries, slack = 100_000, 200, 2
	most := limit/4096 + slack
	for _, arm := range []struct {
		name  string
		entry func(i int) guest.Entry
	}{{"dir", func(i int) guest.Entry { return dirEntry(fmt.Sprintf("d%03d", i)) }}, {"link", func(i int) guest.Entry { return linkEntry(fmt.Sprintf("l%03d", i), "x") }}} {
		t.Run(arm.name, func(t *testing.T) {
			m := &manifest{limit: limit}
			for i := range tries {
				m.add(arm.entry(i)) // the guest keeps sending; a refusal ends the tree, so only what was kept counts
			}
			dest := t.TempDir()
			err := write(openDir(t, dest), m, from(nil))
			written := len(must(os.ReadDir(dest)))
			if err == nil && written != len(m.entries) {
				t.Errorf("%d entries on the host, but %d were accepted", written, len(m.entries))
			}
			if err == nil && len(m.entries) > most || written > most {
				t.Errorf("%s: %d accepted, %d written against a limit of %d bytes, want at most %d (%d blocks of 4096 plus %d)", arm.name, len(m.entries), written, limit, most, limit/4096, slack)
			}
		})
	}
}
