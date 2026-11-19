// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C18 of S-1008 (I10). Fix unit S-F11 first moves this file to
// internal/fileserve/c18_test.go, as this comment says.

//go:build linux

package fileserve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestGrowthCapEntries is I10 on the export through entries: SYMLINK and MKDIR each cost a host block
// and inode, so against a cap of limit bytes at most limit/4096 plus slack may be accepted.
func TestGrowthCapEntries(t *testing.T) {
	const limit, tries, slack = 100_000, 200, 2
	most, target := limit/4096+slack, strings.Repeat("x", 4000)
	for _, arm := range []struct {
		name string
		req  func(i int) []byte
	}{
		{"symlink", func(i int) []byte { return reqSymlink(rootID, fmt.Sprintf("l%03d", i), target) }},
		{"mkdir", func(i int) []byte { return reqMkdir(rootID, fmt.Sprintf("d%03d", i)) }},
	} {
		t.Run(arm.name, func(t *testing.T) {
			export := filepath.Join(t.TempDir(), "export")
			if err := os.Mkdir(export, 0o755); err != nil {
				t.Fatal(err)
			}
			k, stop := startCapped(t, export, limit)
			defer func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			}()
			k.ok(reqInit(7, 37))
			accepted := 0
			for i := range tries {
				switch e, _ := k.call(arm.req(i)); e {
				case 0:
					accepted++
				case syscall.ENOSPC:
				default:
					t.Fatalf("%s %d: %v, want 0 or ENOSPC", arm.name, i, e)
				}
			}
			ents, err := os.ReadDir(export)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != accepted {
				t.Errorf("%d entries on the host, but %d requests were accepted", len(ents), accepted)
			}
			if accepted > most {
				t.Errorf("%s: %d entries accepted without ENOSPC against a cap of %d bytes, want at most %d (%d blocks of 4096 plus %d)", arm.name, accepted, limit, most, limit/4096, slack)
			}
		})
	}
}
