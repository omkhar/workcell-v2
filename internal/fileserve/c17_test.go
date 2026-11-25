// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C17 of S-1008 (I10). Fix unit S-F10 first moves this file to internal/fileserve/c17_test.go, as this comment says.

//go:build linux

package fileserve

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGrowthCapAppend is I10 on the export: a file opened O_APPEND, through CREATE or OPEN, must stay within the cap however many WRITEs name offset 0.
func TestGrowthCapAppend(t *testing.T) {
	const limit, chunk, rounds, flags = 100_000, 60_000, 20, unix.O_RDWR | unix.O_APPEND
	for _, tc := range []struct {
		name string
		open func(k *kern) (node, fh uint64)
	}{
		{"create", func(k *kern) (uint64, uint64) {
			b := k.ok(reqCreate(1, "f", flags, 0o644))
			return le.Uint64(b), le.Uint64(b[entryOutLen:])
		}},
		{"open", func(k *kern) (uint64, uint64) {
			n := le.Uint64(k.ok(reqLookup(1, "f")))
			return n, le.Uint64(k.ok(reqOpen(n, flags)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			export := t.TempDir()
			f := filepath.Join(export, "f")
			if tc.name == "open" {
				if err := os.WriteFile(f, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			k, stop := startCapped(t, export, limit)
			defer func() {
				if err := stop(); err != nil {
					t.Error(err)
				}
			}()
			k.ok(reqInit(7, 37))
			node, fh := tc.open(k)
			enospc := 0
			for range rounds {
				switch e, _ := k.call(reqWrite(node, fh, 0, make([]byte, chunk))); e {
				case 0:
				case syscall.ENOSPC:
					enospc++
				default:
					t.Fatalf("write: %v", e)
				}
			}
			st, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() > limit {
				t.Errorf("the file grew to %d bytes on the host, past the cap of %d, with %d writes refused", st.Size(), limit, enospc)
			}
		})
	}
}
