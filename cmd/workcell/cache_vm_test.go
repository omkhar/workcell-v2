// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"fmt"
	"testing"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

func TestLockCache(t *testing.T) {
	r, w := vmm.Cache{Name: "go"}, vmm.Cache{Name: "go", Writable: true}
	const readWrite, wait = "cache go is in use read-write by another session", "cache go is in use by another session; wait, or run without :rw"
	tests := []struct {
		name string
		held []vmm.Cache // taken first, and kept
		take vmm.Cache
		err  string
	}{
		{"a reader on its own", nil, r, ""},
		{"a writer on its own", nil, w, ""},
		{"readers share", []vmm.Cache{r}, r, ""},
		{"a writer excludes a writer", []vmm.Cache{w}, w, wait},
		{"a writer excludes a reader", []vmm.Cache{w}, r, readWrite},
		{"a reader excludes a writer", []vmm.Cache{r}, w, wait},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, c := range tc.held {
				f, err := lockCache(dir, c)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
			}
			f, err := lockCache(dir, tc.take)
			if err == nil {
				f.Close()
			}
			if got := fmt.Sprint(err); (err == nil) != (tc.err == "") || err != nil && got != tc.err {
				t.Errorf("lockCache(%+v) = %v, want %q", tc.take, err, tc.err)
			}
		})
	}
}
