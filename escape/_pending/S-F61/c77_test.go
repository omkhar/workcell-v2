// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C77 of S-1008 (I10). Fix unit S-F61 first moves this file to internal/fileserve/c77_test.go, as this comment says; the harness is Linux only, so the build constraint below stays.

//go:build linux

package fileserve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestC77WritesIntoHoles is I10 on the host's disk: a sparse file that lay in the export before the session has a length far past the growth cap, and a WRITE below the length is charged nothing, so writes into its holes take host blocks without bound. Judged by the host's st.Blocks alone, so a fix may answer any errno.
func TestC77WritesIntoHoles(t *testing.T) {
	const limit, chunk, stride, rounds, size, slack = 100_000, 60_000, 1 << 20, 40, 256 << 20, 2 * block
	f := filepath.Join(t.TempDir(), "sparse")
	if err := errors.Join(os.WriteFile(f, nil, 0o644), os.Truncate(f, size)); err != nil {
		t.Fatal(err)
	}
	blocks := func() int64 { // what the host holds for f, in units of 512 bytes
		var st unix.Stat_t
		if err := unix.Stat(f, &st); err != nil {
			t.Fatal(err)
		}
		return st.Blocks
	}
	before := blocks()
	if before*512 >= size {
		t.Skipf("the temp directory's filesystem stores no holes: %d blocks for a truncated file of %d bytes", before, size)
	}
	k, stop := startCapped(t, filepath.Dir(f), limit)
	defer func() { _ = stop() }()
	k.ok(reqInit(7, 37))
	n := le.Uint64(k.ok(reqLookup(rootID, "sparse")))
	fh := le.Uint64(k.ok(reqOpen(n, unix.O_WRONLY)))
	accepted := 0
	for i := range rounds { // every write lies below the length, one in each megabyte
		if e, _ := k.call(reqWrite(n, fh, uint64(i*stride), make([]byte, chunk))); e == 0 {
			accepted++
		}
	}
	k.call(reqFsync(n, fh))
	if grown := (blocks() - before) * 512; grown > limit+slack {
		t.Errorf("I10: the host's blocks for the sparse file grew by %d bytes against a growth cap of %d, with %d of %d writes of %d bytes into its holes accepted", grown, limit, accepted, rounds, chunk)
	}
}
