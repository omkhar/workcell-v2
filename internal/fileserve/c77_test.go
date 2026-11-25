// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C77 of S-1008 (I10). Parked under escape/_pending/S-F61 until fix unit S-F61 moved it here; the harness is Linux only, so the build constraint below stays.

//go:build linux

package fileserve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestC77WritesIntoHoles is I10 on the host's disk: a sparse file that lay in the export before the session has a length far past the growth cap, and a WRITE below the length is charged nothing, so writes into its holes take host blocks without bound. Judged by the host's st.Blocks alone, so a fix may answer any errno. The second arm holds the block rule: the host allocates a whole block for a one-byte write into a hole, so far more one-byte writes than limit/block, each in its own block, must be stopped too.
func TestC77WritesIntoHoles(t *testing.T) {
	const limit, size, slack = 100_000, 256 << 20, 2 * block
	for _, a := range [][3]int{{60_000, 1 << 20, 40}, {1, block, 200}} { // chunk, stride, rounds: 60000 bytes one per MiB, then one byte one per block
		chunk, stride, rounds := a[0], a[1], a[2]
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
		t.Cleanup(func() { _ = stop() })
		k.ok(reqInit(7, 37))
		n := le.Uint64(k.ok(reqLookup(rootID, "sparse")))
		fh := le.Uint64(k.ok(reqOpen(n, unix.O_WRONLY)))
		accepted := 0
		for i := range rounds { // every write lies below the length, one per stride
			if e, _ := k.call(reqWrite(n, fh, uint64(i*stride), make([]byte, chunk))); e == 0 {
				accepted++
			}
		}
		k.call(reqFsync(n, fh))
		if grown := (blocks() - before) * 512; grown > limit+slack {
			t.Errorf("I10: the host's blocks for the sparse file grew by %d bytes against a growth cap of %d, with %d of %d writes of %d bytes, one per %d bytes, into its holes accepted", grown, limit, accepted, rounds, chunk, stride)
		}
	}
}
