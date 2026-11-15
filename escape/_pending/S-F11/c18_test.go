// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestGrowthCapEntries is I10 on the export through entries, not bytes: SYMLINK and MKDIR each
// take a host block (a target of 60 bytes or more leaves the inode on ext4 and xfs) and a host
// inode, so a guest that makes entries grows the host like one that writes. Against a cap of
// limit bytes the server may accept at most limit/4096 entries of either kind, plus a little
// slack for how a fix rounds; the rest are ENOSPC. The count is the judge because it holds on
// any filesystem; the blocks the host really spent are logged beside it.
func TestGrowthCapEntries(t *testing.T) {
	const limit = 100_000
	const tries = 200
	const slack = 2
	most := limit/4096 + slack
	target := make([]byte, 4000)
	for i := range target {
		target[i] = 'x'
	}
	for _, arm := range []struct {
		name string
		req  func(i int) []byte
	}{
		{"symlink", func(i int) []byte { return reqSymlink(rootID, fmt.Sprintf("l%03d", i), string(target)) }},
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
			accepted, refused := 0, 0
			for i := 0; i < tries; i++ {
				switch e, _ := k.call(arm.req(i)); e {
				case 0:
					accepted++
				case syscall.ENOSPC:
					refused++
				default:
					t.Fatalf("%s %d: %v, want 0 or ENOSPC", arm.name, i, e)
				}
			}
			// What the host really holds: every entry under the export, its blocks, and its inode.
			ents, err := os.ReadDir(export)
			if err != nil {
				t.Fatal(err)
			}
			var bytes int64
			for _, e := range ents {
				var st syscall.Stat_t
				if err := syscall.Lstat(filepath.Join(export, e.Name()), &st); err != nil {
					t.Fatal(err)
				}
				bytes += st.Blocks * 512
			}
			t.Logf("%s: %d accepted, %d ENOSPC; the host holds %d entries (inodes) and %d bytes of blocks against a cap of %d",
				arm.name, accepted, refused, len(ents), bytes, limit)
			if len(ents) != accepted {
				t.Errorf("%d entries on the host, but %d requests were accepted", len(ents), accepted)
			}
			if accepted > most {
				t.Errorf("%s: %d entries accepted without ENOSPC against a cap of %d bytes, want at most %d (%d blocks of 4096 plus %d)",
					arm.name, accepted, limit, most, limit/4096, slack)
			}
		})
	}
}
