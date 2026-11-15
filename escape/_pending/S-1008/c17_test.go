// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGrowthCapAppend is I10 on the export against a guest that writes its own FUSE frames
// (S-1008 C17). A descriptor opened O_APPEND appends whatever offset pwrite is given, while
// WRITE is charged by the offset the request names. So after one write that fills part of
// the cap, every further WRITE at offset 0 ends at or below the file's recorded size, costs
// nothing, and still lands at the end: the file under the export grows without bound and no
// request is ENOSPC. The host file must stay within the cap, through CREATE and through OPEN.
func TestGrowthCapAppend(t *testing.T) {
	const (
		limit  = 100_000
		chunk  = 60_000
		rounds = 20
		flags  = unix.O_RDWR | unix.O_APPEND // 0x402, as `>>` in the guest opens
	)
	for _, tc := range []struct {
		name string
		open func(k *kern) (node, fh uint64)
	}{
		{"create", func(k *kern) (uint64, uint64) {
			body := k.ok(reqCreate(1, "f", flags, 0o644))
			return le.Uint64(body), le.Uint64(body[entryOutLen:])
		}},
		{"open", func(k *kern) (uint64, uint64) {
			n := le.Uint64(k.ok(reqLookup(1, "f")))
			return n, le.Uint64(k.ok(reqOpen(n, flags)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			export := t.TempDir()
			if tc.name == "open" {
				if err := os.WriteFile(filepath.Join(export, "f"), nil, 0o644); err != nil {
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
			accepted, enospc := 0, 0
			for range rounds {
				switch e, _ := k.call(reqWrite(node, fh, 0, make([]byte, chunk))); e {
				case 0:
					accepted++
				case syscall.ENOSPC:
					enospc++
				default:
					t.Fatalf("write: %v", e)
				}
			}
			st, err := os.Stat(filepath.Join(export, "f"))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d writes of %d at offset 0 with a cap of %d: %d accepted, %d ENOSPC, file is %d bytes on the host",
				rounds, chunk, limit, accepted, enospc, st.Size())
			if st.Size() > limit {
				t.Errorf("the file grew to %d bytes on the host, past the cap of %d, with %d writes refused", st.Size(), limit, enospc)
			}
		})
	}
}
