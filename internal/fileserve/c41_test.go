// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C41 of S-1016c (I1).

//go:build linux

package fileserve

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestC41MountDoesNotWriteThroughHardLink (I1): export file "hl" shares its inode with dir/other, which no path in the export names. Whatever errno the guest gets, dir/other keeps its bytes, mode and mtime; "hl" stays readable and one-name file "victim" writable.
func TestC41MountDoesNotWriteThroughHardLink(t *testing.T) {
	open := func(k *kern, n uint64, flags uint32) uint64 { // 0, which no request takes, when the open is refused
		_, b := k.call(reqOpen(n, flags))
		return le.Uint64(append(b, make([]byte, 8)...))
	}
	state := func(p string) [4]any { // all the judge compares: a host file's bytes, read error, mode and mtime
		b, err := os.ReadFile(p)
		st, _ := os.Stat(p)
		return [4]any{string(b), err, st.Mode(), st.ModTime().UTC()}
	}
	arm := func(name string, do func(k *kern, n uint64)) {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			k, stop := start(t, fx.export)
			defer func() { _ = stop() }()
			_ = unix.UtimesNano(fx.dir+"/other", []unix.Timespec{{Sec: 9}, {Sec: 9}}) // an old mtime: on a coarse clock a change to "now" would not show
			k.ok(reqInit(7, 37))
			n, was := le.Uint64(k.ok(reqLookup(1, "hl"))), state(fx.dir+"/other")
			do(k, n)
			if now := state(fx.dir + "/other"); now != was {
				t.Errorf("I1: the guest changed a host file outside the export through the hard link: dir/other [bytes err mode mtime] is now %q, was %q", now, was)
			}
			named := exists(fx.export+"/hl") && state(fx.export+"/hl") == state(fx.dir+"/other") // false once an arm took the name hl from dir/other: nothing to read
			if e, got := k.call(reqRead(n, open(k, n, unix.O_RDONLY), 0, 16)); named && (e != 0 || string(got) != state(fx.dir + "/other")[0]) {
				t.Errorf("the export refuses to read its hard-linked file: O_RDONLY open and READ of hl gave %q (errno %d), want the bytes of dir/other", got, e)
			}
			v := le.Uint64(k.ok(reqLookup(1, "victim")))
			k.ok(reqWrite(v, open(k, v, unix.O_WRONLY|unix.O_TRUNC), 0, []byte("mine")))
			if b, err := os.ReadFile(fx.export + "/victim"); err != nil || string(b) != "mine" {
				t.Errorf("the export refuses a write to its own one-name file: victim is %q (err %v), want %q", b, err, "mine")
			}
		})
	}
	arm("1 write O_WRONLY", func(k *kern, n uint64) { k.call(reqWrite(n, open(k, n, unix.O_WRONLY), 0, []byte("pwned"))) })
	arm("1 write O_RDWR", func(k *kern, n uint64) { k.call(reqWrite(n, open(k, n, unix.O_RDWR), 0, []byte("pwned"))) })
	arm("2 open O_WRONLY O_TRUNC", func(k *kern, n uint64) { open(k, n, unix.O_WRONLY|unix.O_TRUNC) })
	arm("2 open O_RDONLY O_TRUNC", func(k *kern, n uint64) { open(k, n, unix.O_RDONLY|unix.O_TRUNC) })
	arm("3 setattr size by node", func(k *kern, n uint64) { k.call(reqSetattr(n, fattrSize, 0, 0, 0)) })
	arm("3 setattr mode by node", func(k *kern, n uint64) { k.call(reqSetattr(n, fattrMode, 0, 0, 0o777)) })
	arm("3 setattr mtime by node", func(k *kern, n uint64) { k.call(reqSetattr(n, fattrMtime, 0, 0, 0)) })
	arm("3 setattr mtime now by node", func(k *kern, n uint64) { k.call(reqSetattr(n, fattrMtimeNow, 0, 0, 0)) })
	arm("3 setattr mode by O_RDONLY fh", func(k *kern, n uint64) { k.call(reqSetattr(n, fattrFh|fattrMode, open(k, n, unix.O_RDONLY), 0, 0o666)) })
	late := func(k *kern, n, h uint64, r []byte) { k.ok(r); k.call(reqSetattr(n, fattrFh|fattrMode, h, 0, 0o777)) } // r takes the name hl from dir/other, so its link count is 1
	arm("4 setattr mode by fh after UNLINK", func(k *kern, n uint64) { late(k, n, open(k, n, unix.O_RDONLY), reqUnlink(1, "hl")) })
	arm("4 setattr mode by fh after RENAME over", func(k *kern, n uint64) { late(k, n, open(k, n, unix.O_RDONLY), reqRename(1, "fg", 1, "hl")) })
}
