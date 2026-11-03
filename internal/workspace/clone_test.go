// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package workspace

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestCloneSpeed is the acceptance test of clone mode: a 1 GB repository adds under 300 ms
// on a filesystem that can reflink. It needs mkfs.xfs or mkfs.btrfs and permission to loop
// mount (root, or passwordless sudo), and says which is missing when it skips.
func TestCloneSpeed(t *testing.T) {
	var mkfs []string
	for _, c := range [][]string{{"mkfs.xfs", "-q", "-m", "reflink=1"}, {"mkfs.btrfs", "-q"}} {
		if p, err := exec.LookPath(c[0]); err == nil {
			mkfs = append([]string{p}, c[1:]...)
			break
		}
	}
	if mkfs == nil {
		t.Skip("neither mkfs.xfs nor mkfs.btrfs is on PATH: no filesystem to reflink on")
	}
	var priv []string // the prefix of commands that need root
	if os.Geteuid() != 0 {
		priv = []string{"sudo", "-n"}
	}
	sh := func(args ...string) ([]byte, error) {
		return exec.Command(args[0], args[1:]...).CombinedOutput()
	}
	fsFile := filepath.Join(t.TempDir(), "fs.img")
	f, err := os.Create(fsFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(3 << 30); err != nil {
		t.Skipf("no room for a 3 GiB sparse file: %v", err)
	}
	f.Close()
	if out, err := sh(append(mkfs, fsFile)...); err != nil {
		t.Skipf("%s: %v\n%s", mkfs[0], err, out)
	}
	mnt := t.TempDir()
	if out, err := sh(append(priv, "mount", "-o", "loop", fsFile, mnt)...); err != nil {
		t.Skipf("cannot loop mount (need root or sudo -n): %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := sh(append(priv, "umount", mnt)...); err != nil {
			t.Errorf("umount %s: %v\n%s", mnt, err, out)
		}
	})
	if len(priv) > 0 {
		if out, err := sh(append(priv, "chown", fmt.Sprint(os.Getuid(), ":", os.Getgid()), mnt)...); err != nil {
			t.Fatalf("chown %s: %v\n%s", mnt, err, out)
		}
	}

	// 64 files of 16 MiB, written and flushed once, untimed: this is the repository.
	repo := filepath.Join(mnt, "repo")
	if err := os.Mkdir(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("workcell clone "), 1<<17)[:1<<20]
	for i := range 64 {
		g, err := os.Create(filepath.Join(repo, fmt.Sprintf("f%02d", i)))
		if err != nil {
			t.Fatal(err)
		}
		for range 16 {
			if _, err := g.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := g.Sync(); err != nil {
			t.Fatal(err)
		}
		g.Close()
	}

	start := time.Now()
	st, err := Export(context.Background(), repo, filepath.Join(mnt, "workspace.ext4"), 1<<30)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: exported %d files, %d MiB in %v (stats %+v)", mkfs[0], st.Files, st.Bytes>>20, took, st)
	if st.Cloned != 64 || st.Copied != 0 {
		t.Errorf("%d files cloned and %d copied, want 64 and 0", st.Cloned, st.Copied)
	}
	if took >= 300*time.Millisecond {
		t.Errorf("exporting 1 GB took %v, want under 300ms", took)
	}
	if _, err := exec.LookPath("e2fsck"); err == nil { // the shared blocks must still make a sound image
		if out, err := exec.Command("e2fsck", "-fn", filepath.Join(mnt, "workspace.ext4")).CombinedOutput(); err != nil {
			t.Errorf("e2fsck -fn: %v\n%s", err, out)
		}
	}
}
