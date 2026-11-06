// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Package clonespike measures clone mode (U-500) on a real reflink filesystem and logs one
// line, so that the hosted log shows the result of the acceptance test or why it skipped.
// It is a copy of the setup in internal/workspace/clone_test.go, and goes at cutover.
package clonespike

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/workspace"
)

func TestClone(t *testing.T) {
	var mkfs []string
	for _, c := range [][]string{{"mkfs.xfs", "-q", "-m", "reflink=1"}, {"mkfs.btrfs", "-q"}} {
		if p, err := exec.LookPath(c[0]); err == nil {
			mkfs = append([]string{p}, c[1:]...)
			break
		}
	}
	if mkfs == nil {
		t.Skip("clone: skipped, neither mkfs.xfs nor mkfs.btrfs is on PATH")
	}
	fsName := strings.TrimPrefix(filepath.Base(mkfs[0]), "mkfs.")
	var priv []string // the prefix of commands that need root
	if os.Geteuid() != 0 {
		priv = []string{"sudo", "-n"}
	}
	sh := func(args ...string) ([]byte, error) { return exec.Command(args[0], args[1:]...).CombinedOutput() }
	fsFile := filepath.Join(t.TempDir(), "fs.img")
	f, err := os.Create(fsFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(3 << 30); err != nil {
		t.Skipf("clone: skipped, no room for a 3 GiB sparse file: %v", err)
	}
	f.Close()
	if out, err := sh(append(mkfs, fsFile)...); err != nil {
		t.Skipf("clone: skipped, %s failed: %v %s", mkfs[0], err, out)
	}
	mnt := t.TempDir()
	if out, err := sh(append(priv, "mount", "-o", "loop", fsFile, mnt)...); err != nil {
		t.Skipf("clone: skipped, cannot loop mount %s (need root or sudo -n): %v %s", fsName, err, out)
	}
	t.Cleanup(func() {
		if out, err := sh(append(priv, "umount", mnt)...); err != nil {
			t.Errorf("umount %s: %v\n%s", mnt, err, out)
		}
	})
	if len(priv) > 0 {
		if out, err := sh(append(priv, "chown", fmt.Sprint(os.Getuid(), ":", os.Getgid()), mnt)...); err != nil {
			t.Skipf("clone: skipped, chown %s: %v %s", mnt, err, out)
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

	image := filepath.Join(mnt, "workspace.ext4")
	start := time.Now()
	st, err := workspace.Export(context.Background(), repo, image, 1<<30)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("clone: fs=%s files=%d bytes=%d elapsed_ms=%d", fsName, st.Files, st.Bytes, took.Milliseconds())
	if _, err := exec.LookPath("e2fsck"); err != nil {
		t.Logf("clone: e2fsck not on PATH, image not checked")
		return
	}
	out, err := exec.Command("e2fsck", "-fn", image).CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	t.Logf("clone: e2fsck -fn err=%v: %s", err, lines[len(lines)-1])
}
