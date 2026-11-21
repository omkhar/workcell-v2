// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
//go:build darwin

package main

import (
	"github.com/omkhar/workcell/v2/internal/guest"
	"os"
	"os/exec"
	"testing"
)

// TestPullWritesDotGitHFS (C44 of S-1016d, I8; fix unit S-F32 first moves this file to cmd/workcell/c44_test.go): on a case-insensitive HFS+ volume made by hdiutil at run time, the guest path ".g<U+200C>it/hooks/pre-commit" resolves to the real .git, so manifest.add accepts it and write lays down a 0755 hook, which I8 must forbid; it skips where such an image cannot be made or attached.
func TestPullWritesDotGitHFS(t *testing.T) {
	img, mnt := t.TempDir()+"/t.dmg", t.TempDir()
	if exec.Command("hdiutil", "create", "-size", "20m", "-fs", "HFS+", "-volname", "T", img).Run() != nil || exec.Command("hdiutil", "attach", "-nobrowse", "-mountpoint", mnt, img).Run() != nil {
		t.Skip("cannot make or attach an HFS+ image here")
	}
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", mnt).Run() })
	must(0, os.MkdirAll(mnt+"/repo/.git/hooks", 0o755))
	if m := (&manifest{limit: 1000}); m.add(guest.Entry{Kind: guest.KindFile, Path: ".g\u200cit/hooks/pre-commit", Size: 2, Exec: true}) == nil {
		write(openDir(t, mnt+"/repo"), m, from([]byte("xx")))
	}
	if _, err := os.Stat(mnt + "/repo/.git/hooks/pre-commit"); err == nil {
		t.Fatalf("I8: guest wrote the real .git/hooks/pre-commit through the U+200C alias on HFS+")
	}
}
