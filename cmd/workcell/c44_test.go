// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
//go:build darwin && arm64 && cgo

package main

import (
	"github.com/omkhar/workcell/v2/internal/guest"
	"os"
	"os/exec"
	"testing"
)

// TestPullWritesDotGitHFS (C44 of S-1016d, I8; fixed by S-F32): on a case-insensitive HFS+ volume made by hdiutil at run time, guest paths that alias ".git" such as ".g<U+200C>it/hooks/pre-commit" or ".g<U+FEFF>it/config" resolve to the real ".git", so the fix must leave every ".git" (a directory, a nested one, an absent one, or a worktree file) untouched while ordinary names still land; judged only by the filesystem afterwards, and the fix depends on no list of code points. It skips where such an HFS+ image cannot be made or attached.
func TestPullWritesDotGitHFS(t *testing.T) {
	img, mnt := t.TempDir()+"/t.dmg", t.TempDir()
	if exec.Command("hdiutil", "create", "-size", "20m", "-fs", "HFS+", "-volname", "T", img).Run() != nil || exec.Command("hdiutil", "attach", "-nobrowse", "-mountpoint", mnt, img).Run() != nil {
		t.Skip("cannot make or attach an HFS+ image here")
	}
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", mnt).Run() })
	for _, c := range []struct{ dir, mk, wf, de, path, target, want, exec string }{{"a", ".git/hooks", "pad", "", ".g\u200cit/hooks/pre-commit", ".git/hooks/pre-commit", "", "1"}, {"b", ".git/hooks", "pad", "", ".g\ufeffit/config", ".git/config", "", ""}, {"c", "sub/.git", "pad", "", "sub/.g\u200cit/x", "sub/.git/x", "", ""}, {"d", "", "pad", ".g\u200cit", ".g\u200cit/y", ".git/y", "", ""}, {"e", "", ".git", "", ".g\u200cit", ".git", "gitdir: x", ""}, {"f", "", "pad", "git", "readme", "readme", "xx", ""}} {
		must(0, os.MkdirAll(mnt+"/"+c.dir+"/"+c.mk, 0o755))
		must(0, os.WriteFile(mnt+"/"+c.dir+"/"+c.wf, []byte("gitdir: x"), 0o644))
		m := &manifest{limit: 1 << 20}
		m.add(guest.Entry{Kind: guest.KindDir, Path: c.de})
		m.add(guest.Entry{Kind: guest.KindFile, Path: c.path, Size: 2, Exec: c.exec != ""})
		write(openDir(t, mnt+"/"+c.dir), m, from([]byte("xx")))
		if b, err := os.ReadFile(mnt + "/" + c.dir + "/" + c.target); (c.want == "") == (err == nil) || (err == nil && string(b) != c.want) {
			t.Errorf("arm %s: target %q = %q (err %v), want %q", c.dir, c.target, b, err, c.want)
		}
	}
}
