// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C91 of S-1008 sweep 4 (I8): the pull refuses the name .git and what shares its inode, so a repository whose .git is a symbolic link to, or a gitfile naming, a git directory kept in the work tree under another name (git init --separate-git-dir ./gitdir) has that directory written by the guest: its hooks and config are obeyed at the operator's next git command. Fails until the fix lands.
// Re-created by S-F77 from the record of C91 in loop/state/FINDINGS.md; it lives here, in the suite, from that unit on.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
)

// TestC91GitDirectoryUnderAnotherName: the real writer, a destination whose .git names the in-tree directory gitdir in the two forms git reads, and a guest tree of gitdir/hooks/pre-commit and gitdir/config. Where git is on PATH the repository is git's own, and a commit afterwards shows whether the hook ran. Controls: the name .git is still refused by the manifest, and a .git that names a directory outside the destination leaves the plain in-tree gitdir writable as before. How a fix refuses is not judged.
func TestC91GitDirectoryUnderAnotherName(t *testing.T) {
	git, _ := exec.LookPath("git")
	if err := (&manifest{limit: 1 << 20}).add(fileEntry(".git/hooks/pre-commit", 1, true)); err == nil {
		t.Error("control: the manifest admitted .git/hooks/pre-commit")
	}
	for _, tc := range []struct {
		name  string
		point func(g, in, out string) error // makes .git at g; in is the in-tree gitdir, out a directory outside
		real  bool                          // gitdir is the git directory git obeys
	}{
		{"a symbolic link .git -> gitdir", func(g, _, _ string) error { return os.Symlink("gitdir", g) }, true},
		{"a gitfile .git naming gitdir", func(g, in, _ string) error { return os.WriteFile(g, []byte("gitdir: "+in+"\n"), 0o644) }, true},
		{"control: .git -> a directory outside", func(g, _, out string) error { return os.Symlink(out, g) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dest, outside, canary := filepath.Join(parent, "dest"), filepath.Join(parent, "outside"), filepath.Join(parent, "canary")
			gitdir := filepath.Join(dest, "gitdir")
			must(0, os.MkdirAll(gitdir, 0o755))
			must(0, os.Mkdir(outside, 0o755))
			if git != "" {
				must(exec.Command(git, "init", "-q", "--separate-git-dir="+gitdir, dest).CombinedOutput())
				must(0, os.Remove(filepath.Join(dest, ".git")))
			}
			must(0, tc.point(filepath.Join(dest, ".git"), gitdir, outside))
			hook, config := "#!/bin/sh\ntouch "+canary+"\n", "[core]\n\tbare = false\n"
			err := write(openDir(t, dest), judged(t, []guest.Entry{dirEntry("gitdir"), dirEntry("gitdir/hooks"), fileEntry("gitdir/hooks/pre-commit", int64(len(hook)), true), fileEntry("gitdir/config", int64(len(config)), false)}), from([]byte(hook+config)))
			h, _ := os.ReadFile(filepath.Join(gitdir, "hooks", "pre-commit"))
			c, _ := os.ReadFile(filepath.Join(gitdir, "config"))
			if hk, cf := string(h) == hook, string(c) == config; hk != cf || hk == tc.real {
				t.Errorf("I8: after the writer (%v) the guest's hook lies in gitdir: %t, its config: %t; gitdir is the git directory git obeys: %t, and must take both exactly when it is not", err, hk, cf, tc.real)
			}
			if tc.real && git != "" {
				out, err := exec.Command(git, "-C", dest, "-c", "user.name=c91", "-c", "user.email=c91@example.invalid", "commit", "-q", "--allow-empty", "-m", "c91").CombinedOutput()
				if _, found := os.Stat(canary); found == nil {
					t.Errorf("I8: git commit on the host (%v, %q) ran the guest's pre-commit hook: %s exists", err, out, canary)
				}
			}
		})
	}
}
