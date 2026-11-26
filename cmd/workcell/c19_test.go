// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C19 of S-1008 (I7, I8, I9, I13, I14). Fix unit S-F12 first moves this file to cmd/workcell/c19_test.go, as this comment says.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"cmp"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// c19Data fills data as a data directory before a session: dummy artifacts and an earlier session of repo with a marked audit log and workspace image, and no audit key. It returns the artifacts.
func c19Data(t *testing.T, data, repo string) artifacts {
	t.Helper()
	must(0, os.MkdirAll(data, 0o700))
	for _, n := range required() {
		must(0, os.WriteFile(filepath.Join(data, n), []byte("dummy "+n), 0o644))
	}
	other := mkSession(t, filepath.Join(data, "sessions"), idOld, repo)
	must(0, os.WriteFile(filepath.Join(other, "audit.log"), []byte("C19-OTHER-SESSION-AUDIT-LOG\n"), 0o600))
	must(0, os.WriteFile(filepath.Join(other, "workspace.ext4"), []byte("C19-OTHER-SESSION-WORKSPACE"), 0o600))
	a, err := findArtifacts(data)
	must(0, err)
	return a
}

// c19Untouched fails when a session got past the refusal: a minted audit key, a new session directory or a boot record under data.
func c19Untouched(t *testing.T, data string) {
	t.Helper()
	if key := filepath.Join(data, "audit.key"); exists(key) {
		t.Errorf("%s was minted inside the directory the guest gets: the guest can seal a rewritten log (I9)", key)
	}
	ents, _ := os.ReadDir(filepath.Join(data, "sessions"))
	for _, e := range ents {
		if e.Name() != idOld {
			t.Errorf("a session directory %s was made inside the directory the guest gets (I7)", e.Name())
		}
	}
	if vmm := filepath.Join(data, "sessions", idOld, "vmm"); exists(vmm) {
		t.Errorf("the session reached boot: %s was written", vmm)
	}
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory (I7, I9, I13, I14): a workspace that holds the data or the config directory is refused, naming it, before a session directory, key or export is made.
func TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory(t *testing.T) {
	for _, tc := range []struct {
		name                string
		mount, config, link bool // config: the workspace holds the config directory alone; link: through a symlink, and not made yet
	}{{"clone", false, false, false}, {"mount", true, false, false}, {"clone, config directory", false, true, false},
		{"clone, config directory behind a symlink, not made yet", false, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			data, config := filepath.Join(work, "workcell"), filepath.Join(t.TempDir(), "workcell")
			held := data
			if tc.config {
				data, config = config, data
				held = config
			}
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			if tc.link { // first use: $XDG_CONFIG_HOME is a dotfiles symlink to the workspace, and workcell/ under it does not exist yet
				link := filepath.Join(t.TempDir(), "config-link")
				must(0, os.Symlink(work, link))
				t.Setenv("XDG_CONFIG_HOME", link)
				held = filepath.Join(link, "workcell")
			} else {
				must(0, os.MkdirAll(config, 0o700))
				must(0, os.WriteFile(filepath.Join(config, "config.toml"), []byte("# C19\n"), 0o600))
			}
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			r := session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, nil, nil)
			if r.err == nil {
				t.Fatal("the session ran")
			}
			if !strings.Contains(r.err.Error(), held) {
				t.Errorf("session failed with %q, want a refusal naming %s", r.err, held)
			}
			c19Untouched(t, data)
		})
	}
}

// TestC19PullRefusesADestinationThatHoldsTheDataDirectory (I8, I9, I14): a pull destination that holds the data directory is refused in one line, naming it, before anything boots.
func TestC19PullRefusesADestinationThatHoldsTheDataDirectory(t *testing.T) {
	dest := t.TempDir()
	data, repo := filepath.Join(dest, "workcell"), filepath.Join(dest, "repo")
	must(0, os.Mkdir(repo, 0o700))
	t.Setenv("XDG_DATA_HOME", dest)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c19Data(t, data, repo)
	t.Chdir(repo)
	var stderr bytes.Buffer
	if code := pull([]string{dest}, &stderr); code != 1 || !strings.Contains(stderr.String(), data) || strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("pull exited %d with %q, want 1 and one line refusing a destination that holds %s", code, stderr.String(), data)
	}
	c19Untouched(t, data)
}

// TestC85ConfigFileOfAnotherName (I13; I5, I14 by consequence): holds judges a config.toml that is a symbolic link to a file not made yet by where it points, since the guest of a --mount session would make it, and refuses one with more than one name (a hard link), whose other names it cannot find; a link to an absent file elsewhere, and a file of one name, run. The config directory is itself a link, as a dotfiles layout has it, so a relative target is read from where that directory really is, as the kernel reads it. resolved ends on a loop of links, at the name it is at.
func TestC85ConfigFileOfAnotherName(t *testing.T) {
	work, cfg := filepath.Join(t.TempDir(), "sub", "dot"), t.TempDir() // <cfg>/workcell -> sub/wc, so a target ../dot/config.toml names a file in the workspace
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", cfg)
	file, present, loop, a, b := filepath.Join(cfg, "workcell", "config.toml"), filepath.Join(cfg, "present"), filepath.Join(cfg, "loop"), filepath.Join(cfg, "a"), filepath.Join(cfg, "b")
	must(0, cmp.Or(os.MkdirAll(work, 0o700), os.MkdirAll(filepath.Join(filepath.Dir(work), "wc"), 0o700), os.Symlink(filepath.Join(filepath.Dir(work), "wc"), filepath.Dir(file)), os.WriteFile(present, []byte("# C85\n"), 0o600), os.Symlink(loop, loop), os.Symlink("b", a), os.Symlink("a", b)))
	make := map[string]func(string, string) error{"symlink": os.Symlink, "link": os.Link, "file": func(_, name string) error { return os.WriteFile(name, []byte("# C85\n"), 0o600) }}
	for _, tc := range []struct{ name, kind, target, want string }{{"a link to a file not made yet under the workspace", "symlink", filepath.Join(work, "dotfiles", "config.toml"), file},
		{"a link to a file not made yet elsewhere", "symlink", filepath.Join(cfg, "dotfiles", "config.toml"), ""}, {"a hard link to a file elsewhere", "link", present, file + " has 2 names"}, {"a file of one name", "file", "", ""},
		{"a link with a relative target, read through the linked config directory", "symlink", filepath.Join("..", "dot", "config.toml"), file}} {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(file)
			must(0, make[tc.kind](tc.target, file))
			if err := holds(work); (err != nil) != (tc.want != "") || err != nil && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("holds(%s) = %v, want %q (empty: a session there runs)", work, err, tc.want)
			}
		})
	}
	for _, p := range []string{loop, a} { // a -> a, and a -> b -> a: resolved returns, at the name it is at
		if got := resolved(p); got != p {
			t.Errorf("resolved(%s) = %s on a loop of links, want %s", p, got, p)
		}
	}
}
