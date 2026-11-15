// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C19 of S-1008 (I7, I8, I9, I13, I14). Fix unit S-F12 first moves this file to
// cmd/workcell/c19_test.go, as this comment says.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// c19Data fills data as a data directory before a session: dummy artifacts and an earlier session of
// repo with a marked audit log and workspace image, and no audit key. It returns the artifacts.
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

// c19Untouched fails when a session got past the refusal: a minted audit key, a new session directory
// or a boot record under data.
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

// TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory (I7, I9, I13, I14): a workspace that holds the
// data or the config directory is refused, naming it, before a session directory, key or export is made.
func TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mount, config bool // config: the workspace holds the config directory alone
	}{{"clone", false, false}, {"mount", true, false}, {"clone, config directory", false, true}} {
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
			must(0, os.MkdirAll(config, 0o700))
			must(0, os.WriteFile(filepath.Join(config, "config.toml"), []byte("# C19\n"), 0o600))
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

// TestC19PullRefusesADestinationThatHoldsTheDataDirectory (I8, I9, I14): a pull destination that holds
// the data directory is refused in one line, naming it, before anything boots.
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
