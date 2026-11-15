// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// c19Data fills data with what a data directory holds before a session: the pinned artifacts (dummies: nothing boots here), the VMM binary where the
// backend is a program, and an earlier session of repo with its audit log and its workspace image, each carrying a marker. It mints no audit key: a
// session that is refused before it starts must leave none behind. It returns the artifacts as loadArtifacts would.
func c19Data(t *testing.T, data, repo string) artifacts {
	t.Helper()
	must(0, os.MkdirAll(data, 0o700))
	for _, n := range required() {
		must(0, os.WriteFile(filepath.Join(data, n), []byte("dummy "+n), 0o644)) // not executable: a boot that gets this far fails at once
	}
	other := mkSession(t, filepath.Join(data, "sessions"), idOld, repo)
	must(0, os.WriteFile(filepath.Join(other, "audit.log"), []byte("C19-OTHER-SESSION-AUDIT-LOG\n"), 0o600))
	must(0, os.WriteFile(filepath.Join(other, "workspace.ext4"), []byte("C19-OTHER-SESSION-WORKSPACE"), 0o600))
	a, err := findArtifacts(data)
	must(0, err)
	return a
}

// c19Untouched fails the test when a session got past the refusal: a new session directory, a minted audit key, or a boot record (vmm) in the earlier
// session's directory, under the data directory data.
func c19Untouched(t *testing.T, data string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(data, "audit.key")); err == nil {
		t.Errorf("%s was minted inside the directory the guest gets: the guest can seal a rewritten log (I9)", filepath.Join(data, "audit.key"))
	}
	entries, _ := os.ReadDir(filepath.Join(data, "sessions"))
	for _, e := range entries {
		if e.Name() != idOld {
			t.Errorf("a session directory %s was made inside the directory the guest gets (I7)", e.Name())
			if files, err := os.ReadDir(filepath.Join(data, "sessions", e.Name())); err == nil {
				for _, f := range files {
					t.Logf("  it holds %s", f.Name())
				}
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(data, "sessions", idOld, "vmm")); err == nil {
		t.Errorf("the session reached boot: %s was written", filepath.Join(data, "sessions", idOld, "vmm"))
	}
}

// TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory (I7, I9, I13, I14): `cd ~ && workcell run claude` makes the home directory the workspace, and
// the data directory (~/.local/share/workcell) and the config directory (~/.config/workcell) lie inside it. In clone mode the export then copies the
// audit key, every other session's audit log and workspace image, and the boot artifacts into the guest's /workspace, and `workcell pull` writes the
// guest's versions back over them; in mount mode the guest has them live. A session whose directory holds either must be refused before a session
// directory, a key or an export is made, with an error that names the directory it holds.
func TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory(t *testing.T) {
	tests := []struct {
		name   string
		mount  bool
		config bool // the workspace holds the config directory alone; the data directory lies elsewhere
	}{
		{"clone", false, false},
		{"mount", true, false},
		{"clone, config directory", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir() // the operator's directory, the session's workspace
			data, config := filepath.Join(work, "workcell"), filepath.Join(t.TempDir(), "workcell")
			if tc.config {
				data, config = filepath.Join(t.TempDir(), "workcell"), filepath.Join(work, "workcell")
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
			held := data
			if tc.config {
				held = config
			}
			if !strings.Contains(r.err.Error(), held) {
				t.Errorf("session failed with %q, want a refusal naming %s", r.err, held)
			}
			c19Untouched(t, data)
		})
	}
}

// TestC19PullRefusesADestinationThatHoldsTheDataDirectory (I8, I9, I14): `workcell pull <dir>` writes the guest's tree into dir, replacing any file
// that is there. When dir holds the data directory, the guest's `workcell/audit.key`, `workcell/root.ext4` or `workcell/sessions/<id>/audit.log`
// passes checkPath and lands on the host's. pull must refuse such a destination before it boots anything.
func TestC19PullRefusesADestinationThatHoldsTheDataDirectory(t *testing.T) {
	dest := t.TempDir()
	data, repo := filepath.Join(dest, "workcell"), filepath.Join(dest, "repo")
	must(0, os.Mkdir(repo, 0o700))
	t.Setenv("XDG_DATA_HOME", dest)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c19Data(t, data, repo) // the newest session of repo, whose image pull would boot
	t.Chdir(repo)
	var stderr bytes.Buffer
	code := pull([]string{dest}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), data) || strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("pull exited %d with %q, want 1 and one line refusing a destination that holds %s", code, stderr.String(), data)
	}
	c19Untouched(t, data)
}
