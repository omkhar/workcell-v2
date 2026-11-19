// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C28 of S-1013 (I1, I4). Fix unit S-F20 first moves this file to cmd/workcell/c28_test.go, package main,
// build tag `linux || (darwin && arm64 && cgo)`, as this comment says.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC28TempDirInMountExport (I1, I4): a mount session whose export holds os.TempDir()
// is refused, naming that directory, before boot. Otherwise the VMM's vsock_<port> sockets are made inside the
// tree the guest may rewrite: guest root unlinks one and symlinks it to a host socket of the operator's uid
// (docker.sock, ssh-agent), and the VMM's next connect for that port follows the link.
func TestC28TempDirInMountExport(t *testing.T) {
	for _, tc := range []struct {
		name, sub string
		link      bool // TMPDIR is a symlink outside the export that resolves into it
	}{{"cwd", "", false}, {"cwd/tmp", "tmp", false}, {"link to cwd/tmp", "tmp", true}} { // `cd /tmp && workcell run --mount`, or TMPDIR set under the repository by its .envrc
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir() // the test's own temp root is fixed here, before TMPDIR moves
			data, config := filepath.Join(t.TempDir(), "workcell"), t.TempDir()
			real := filepath.Join(work, tc.sub)
			must(0, os.MkdirAll(real, 0o700))
			tmp := real
			if tc.link {
				tmp = filepath.Join(t.TempDir(), "tmp-link")
				must(0, os.Symlink(real, tmp))
			}
			t.Setenv("TMPDIR", tmp)
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", config)
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			r := session([]string{"true"}, limits{DiskMiB: 16}, true, a, nil, nil)
			if r.err == nil {
				t.Fatal("the session ran")
			}
			if !strings.Contains(r.err.Error(), tmp) && !strings.Contains(r.err.Error(), real) {
				t.Errorf("session failed with %q, want a refusal naming the temp directory %s inside the export", r.err, tmp)
			}
			ents, _ := os.ReadDir(filepath.Join(data, "sessions"))
			for _, e := range ents { // a new session's boot record names the directory the sockets were made in
				if e.Name() == idOld {
					continue
				}
				if b, err := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "vmm")); err == nil {
					t.Errorf("the session reached boot: the VMM's sockets were made in %s, inside the mount export %s (I1, I4)", strings.TrimSpace(string(b)), work)
				}
			}
			if left, _ := filepath.Glob(filepath.Join(real, "wc*")); len(left) > 0 {
				t.Errorf("a VMM directory was left inside the export: %v", left)
			}
		})
	}
	t.Run("elsewhere", func(t *testing.T) { // the temp directory outside the export: the mount session is not refused for it
		work, tmp := t.TempDir(), t.TempDir()
		data, config := filepath.Join(t.TempDir(), "workcell"), t.TempDir()
		t.Setenv("TMPDIR", tmp)
		t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
		t.Setenv("XDG_CONFIG_HOME", config)
		a := c19Data(t, data, "/elsewhere")
		t.Chdir(work)
		r := session([]string{"true"}, limits{DiskMiB: 16}, true, a, nil, nil)
		if r.err != nil && strings.Contains(r.err.Error(), tmp) {
			t.Errorf("session failed with %q: a temp directory outside the export was refused", r.err)
		}
	})
}
