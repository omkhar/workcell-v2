// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C58 of S-1009, sweep 2 (I5, I13). Fix unit S-F41 moved this file here from
// escape/_pending/S-F41/c58_test.go, where it waited between the audit and the fix (S4).

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestC58RepositoryCannotSwitchOffTheSourceCheck (I5, I13): the operator's key file lies under cwd, as in C54, and the repository's workcell.toml drops the [[secret]] row that names it, by naming
// another row or by emptying [network] allow. The row is gone, but the key file is still under cwd and still goes into the guest's /workspace. A repository file that changes nothing leaves the
// config refused before anything is made (C54); one that drops the row must not switch that refusal off. The VMM is a dummy: a session not refused fails at boot, after the session directory and the export.
func TestC58RepositoryCannotSwitchOffTheSourceCheck(t *testing.T) {
	const key = "sk-ant-c58-real-key-0123456789"
	for _, repo := range []string{"# C58: changes nothing\n", "[[secret]]\nname = \"nothing\"\nsource = \"x\"\n", "[network]\nallow = []\n"} { // the repository's workcell.toml
		for _, mount := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q mount=%t", repo, mount), func(t *testing.T) {
				work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell")
				t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
				t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
				must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, repoFile), []byte(repo), 0o600),
					os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(config, "config.toml"),
						[]byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nhost = \"api.anthropic.com\"\nheader = \"x-api-key\"\nsource = \"file:"+work+"/.secrets/anthropic.key\"\n"), 0o600)))
				a := c19Data(t, data, "/elsewhere")
				t.Chdir(work)
				if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); err == nil { // a refusal here holds the invariant
					t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, mount, a, allow, secrets).err)
				}
				for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) {
					if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld {
						t.Errorf("I5: session %s was made with %s as /workspace (mount: %t; the key lies in its export: %t)", e.Name(), work, mount, bytes.Contains(b, []byte(key)))
					}
				}
			})
		}
	}
}
