// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C82 of S-1009b (I5): a file: source whose path is relative to the directory the session is run in, file:.secrets/anthropic.key, file:./.secrets/anthropic.key or file:../repo/.secrets/anthropic.key, names the key under cwd and loads with a binding, where the absolute spelling of the same file is refused with C54's line. Fix unit S-F66 moved this file here from escape/_pending/S-F66/ (S4).

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestC82RelativeFileSource (I5): loadPolicy judges the one word of a file: source from its first slash on, so .secrets/anthropic.key is judged as /anthropic.key, ./.secrets/anthropic.key as /.secrets/anthropic.key and ../repo/.secrets/anthropic.key as /repo/.secrets/anthropic.key, none inside cwd, and the row loads with a binding; read from cwd, each names the key there. The broker refuses every relative file: path, so the row can never be served, and nothing says so before the export: a session not refused goes past it, so in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. Controls: the absolute path of the key is refused with C54's line, and an absolute path outside cwd loads, now and after a fix; a fix may refuse every relative file: value or judge it against cwd, so a refusal of a finding arm holds the invariant, and it holds whether or not the repository's workcell.toml keeps the row (C58's pattern): dropped, the row loads nothing, yet the key it names is still under cwd and still goes into the export. Precondition the attacker does not control: the operator's row spells the path relative to the directory. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export.
func TestC82RelativeFileSource(t *testing.T) {
	const key = "sk-ant-c82-real-key-0123456789"
	for _, tc := range []struct{ source, mode, repo, want string }{ // source: the [[secret]] source, with WORK for cwd and ROOT for its parent; mode: clone or mount; repo: the repository's workcell.toml, "" for none; want: "refuse" (refused on this tree and after a fix), "accept" (loads, on this tree and after a fix) or "" (the finding)
		{"file:.secrets/anthropic.key", "clone", "", ""}, {"file:.secrets/anthropic.key", "mount", "", ""}, {"file:./.secrets/anthropic.key", "clone", "", ""}, {"file:../repo/.secrets/anthropic.key", "mount", "", ""}, {"file:WORK/.secrets/anthropic.key", "clone", "", "refuse"}, {"file:ROOT/cfg/anthropic.key", "clone", "", "accept"},
		{"file:.secrets/anthropic.key", "clone", "[[secret]]\nname = \"nothing\"\nsource = \"x\"\n", ""}, // C58's pattern: the repository drops the row, and the key it names is still under cwd
	} {
		t.Run(tc.mode+" "+tc.source+map[bool]string{true: " dropped by workcell.toml"}[tc.repo != ""], func(t *testing.T) {
			root := must(filepath.EvalSymlinks(must(os.MkdirTemp("", "c82")))) // not t.TempDir(): a path built from the arm's name could hold a separator; macOS: /var is /private/var
			defer os.RemoveAll(root)
			work, data, config := filepath.Join(root, "repo"), filepath.Join(root, "data", "workcell"), filepath.Join(root, "cfg", "workcell")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			source := strings.NewReplacer("WORK", work, "ROOT", root).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(root, "cfg", "anthropic.key"), []byte(key+"\n"), 0o600),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600)))
			if tc.repo != "" {
				must(0, os.WriteFile(filepath.Join(work, "workcell.toml"), []byte(tc.repo), 0o600))
			}
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); tc.want == "accept" && err != nil {
				t.Errorf("refused %s, an absolute path outside cwd: %v", tc.source, err)
			} else if tc.want == "refuse" && (err == nil || !strings.Contains(err.Error(), "lies inside the directory")) {
				t.Errorf("%s, the key's absolute path under cwd, got %v, want C54's refusal", tc.source, err)
			} else if tc.want == "" && err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mode == "mount", a, allow, secrets).err)
				_, err := secret.Resolve(context.Background(), source) // as the broker reads it, at first use, after the export: it refuses the relative path, so the row that loaded can never be served
				t.Logf("the broker, at first use: %v", err)
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mode == "mount" || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key, which the row names by a path relative to that directory", e.Name(), tc.source, work)
				}
			}
		})
	}
}
