// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C80 of S-1009b, the S-F62 orchestrator's probe (I5): a relative word of a cmd: source, the key's absolute path without its first slash, loads with a binding where the same path with its slash is refused; the broker runs the words from /, where the word names the key under cwd. Fix unit S-F64 moves this file to cmd/workcell/c80_test.go (S4).

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

// TestC80RelativeWordReadFromRoot (I5): loadPolicy judges a word of a cmd: source from its first slash on, so the relative word home/u/repo/.secrets/anthropic.key is judged as /u/repo/.secrets/anthropic.key, outside cwd /home/u/repo, and the row loads; the broker runs the words from / with no shell of its own, so /bin/cat reads /home/u/repo/.secrets/anthropic.key, which lies in cwd. The row holds none of the twelve characters S-F62 refuses. Controls: the literal absolute path and ./home/u/... are refused with C54's line, and a relative word that names a file outside cwd when read from / loads, now and after a fix. A session not refused goes past the export: in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. Each row not refused is run here once as the broker runs it, by the broker's own secret.Resolve, and must print the key. Precondition the attacker does not control: the operator's row spells the path that way. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export.
func TestC80RelativeWordReadFromRoot(t *testing.T) {
	const key = "sk-ant-c80-real-key-0123456789"
	for _, tc := range []struct{ source, mode, want string }{ // source: the [[secret]] source, with REL for the key's path under cwd without its first slash and OUTREL for a key outside cwd without it; mode: clone or mount; want: "refuse" (refused on this tree and after a fix), "accept" (loads, on this tree and after a fix) or "" (the finding)
		{"cmd:/bin/cat REL", "clone", ""}, {"cmd:/bin/cat REL", "mount", ""}, {"cmd:/bin/cat ./REL", "clone", "refuse"}, {"cmd:/bin/cat /REL", "clone", "refuse"}, {"cmd:/bin/cat OUTREL", "clone", "accept"}, {"cmd:/bin/cat /OUTREL", "clone", "accept"},
	} {
		t.Run(tc.mode+" "+tc.source, func(t *testing.T) {
			root := must(filepath.EvalSymlinks(must(os.MkdirTemp("", "c80")))) // not t.TempDir(): a path built from the arm's name could hold a separator or one of the twelve characters; macOS: /var is /private/var
			defer os.RemoveAll(root)
			work, data, config := filepath.Join(root, "repo"), filepath.Join(root, "data", "workcell"), filepath.Join(root, "cfg", "workcell")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			source := strings.NewReplacer("REL", strings.TrimPrefix(work, "/")+"/.secrets/anthropic.key", "OUTREL", strings.TrimPrefix(root, "/")+"/cfg/anthropic.key").Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(root, "cfg", "anthropic.key"), []byte(key+"\n"), 0o600),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); tc.want == "accept" && err != nil {
				t.Errorf("refused %s, which names a file outside cwd when read from /: %v", tc.source, err)
			} else if tc.want == "refuse" && (err == nil || !strings.Contains(err.Error(), "lies inside the directory")) {
				t.Errorf("%s, whose path lies under cwd, got %v, want C54's refusal", tc.source, err)
			} else if tc.want == "" && err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mode == "mount", a, allow, secrets).err)
				if b, err := secret.Resolve(context.Background(), source); string(b) != key { // as the broker runs it: the words split on spaces, from /, with no shell
					t.Errorf("run as the broker runs it, %q did not print the key: %v", source, err)
				}
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mode == "mount" || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key, which the broker reads from / through the relative word", e.Name(), tc.source, work)
				}
			}
		})
	}
}
