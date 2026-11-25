// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C75 of S-1021, sweep 3 (I5): the residue of C72, as C72 was of C54. A list word of a cmd: source names the working directory itself before a ':' or ',' separator, --dir=<cwd>:<out>/b. Its fix unit moves this file to cmd/workcell/c75_test.go, beside c72_test.go.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"cmp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestC75WorkspaceBeforeAListSeparator (I5): loadPolicy judges a list word of a cmd: source from its first slash and after each separator, and each lexical ancestor of those texts. The word --dir=<cwd>:<out>/b is judged as <cwd>:<out>/b, whose ancestors
// <cwd>:<out> and <cwd>: are not cwd, and as <out>/b, which lies outside it; so the row passes where --dir=<cwd>, the bare word <cwd> and --dir=<cwd>/k:<out>/b are refused (the control arms). The session then goes past the export: in clone mode
// the image the guest gets as /workspace holds the key, under --mount cwd is served live. The helper, handed the word as the broker would hand it per use, takes the text before the separator as its directory and reads the key file in it; it is
// run here once, on the host, only when the row was not refused. Precondition the attacker does not control: the operator's row spells the word that way. The VMM is a dummy, as in C54 and C72: a session not refused fails at boot, after the export.
func TestC75WorkspaceBeforeAListSeparator(t *testing.T) {
	const key = "sk-ant-c75-real-key-0123456789"
	for _, tc := range []struct {
		name, source string // source: the [[secret]] source, with WORK for cwd and OUT for a directory outside it
		mount        bool
	}{
		{"clone colon", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:OUT/b", false}, {"mount colon", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:OUT/b", true}, // the names hold no separator: t.TempDir keeps a ',' of the name, and the helper would cut there
		{"clone comma", "cmd:/bin/sh OUT/get-key.sh --dir=WORK,OUT/b", false}, {"mount comma", "cmd:/bin/sh OUT/get-key.sh --dir=WORK,OUT/b", true},
		{"control --dir=WORK", "cmd:/bin/sh OUT/get-key.sh --dir=WORK", false}, {"control bare WORK", "cmd:/bin/sh OUT/get-key.sh WORK", false}, {"control --dir=WORK/k", "cmd:/bin/sh OUT/get-key.sh --dir=WORK/k:OUT/b", false}, // refused today, so no session exists
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", t.TempDir())
			helper, source := filepath.Join(filepath.Dir(config), "get-key.sh"), strings.NewReplacer("WORK", work, "OUT", filepath.Dir(config)).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(helper, []byte("#!/bin/sh\nd=${1#--dir=}\nd=${d%%[:,]*}\ncat \"$d/.secrets/anthropic.key\"\n"), 0o700),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, allow, secrets).err)
				if out, err := exec.Command("/bin/sh", helper, source[strings.LastIndexByte(source, ' ')+1:]).CombinedOutput(); !strings.Contains(string(out), key) { // the last word, as the broker would hand it
					t.Errorf("the helper, handed the last word of %q, did not read the key: %q, %v", source, out, err)
				}
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mount || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key, which the helper reads from the text before the separator", e.Name(), tc.source, work)
				}
			}
		})
	}
}
