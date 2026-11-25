// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C72 of S-1007, sweep 3 (I5): a cmd: source whose program lies outside cwd, but one of whose option words names a file under cwd spelled inside the word (--key=<cwd>/... or -k<cwd>/...). Fixed by unit S-F56.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC72SecretPathInsideAnOptionWord (I5): loadPolicy judges a word of a cmd: source against cwd only when the whole word is an absolute path, so the key file under cwd passes when its path is spelled inside an option word, where the same path as a bare word is refused (the control arm, which main passes). The session then goes past the export: in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. Precondition the attacker does not control: the operator's row spells the path that way. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export. The program reads the file under either spelling, but is never run here: the broker would run it per use.
func TestC72SecretPathInsideAnOptionWord(t *testing.T) {
	const key = "sk-ant-c72-real-key-0123456789"
	for _, tc := range []struct {
		name, source string // source: the [[secret]] source, with WORK for cwd and OUT for a directory outside it
		mount        bool
	}{
		{"clone, --key=", "cmd:/bin/sh OUT/get-key.sh --key=WORK/.secrets/anthropic.key", false}, {"mount, --key=", "cmd:/bin/sh OUT/get-key.sh --key=WORK/.secrets/anthropic.key", true}, {"clone, -k", "cmd:/bin/sh OUT/get-key.sh -kWORK/.secrets/anthropic.key", false},
		{"mount, -k", "cmd:/bin/sh OUT/get-key.sh -kWORK/.secrets/anthropic.key", true}, {"control: clone, bare word", "cmd:/bin/sh OUT/get-key.sh WORK/.secrets/anthropic.key", false}, // the control: refused, so no session exists; accepted, its export would hold the key
		{"clone, --files=OUT:WORK", "cmd:/bin/sh OUT/get-key.sh --files=OUT/a:WORK/.secrets/anthropic.key", false}, {"mount, --files=OUT:WORK", "cmd:/bin/sh OUT/get-key.sh --files=OUT/a:WORK/.secrets/anthropic.key", true}, {"clone, -fOUT,WORK", "cmd:/bin/sh OUT/get-key.sh -fOUT/a,WORK/.secrets/anthropic.key", false}, // the review of S-F56: a word that holds two paths, the second one under cwd
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", t.TempDir())
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(filepath.Dir(config), "get-key.sh"), []byte("#!/bin/sh\np=${1#--key=}\ncat \"${p#-k}\"\n"), 0o700),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+strings.NewReplacer("WORK", work, "OUT", filepath.Dir(config)).Replace(tc.source)+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, allow, secrets).err)
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mount || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key", e.Name(), tc.source, work)
				}
			}
		})
	}
}
