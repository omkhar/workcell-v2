// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C81 of S-1009b, the S-F62 orchestrator's probe (I5): the relative text of C80 after a separator inside a word of a cmd: source, cat<home/u/repo/.secrets/anthropic.key, and after each other separator a loadable word may hold, read as a path from / by the program or helper the row runs. Fix unit S-F65 moves this file to cmd/workcell/c81_test.go (S4).

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

// TestC81RelativeTextAfterASeparator (I5): loadPolicy judges the text after each separator of a word from its first slash on, so in cat<home/u/repo/.secrets/anthropic.key both texts are judged as /u/repo/.secrets/anthropic.key, outside cwd /home/u/repo, and the row loads; the broker runs the words from / with no shell of its own, and /bin/sh, handed the word by -c, opens home/u/repo/.secrets/anthropic.key there, which lies in cwd. The same after `=`, which dd reads as the path of its input, and after each other separator byte that none of the twelve characters S-F62 refuses covers, through a helper outside cwd that takes the text after the first separator of its argument as a path. Controls: the same rows with the slash are refused with C54's line, and a relative text after a separator that names a file outside cwd when read from / loads, now and after a fix. A session not refused goes past the export: in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. Each row not refused is run here once as the broker runs it, by the broker's own secret.Resolve, and must print the key. Precondition the attacker does not control: the operator's row spells the word that way. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export.
func TestC81RelativeTextAfterASeparator(t *testing.T) {
	const key = "sk-ant-c81-real-key-0123456789"
	for _, tc := range []struct{ source, mode, want string }{ // source: the [[secret]] source, with REL for the key's path under cwd without its first slash, OUTREL for a key outside cwd without it and OUT for the helper's directory outside cwd; mode: clone or mount; want: "refuse" (refused on this tree and after a fix), "accept" (loads, on this tree and after a fix) or "" (the finding)
		{"cmd:/bin/sh -c cat<REL", "clone", ""}, {"cmd:/bin/sh -c cat<REL", "mount", ""}, {"cmd:/bin/dd if=REL", "clone", ""}, {"cmd:OUT/get-key.sh k:REL", "mount", ""}, {"cmd:OUT/get-key.sh k,REL", "clone", ""}, {"cmd:OUT/get-key.sh k>REL", "mount", ""}, {"cmd:OUT/get-key.sh k|REL", "clone", ""},
		{"cmd:OUT/get-key.sh k(REL", "mount", ""}, {"cmd:OUT/get-key.sh k)REL", "clone", ""}, {"cmd:OUT/get-key.sh k+REL", "mount", ""}, {"cmd:OUT/get-key.sh k@REL", "clone", ""}, {"cmd:OUT/get-key.sh k%REL", "mount", ""}, {"cmd:OUT/get-key.sh k#REL", "clone", ""}, {"cmd:OUT/get-key.sh k!REL", "mount", ""}, {"cmd:OUT/get-key.sh k^REL", "clone", ""}, {"cmd:OUT/get-key.sh k]REL", "mount", ""}, {"cmd:OUT/get-key.sh k}REL", "clone", ""},
		{"cmd:/bin/sh -c cat</REL", "clone", "refuse"}, {"cmd:/bin/dd if=/REL", "clone", "refuse"}, {"cmd:OUT/get-key.sh k:/REL", "clone", "refuse"}, {"cmd:/bin/sh -c cat<OUTREL", "clone", "accept"}, {"cmd:/bin/dd if=OUTREL", "clone", "accept"}, {"cmd:OUT/get-key.sh k:OUTREL", "clone", "accept"},
	} {
		t.Run(tc.mode+" "+tc.source, func(t *testing.T) {
			root := must(filepath.EvalSymlinks(must(os.MkdirTemp("", "c81")))) // not t.TempDir(): a path built from the arm's name would hold its separator, or one of the twelve characters; macOS: /var is /private/var
			defer os.RemoveAll(root)
			work, data, config := filepath.Join(root, "repo"), filepath.Join(root, "data", "workcell"), filepath.Join(root, "cfg", "workcell")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			source := strings.NewReplacer("REL", strings.TrimPrefix(work, "/")+"/.secrets/anthropic.key", "OUTREL", strings.TrimPrefix(root, "/")+"/cfg/anthropic.key", "OUT", filepath.Dir(config)).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(root, "cfg", "anthropic.key"), []byte(key+"\n"), 0o600),
				os.WriteFile(filepath.Join(root, "cfg", "get-key.sh"), []byte("#!/bin/sh\ncat \"${1#*[!A-Za-z0-9._/-]}\"\n"), 0o700), os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600))) // the helper's path is the text after the first byte that is not a name byte, as loadPolicy cuts a word
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); tc.want == "accept" && err != nil {
				t.Errorf("refused %s, which names a file outside cwd when read from /: %v", tc.source, err)
			} else if tc.want == "refuse" && (err == nil || !strings.Contains(err.Error(), "lies inside the directory")) {
				t.Errorf("%s, whose path lies under cwd, got %v, want C54's refusal", tc.source, err)
			} else if tc.want == "" && err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mode == "mount", a, allow, secrets).err)
				if b, err := secret.Resolve(context.Background(), source); string(b) != key { // as the broker runs it: the words split on spaces, from /, with no shell of its own
					t.Errorf("run as the broker runs it, %q did not print the key: %v", source, err)
				}
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mode == "mount" || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key, which the program reads from / through the text after the separator", e.Name(), tc.source, work)
				}
			}
		})
	}
}
