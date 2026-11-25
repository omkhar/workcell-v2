// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C75 of S-1021, sweep 3 (I5): the residue of C72, as C72 was of C54. A list word of a cmd: source names the working directory itself before a ':' or ',' separator, --dir=<cwd>:<out>/b. Fixed by unit S-F59.

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

// TestC75WorkspaceBeforeAListSeparator (I5): loadPolicy judges a list word of a cmd: source from its first slash and after each ':' or ',', and each lexical ancestor of those texts, so --dir=<cwd>:<out>/b is judged as <cwd>:<out>/b, whose ancestors <cwd>:<out> and <cwd>: are not cwd, and as <out>/b, outside it; the row passes where --dir=<cwd>, the bare word <cwd> and --dir=<cwd>/k:<out>/b are refused (the control arms). S-F59: a path of such a word also ends before any separator byte (every ASCII byte that is not a letter, a digit, '.', '_', '-' or '/') and starts after one, and the texts are resolved as in C54, so a link to cwd is cwd too. A session not refused goes past the export: in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. The helper, handed the word as the broker would hand it per use, takes the text before the first list separator, or the map's key or value, as its directory and reads the key file in it; it is run here once, on the host, only when the row was not refused. Rows marked accept name no path under cwd and must not be refused: the sibling <cwd>-keys continues the name with a name byte. A name that holds '=' puts '=' into WORK and OUT themselves (t.TempDir keeps it; ':', ';', '|' and '/' it drops), so those arms show a directory whose own path holds a separator byte. Precondition the attacker does not control: the operator's row spells the word that way. The VMM is a dummy, as in C54 and C72: a session not refused fails at boot, after the export.
func TestC75WorkspaceBeforeAListSeparator(t *testing.T) {
	const key = "sk-ant-c75-real-key-0123456789"
	for _, tc := range []struct {
		name, source  string // source: the [[secret]] source, with WORK for cwd, OUT for a directory outside it and LINK for a link in OUT to cwd
		mount, accept bool
	}{
		{"clone colon", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:OUT/b", false, false}, {"mount colon", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:OUT/b", true, false}, // the names hold no separator: t.TempDir keeps a ',' of the name, and the helper would cut there
		{"clone comma", "cmd:/bin/sh OUT/get-key.sh --dir=WORK,OUT/b", false, false}, {"mount comma", "cmd:/bin/sh OUT/get-key.sh --dir=WORK,OUT/b", true, false},
		{"control --dir=WORK", "cmd:/bin/sh OUT/get-key.sh --dir=WORK", false, false}, {"control bare WORK", "cmd:/bin/sh OUT/get-key.sh WORK", false, false}, {"control --dir=WORK/k", "cmd:/bin/sh OUT/get-key.sh --dir=WORK/k:OUT/b", false, false}, // refused today, so no session exists
		{"clone bare WORK:OUT/b", "cmd:/bin/sh OUT/get-key.sh WORK:OUT/b", false, false}, {"clone --dir=WORK: alone", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:", false, false}, {"clone --dir=WORK:rel", "cmd:/bin/sh OUT/get-key.sh --dir=WORK:rel", false, false}, // the probes of S-1021; the last two names put '=' into the paths
		{"clone map equals", "cmd:/bin/sh OUT/get-key.sh --map=WORK=OUT/b", false, false}, {"mount --dir=WORK;OUT/b", "cmd:/bin/sh OUT/get-key.sh --dir=WORK;OUT/b", true, false}, {"clone pipe", "cmd:/bin/sh OUT/get-key.sh --dir=WORK|OUT/b", false, false}, // cwd ends before '=', ';' and '|'; the ';' arm's paths hold '='
		{"clone map OUT then key below WORK", "cmd:/bin/sh OUT/get-key.sh --map=OUT/a=WORK/.secrets/anthropic.key", false, false}, {"clone --dir=LINK:OUT/b", "cmd:/bin/sh OUT/get-key.sh --dir=LINK:OUT/b", false, false}, // a path below cwd starts after '='; a link to cwd ends before ':' (its paths hold '=')
		{"accepted --dir=WORK-keys/x", "cmd:/bin/sh OUT/get-key.sh --dir=WORK-keys/x", false, true}, {"accepted OUT/a:OUT/b", "cmd:/bin/sh OUT/get-key.sh --dir=OUT/a:OUT/b", false, true}, // on purpose: a sibling of cwd (its paths hold '=') and a word whose paths all lie outside
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", t.TempDir())
			helper, link := filepath.Join(filepath.Dir(config), "get-key.sh"), filepath.Join(filepath.Dir(config), "link")
			source := strings.NewReplacer("WORK", work, "OUT", filepath.Dir(config), "LINK", link).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(work+"-keys", 0o700), os.MkdirAll(config, 0o700), os.Symlink(work, link), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600),
				os.WriteFile(helper, []byte("#!/bin/sh\nw=${1#--*=}\nfor d in \"${w%%[:,;|]*}\" \"${w%%=*}\" \"${w##*=}\"; do [ -f \"$d\" ] && exec cat \"$d\"; [ -f \"$d/.secrets/anthropic.key\" ] && exec cat \"$d/.secrets/anthropic.key\"; done\nexit 1\n"), 0o700),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); tc.accept && err != nil { // a row the policy accepts on purpose names no path under cwd; no session is made for it here
				t.Errorf("refused %s, whose paths all lie outside cwd: %v", tc.source, err)
			} else if !tc.accept && err == nil { // a refusal here holds the invariant as well
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
