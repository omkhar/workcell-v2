// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C78 of S-1009, sweep 3 (I5): a cmd: source that names the key file under cwd as the shell spells the operator's home, `~`, `$HOME` or `${HOME}`, or in any other spelling a shell rewrites in a word. Fix unit S-F62 moved this file here from escape/_pending/S-F62/c78_test.go, where it waited between the audit and the fix (S4).

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

// TestC78SecretPathSpelledFromHome (I5): loadPolicy judges a word of a cmd: source from its first slash on, so `cat<~/repo/.secrets/anthropic.key` is judged as /repo/.secrets/anthropic.key, outside cwd, where the same row with the literal absolute path is refused (a control arm; a source wholly outside cwd loads, the other). The row is live for the operator: the broker runs the words from / with HOME passed and no shell of its own, and /bin/sh expands `~`, `$HOME` and `${HOME}`, as the helper's eval does; the words are run here once, on the host, with HOME alone. Listing those spellings would not close the class: the shell also rewrites a backslash, a quote pair or a `$(...)` inside a name, and bash a glob (`?`, `*`, `[o]`) or a brace word, each of which spells the literal path so that no judged word lies under cwd; and `;` or `&` lets a `cd` to HOME run before a relative path, which is judged from its slash as outside cwd. A session not refused goes past the export: in clone mode the image the guest gets as /workspace holds the key, under --mount cwd is served live. Precondition the attacker does not control: the operator's row spells the path that way. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export.
func TestC78SecretPathSpelledFromHome(t *testing.T) {
	const key = "sk-ant-c78-real-key-0123456789"
	for _, tc := range []struct{ source, mode, want string }{ // source: the [[secret]] source, with LITERAL for the operator's home, whose repo is cwd, and OUT for a directory outside both; mode: clone or mount; want: "refuse" (refused on this tree), "accept" (loads, on this tree and after the fix) or "" (the finding)
		{"cmd:/bin/sh -c cat<~/repo/.secrets/anthropic.key", "clone", ""}, {"cmd:/bin/sh -c cat<~/repo/.secrets/anthropic.key", "mount", ""}, {"cmd:/bin/sh -c cat<$HOME/repo/.secrets/anthropic.key", "clone", ""}, {"cmd:/bin/sh -c cat<${HOME}/repo/.secrets/anthropic.key", "mount", ""},
		{"cmd:OUT/get-key.sh ~/repo/.secrets/anthropic.key", "clone", ""}, {"cmd:OUT/get-key.sh $HOME/repo/.secrets/anthropic.key", "mount", ""}, {"cmd:/bin/sh -c cat<LITERAL/repo/.secrets/anthropic.key", "clone", "refuse"}, {"cmd:/bin/sh -c cat<OUT/anthropic.key", "clone", "accept"},
		{"cmd:/bin/sh -c cat<LITERAL/re\\po/.secrets/anthropic.key", "clone", ""}, {"cmd:/bin/sh -c cat<LITERAL/re''po/.secrets/anthropic.key", "mount", ""}, {"cmd:/bin/sh -c cat<LITERAL/re\"\"po/.secrets/anthropic.key", "clone", ""}, {"cmd:/bin/sh -c cat<$(echo${IFS}LITERAL/re)po/.secrets/anthropic.key", "mount", ""},
		{"cmd:OUT/get-key.sh LITERAL/re\\po/.secrets/anthropic.key", "mount", ""}, {"cmd:/bin/bash -c cat<LITERAL/rep?/.secrets/anthropic.key", "mount", ""}, {"cmd:/bin/bash -c cat<LITERAL/rep*/.secrets/anthropic.key", "clone", ""}, {"cmd:/bin/bash -c cat<LITERAL/rep[o]/.secrets/anthropic.key", "mount", ""},
		{"cmd:/bin/bash -c {cat,LITERAL/re{p,}o/.secrets/anthropic.key}", "clone", ""}, {"cmd:/bin/sh -c cd;cat<repo/.secrets/anthropic.key", "clone", ""}, // dash rewrites no glob or brace in a word; bash does, and runs cat on repo and reo; `;` runs a second command, cd to HOME, before a relative path
	} {
		t.Run(tc.mode+" "+tc.source, func(t *testing.T) {
			if _, err := os.Stat("/bin/bash"); err != nil && strings.HasPrefix(tc.source, "cmd:/bin/bash") {
				t.Skip("no /bin/bash: the glob and brace arms need it")
			}
			home, data, config := must(filepath.EvalSymlinks(must(os.MkdirTemp("", "c78")))), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var; not t.TempDir() for the home, whose name keeps `$`, `{` and `,` from the arm's name, which the shell would rewrite inside the literal path
			defer os.RemoveAll(home)
			work, out := filepath.Join(home, "repo"), filepath.Dir(config)
			t.Setenv("HOME", home)
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			source := strings.NewReplacer("LITERAL", home, "OUT", out).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(out, "anthropic.key"), []byte(key+"\n"), 0o600),
				os.WriteFile(filepath.Join(out, "get-key.sh"), []byte("#!/bin/sh\neval cat \"$1\"\n"), 0o700), os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(source)+"\"\n"), 0o600))) // the source as a TOML basic string
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, os.Stderr); tc.want == "accept" && err != nil {
				t.Errorf("refused %s, which lies wholly outside cwd: %v", tc.source, err)
			} else if tc.want == "refuse" && err == nil {
				t.Errorf("accepted %s, whose literal path lies under cwd", tc.source)
			} else if tc.want == "" && err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mode == "mount", a, allow, secrets).err)
				if b, err := exec.Command("env", append([]string{"-i", "HOME=" + home, "PATH=/usr/bin:/bin"}, strings.Fields(source[4:])...)...).CombinedOutput(); !strings.Contains(string(b), key) { // the words as the broker splits them, with the operator's HOME; they name no relative path, or `cd` to HOME before one, so cwd plays no part
					t.Errorf("run as the broker runs it, %q did not print the key: %q, %v", source, b, err)
				}
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld && (tc.mode == "mount" || strings.Contains(string(b), key)) {
					t.Errorf("I5: session %s started for %s: under --mount %s is served live as /workspace, else its export holds the key, which the shell reads through the operator's home", e.Name(), tc.source, work)
				}
			}
		})
	}
}
