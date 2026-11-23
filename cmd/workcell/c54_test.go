// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C54 of S-1007 (I5): a [[secret]] row whose file: or cmd: source lies under the directory the session runs in. Fixed by unit S-F37.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"cmp"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC54SecretSourceUnderTheWorkspace (I5): the operator's key file, or the program that prints the key, lies under cwd. Neither loadPolicy nor session
// compares a source path with cwd, so the session starts and the guest gets the file as part of /workspace: in the clone image, or live under --mount, where it
// can also rewrite the program the host runs for every later lookup. The session must be refused before a session directory or an export exists, as a cwd that
// holds the data directory is (C19), or at least the key bytes must not reach the image. The VMM is a dummy: a session not refused fails at boot, after both.
func TestC54SecretSourceUnderTheWorkspace(t *testing.T) {
	const key = "sk-ant-c54-real-key-0123456789"
	for _, tc := range []struct {
		name, source string // source: the [[secret]] source, with WORK for cwd and BASE for its last element
		mount        bool
	}{
		{"clone, file: under cwd", "file:WORK/.secrets/anthropic.key", false}, {"mount, file: under cwd", "file:WORK/.secrets/anthropic.key", true},
		{"clone, file: through ..", "file:WORK/../BASE/.secrets/anthropic.key", false},
		{"mount, cmd: under cwd", "cmd:WORK/tools/get-key.sh", true}, {"clone, cmd: under cwd", "cmd:WORK/tools/get-key.sh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", t.TempDir())
			source := strings.NewReplacer("WORK", work, "BASE", filepath.Base(work)).Replace(tc.source)
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(filepath.Join(work, "tools"), 0o700), os.MkdirAll(config, 0o700),
				os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(work, "tools", "get-key.sh"), []byte("#!/bin/sh\necho "+key+"\n"), 0o700),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\"]\n\n[[secret]]\nname = \"anthropic\"\nsource = \""+source+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			if allow, secrets, _, _, err := loadPolicy(nil, io.Discard); err == nil { // a refusal here holds the invariant as well
				t.Logf("session: %v", session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, allow, secrets).err)
			}
			ents, _ := os.ReadDir(filepath.Join(data, "sessions"))
			for _, e := range ents {
				if e.Name() == idOld {
					continue
				}
				image := filepath.Join(data, "sessions", e.Name(), "workspace.ext4")
				if b, _ := os.ReadFile(image); tc.mount {
					t.Errorf("I5: the session %s started with %s served live as /workspace, where the guest reads %s", e.Name(), work, source)
				} else if bytes.Contains(b, []byte(key)) {
					t.Errorf("I5: the key of %s lies in the export %s, which the guest gets as /workspace", source, image)
				}
			}
		})
	}
}
