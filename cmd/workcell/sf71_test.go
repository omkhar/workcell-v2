// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Unit S-F71 (I5): the secret-source rule of ADR-006, check one, which closes the class of C54, C58 and C82 and the three rows of PARKED 225, and admits every word after the program (C72, C75, C78, C80, C81: out of scope, SPEC section 2).

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"cmp"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestSF71SecretSourceJudgedAsTheHostOpensIt (I5): loadPolicy judges the one path the host opens or runs, the file: path or the first field of a cmd: source, as the kernel walks it: the scheme is spelled exactly as the broker's switch has it (file, cmd, secret-service, keychain, signin); the path is absolute and neither lies in nor leads into the working directory or the data directory, every prefix resolved; a file: names, at load, one regular file with one name. Any other row is refused before a session directory exists, with no export. want: refuse, where main loads the row and makes a session for it, or refuses it already (the prefix and target arms, which pass on main); accept, which loads on main and after; admit, a word after the program, which main refuses and the rule no longer reads, so the arm FAILS ON MAIN BY DESIGN and must load after the fix. The fixtures are made here: the key under cwd, a key outside with one name, a hard link outside to the key inside, a directory, a FIFO, a link to an unmade file, a link outside into cwd and one into the data directory, a link in cwd to /bin/sh, a key and a program in the data directory. The VMM is a dummy, as in C54: a session not refused fails at boot, after the export.
func TestSF71SecretSourceJudgedAsTheHostOpensIt(t *testing.T) {
	const key = "sk-ant-sf71-real-key-0123456789"
	for _, tc := range []struct {
		source, want, words string // source: the [[secret]] source, with WORK for cwd, DATA for the data directory and OUT for a directory outside both; words: a text the refusal must hold, "" for any refusal
		mount               bool
	}{
		{"FILE:WORK/.secrets/anthropic.key", "refuse", "", false}, {"File:WORK/.secrets/anthropic.key", "refuse", "", true}, {"foo:WORK/.secrets/anthropic.key", "refuse", "", false}, {"Cmd:/bin/cat OUT/anthropic.key", "refuse", "", true}, {"FILE:OUT/anthropic.key", "refuse", "", true}, // PARKED 225: a scheme not spelled as the broker's switch, today a dead row that loads
		{"file://localhostWORK/.secrets/anthropic.key", "refuse", "", false}, {"file://localhostWORK/.secrets/anthropic.key", "refuse", "", true}, // PARKED 225: read as /localhost/<path>, no regular file
		{"file:OUT/hard.key", "refuse", "", false}, {"file:OUT/hard.key", "refuse", "", true}, // PARKED 225: a second name of the key inside, served live and exported
		{"file:OUT/absent", "refuse", "", true}, {"file:OUT/dir", "refuse", "", true}, {"file:OUT/fifo", "refuse", "", true}, {"file:OUT/unmade.link", "refuse", "", true}, {"file:", "refuse", "", true}, // newly refused: absent, not regular, a link to an unmade file (ADR-006 line 68), no path
		{"cmd:", "refuse", "", true}, {"cmd:tools/get-key.sh", "refuse", "", false}, // newly refused: no program, a relative program (run in cwd, it names the script there)
		{"file:DATA/anthropic.key", "refuse", "", true}, {"cmd:DATA/get-key.sh", "refuse", "", true}, {"file:OUT/intodata/anthropic.key", "refuse", "", true}, {"cmd:OUT/intodata/get-key.sh", "refuse", "", true}, // newly refused: in, or leading into, the data directory
		{"cmd:WORK/tool", "refuse", "lies inside the directory", true}, {"cmd:OUT/intowork/tools/get-key.sh", "refuse", "lies inside the directory", true}, {"file:OUT/intowork/.secrets/anthropic.key", "refuse", "lies inside the directory", false}, // ADR-006 lines 68 and 78: the prefix <cwd> refuses a link to /bin/sh; a link from outside is judged by its target
		{"file:OUT/anthropic.key", "accept", "", false}, {"cmd:/bin/sh OUT/get-key.sh --verbose", "accept", "", false}, {"secret-service:workcell/anthropic", "accept", "", false}, {"keychain:workcell/anthropic", "accept", "", false}, {"signin:login.sf71.test/oauth/token", "accept", "", false}, // controls: admitted on main and after
		{"cmd:/bin/sh OUT/get-key.sh --key=WORK/.secrets/anthropic.key", "admit", "", false}, {"cmd:/bin/cat WORK/.secrets/anthropic.key", "admit", "", false}, // ADR-006 line 35, newly admitted: C72's and C54's word after the program; FAILS ON MAIN BY DESIGN, since main refuses the word
	} {
		t.Run(tc.want+" "+tc.source+map[bool]string{true: " mount"}[tc.mount], func(t *testing.T) {
			root := must(filepath.EvalSymlinks(must(os.MkdirTemp("", "sf71")))) // not t.TempDir(): a path built from the arm's name would hold a separator of main's word loop; macOS: /var is /private/var
			defer os.RemoveAll(root)
			work, data, config, out := filepath.Join(root, "repo"), filepath.Join(root, "data", "workcell"), filepath.Join(root, "cfg", "workcell"), filepath.Join(root, "out")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", filepath.Join(root, "tmp"))
			source, script := strings.NewReplacer("WORK", work, "DATA", data, "OUT", out).Replace(tc.source), []byte("#!/bin/sh\necho "+key+"\n")
			must(0, cmp.Or(os.MkdirAll(filepath.Join(work, ".secrets"), 0o700), os.MkdirAll(filepath.Join(work, "tools"), 0o700), os.MkdirAll(config, 0o700), os.MkdirAll(filepath.Join(out, "dir"), 0o700), os.MkdirAll(filepath.Join(root, "tmp"), 0o700),
				os.WriteFile(filepath.Join(work, ".secrets", "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(work, "tools", "get-key.sh"), script, 0o700), os.WriteFile(filepath.Join(out, "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(out, "get-key.sh"), script, 0o700),
				os.Link(filepath.Join(work, ".secrets", "anthropic.key"), filepath.Join(out, "hard.key")), syscall.Mkfifo(filepath.Join(out, "fifo"), 0o600), os.Symlink(filepath.Join(out, "unmade"), filepath.Join(out, "unmade.link")), os.Symlink(data, filepath.Join(out, "intodata")), os.Symlink(work, filepath.Join(out, "intowork")), os.Symlink("/bin/sh", filepath.Join(work, "tool")),
				os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.anthropic.com\", \"login.sf71.test\"]\n\n[[secret]]\nname = \"k\"\nhost = \"api.anthropic.com\"\nheader = \"authorization\"\nsource = \""+source+"\"\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			must(0, cmp.Or(os.WriteFile(filepath.Join(data, "anthropic.key"), []byte(key+"\n"), 0o600), os.WriteFile(filepath.Join(data, "get-key.sh"), script, 0o700)))
			t.Chdir(work)
			allow, secrets, _, _, err := loadPolicy(nil, io.Discard)
			switch {
			case tc.want == "admit" && err != nil:
				t.Errorf("refused %s, a word after the program, which ADR-006 admits (main refuses it, so this arm fails on main by design): %v", tc.source, err)
			case tc.want == "accept" && err != nil:
				t.Errorf("refused %s, which the rule admits: %v", tc.source, err)
			case tc.want == "refuse" && err == nil:
				t.Errorf("I5: loaded %s with a binding; session: %v", tc.source, session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, allow, secrets).err)
			case tc.want == "refuse" && !strings.Contains(err.Error(), tc.words):
				t.Errorf("refused %s with %v, want the words %q", tc.source, err, tc.words)
			}
			for _, e := range must(os.ReadDir(filepath.Join(data, "sessions"))) { // c19Data made idOld; any other session was not refused before its directory and export
				if b, _ := os.ReadFile(filepath.Join(data, "sessions", e.Name(), "workspace.ext4")); e.Name() != idOld {
					t.Errorf("I5: session %s was made for %s (mount: %t, so %s is served live; the key lies in its export: %t)", e.Name(), tc.source, tc.mount, work, bytes.Contains(b, []byte(key)))
				}
			}
		})
	}
}
