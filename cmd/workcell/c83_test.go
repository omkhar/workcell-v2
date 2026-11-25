// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C83 of S-1010 (I9), fixed by S-F67: a start that fails at the workspace export keeps its session record, as one that fails at boot does.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC83ExportFailureKeepsTheSessionRecord (I9): a start that fails leaves exactly one session directory, whose audit log holds session_start and a session_end with result failed, verify takes it, and rm removes it. The first arm fails at the workspace export: the directory holds a file whose path relative to it passes PATH_MAX, which guest root of an earlier --mount session, or a hostile repository, leaves behind. There the error must be the export's own, not a later boot's; the directory holds no half-written image; and pull and diff, which newest points at that session, refuse it in a line that does not call it a --mount session. The second arm fails later, at boot under the dummy artifacts, and shows what every failed start leaves.
func TestC83ExportFailureKeepsTheSessionRecord(t *testing.T) {
	for _, deep := range []bool{true, false} {
		t.Run(map[bool]string{true: "export: a path past PATH_MAX", false: "boot: dummy artifacts"}[deep], func(t *testing.T) {
			proj, sessions := filepath.Join(t.TempDir(), "proj"), filepath.Join(t.TempDir(), "workcell", "sessions")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(filepath.Dir(sessions)))
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("TMPDIR", t.TempDir())
			a := c19Data(t, filepath.Dir(sessions), "/elsewhere")
			t.Chdir(must(proj, os.Mkdir(proj, 0o700)))
			for d, n := strings.Repeat("d", 100), map[bool]int{true: 60}[deep]; n > 0; n-- { // 60 components of 100 bytes, each made from its parent: no whole path is ever passed
				must(0, os.Chdir(must(d, os.Mkdir(d, 0o700))))
			}
			must(0, os.Chdir(must(proj, os.WriteFile("f", []byte{1}, 0o600)))) // a 1-byte file at the bottom; in the shallow arm, in the directory itself
			r := session([]string{"true"}, limits{DiskMiB: 16}, false, a, nil, nil)
			ents := must(os.ReadDir(sessions)) // the earlier session's id sorts first, a new one's names today
			id := ents[len(ents)-1].Name()
			log, _ := os.ReadFile(filepath.Join(sessions, id, "audit.log"))
			var ferr error // what pull and diff, which share fetch, meet in the directory after the export failed: newest points at the failed session, as at a boot-failed one, and they must refuse it in one line, boot nothing, and not call it a --mount session, which it was not
			if deep {
				_, ferr = fetch(".", func(int, *manifest, source) error { return nil })
			}
			var out, errs strings.Builder
			if code := verify([]string{id}, &out, &errs); r.err == nil || deep && (!strings.HasPrefix(r.err.Error(), "copy ") || exists(filepath.Join(sessions, id, "workspace.ext4")) || ferr == nil || strings.Contains(ferr.Error(), "mount session")) || len(ents) != 2 || code != 0 || !strings.Contains(string(log), `"event":"session_start"`) || !strings.Contains(string(log), `"event":"session_end"`) || !strings.Contains(string(log), `"result":"failed"`) || removeSession(sessions, id) != nil || exists(filepath.Join(sessions, id)) {
				t.Errorf("the session failed with %.120v and left %d session directories besides the earlier one; the newest, %s, has audit log %q, an image: %t, verify exits %d (%s), pull says %.200v, and rm leaves it: %t; want the export's own error (copy ...) in the export arm, one directory, a log with session_start and session_end with result failed, no image after a failed export, exit 0, a one-line refusal of pull that does not call the session a --mount one, and rm to take the directory: the host keeps no record of the session (I9)", r.err, len(ents)-1, id, log, exists(filepath.Join(sessions, id, "workspace.ext4")), code, errs.String(), ferr, exists(filepath.Join(sessions, id)))
			}
		})
	}
}
