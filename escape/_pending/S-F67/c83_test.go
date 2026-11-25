// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C83 of S-1010 (I9). Fix unit S-F67 first moves this file to cmd/workcell/c83_test.go, as this comment says. It fails until the fix.

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC83ExportFailureKeepsTheSessionRecord (I9): a start that fails leaves exactly one session directory, whose audit log holds session_start and a session_end with result failed, and verify takes it. The first arm fails at the workspace export: the directory holds a file whose path relative to it passes PATH_MAX, which guest root of an earlier --mount session, or a hostile repository, leaves behind. The second fails later, at boot under the dummy artifacts, and shows what every failed start leaves.
func TestC83ExportFailureKeepsTheSessionRecord(t *testing.T) {
	for _, deep := range []bool{true, false} {
		t.Run(map[bool]string{true: "export: a path past PATH_MAX", false: "boot: dummy artifacts"}[deep], func(t *testing.T) {
			proj, data := filepath.Join(t.TempDir(), "proj"), filepath.Join(t.TempDir(), "workcell")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("TMPDIR", t.TempDir())
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(must(proj, os.Mkdir(proj, 0o700)))
			for d, n := strings.Repeat("d", 100), map[bool]int{true: 60}[deep]; n > 0; n-- { // 60 components of 100 bytes, each made from its parent: no whole path is ever passed
				must(0, os.Chdir(must(d, os.Mkdir(d, 0o700))))
			}
			must(0, os.WriteFile("f", []byte{1}, 0o600)) // a 1-byte file at the bottom; in the shallow arm, in the directory itself
			must(0, os.Chdir(proj))
			r := session([]string{"true"}, limits{DiskMiB: 16}, false, a, nil, nil)
			ents := must(os.ReadDir(filepath.Join(data, "sessions"))) // the earlier session's id sorts first, a new one's names today
			id := ents[len(ents)-1].Name()
			log, _ := os.ReadFile(filepath.Join(data, "sessions", id, "audit.log"))
			var out, errs strings.Builder
			if code := verify([]string{id}, &out, &errs); r.err == nil || len(ents) != 2 || code != 0 || !strings.Contains(string(log), `"event":"session_start"`) || !strings.Contains(string(log), `"event":"session_end"`) || !strings.Contains(string(log), `"result":"failed"`) {
				t.Errorf("the session failed with %v and left %d session directories besides the earlier one; the newest, %s, has audit log %q and verify exits %d (%s); want an error, one directory, a log with session_start and session_end with result failed, and exit 0: the host keeps no record of the session (I9)", r.err, len(ents)-1, id, log, code, errs.String())
			}
		})
	}
}
