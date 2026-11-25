// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Regression test of finding C62 of S-1013, sweep 2 (I12), fixed by S-F45.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC62WorkingDirectoryNameReachesTheTerminalRaw (I12; the quoting rule of C20, C31 and C38): guest root in a --mount session on an ancestor of the operator's shell renames that directory to a name holding terminal control bytes. A later workcell run there records the name; ls, explain and pull's refusal print it raw.
func TestC62WorkingDirectoryNameReachesTheTerminalRaw(t *testing.T) {
	proj, data := filepath.Join(t.TempDir(), "proj\x1b]0;owned\a\x1b[2J\x1b[31m"), filepath.Join(t.TempDir(), "workcell")
	t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	a := c19Data(t, data, "/elsewhere")
	t.Chdir(must(proj, os.Mkdir(proj, 0o700)))
	session([]string{"true"}, limits{DiskMiB: 16}, false, a, nil, nil) // ends at boot under the dummy VMM; the session and its directory are recorded
	var out strings.Builder
	ls(nil, &out, &out)
	_, err := newest(filepath.Dir(must(newest(filepath.Join(data, "sessions"), proj))), filepath.Join(filepath.Dir(proj), "other\x1b[2J")) // the first must: proj's session is on record
	for _, row := range []struct{ verb, text string }{{"ls", out.String()}, {"explain", explanation(false, proj)}, {"explain --mount", explanation(true, proj)}, {"pull", err.Error()}} {
		if strings.ContainsRune(row.text, 0x1b) {
			t.Errorf("workcell %s prints the working directory's name raw: %q carries an ESC the guest chose to the operator's terminal", row.verb, row.text)
		}
	}
}
