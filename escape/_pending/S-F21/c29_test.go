// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C29 of S-1013 (I7, I9, I13). Fix unit S-F21 first moves this file to cmd/workcell/c29_test.go, package main, tag `linux || (darwin && arm64 && cgo)`.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC29RefusesACwdInsideTheDataDirectory (I7, I9, I13): a session run from, or a pull into, a directory strictly
// inside the data directory (sessions/, layers/<agent>/) is refused, naming both, before a session directory, key or
// boot record is made. Today it runs on, and a mount session lets guest root rewrite every other session's record.
func TestC29RefusesACwdInsideTheDataDirectory(t *testing.T) {
	for _, tc := range [][2]string{{"clone", "sessions"}, {"mount", "sessions"}, {"mount", "layers/agent"}} {
		t.Run(tc[0]+" in "+tc[1], func(t *testing.T) {
			data := filepath.Join(t.TempDir(), "workcell")
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			a, cwd := c19Data(t, data, "/elsewhere"), filepath.Join(data, tc[1])
			must(0, os.MkdirAll(cwd, 0o700))
			t.Chdir(cwd)
			err := session([]string{"true"}, limits{DiskMiB: 16}, tc[0] == "mount", a, nil, nil).err
			if err == nil || !strings.Contains(err.Error(), data) || !strings.Contains(err.Error(), cwd) {
				t.Errorf("session returned %v, want a refusal naming %s inside %s", err, cwd, data)
			}
			c29Untouched(t, data)
		})
	}
	t.Run("pull into sessions", func(t *testing.T) {
		data, repo, stderr := filepath.Join(t.TempDir(), "workcell"), t.TempDir(), strings.Builder{}
		t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		c19Data(t, data, repo)
		t.Chdir(repo)
		dest := filepath.Join(data, "sessions")
		if code, out := pull([]string{dest}, &stderr), stderr.String(); code != 1 || !strings.Contains(out, data) || !strings.Contains(out, dest) || strings.Count(out, "\n") != 1 {
			t.Errorf("pull exited %d with %q, want 1 and one line refusing %s inside %s", code, out, dest, data)
		}
		c29Untouched(t, data)
	})
}

// c29Untouched fails when a session got past the refusal. audit.key lies at <data>/audit.key, above the directory the guest gets here.
func c29Untouched(t *testing.T, data string) {
	t.Helper()
	ms, _ := filepath.Glob(filepath.Join(data, "sessions", "*"))
	for _, p := range append(ms, filepath.Join(data, "audit.key"), filepath.Join(data, "sessions", idOld, "vmm")) {
		if filepath.Base(p) != idOld && exists(p) {
			t.Errorf("%s was made, so the session ran past the refusal (I7, I9)", p)
		}
	}
}
