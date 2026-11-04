// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDataDir(t *testing.T) {
	tests := []struct {
		name, xdg, home, want string
	}{
		{"XDG_DATA_HOME wins", "/x/data", "/home/u", "/x/data/workcell"},
		{"HOME otherwise", "", "/home/u", "/home/u/.local/share/workcell"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tc.xdg)
			t.Setenv("HOME", tc.home)
			got, err := dataDir()
			if err != nil || got != tc.want {
				t.Errorf("dataDir() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestFindArtifacts(t *testing.T) {
	names := required()
	without := func(n string) []string {
		return slices.DeleteFunc(slices.Clone(names), func(s string) bool { return s == n })
	}
	tests := []struct {
		name    string
		present []string
		missing string // the file the error must name; "" for success
	}{
		{"all", names, ""},
		{"none", nil, names[0]},
		{"no kernel", without("vmlinux"), "vmlinux"},
		{"no initrd", without("initrd.cpio"), "initrd.cpio"},
		{"no image", without("root.ext4"), "root.ext4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, n := range tc.present {
				if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			a, err := findArtifacts(dir)
			switch {
			case tc.missing == "" && (err != nil || a.image != filepath.Join(dir, "root.ext4")):
				t.Errorf("findArtifacts = %+v, %v; want them all", a, err)
			case tc.missing != "" && (err == nil || !strings.Contains(err.Error(), filepath.Join(dir, tc.missing))):
				t.Errorf("findArtifacts error = %v, want one naming %s", err, tc.missing)
			}
		})
	}
}

// TestRunUnavailable runs `workcell run` where it cannot start a session: on Linux with an
// empty data directory, elsewhere because there is no backend. Both end with 125 and a
// line that says why. It boots nothing, so it needs no hypervisor.
func TestRunUnavailable(t *testing.T) {
	want := map[string]string{"linux": "firecracker is missing", "darwin": "vmlinux is missing"}
	msg, ok := want[runtime.GOOS]
	if !ok {
		msg = "no backend for this OS yet"
	}
	empty := t.TempDir()
	t.Setenv("XDG_DATA_HOME", empty)
	t.Setenv("HOME", empty)
	var stderr bytes.Buffer
	if code := run([]string{"--", "true"}, &stderr); code != 125 || !strings.Contains(stderr.String(), msg) {
		t.Errorf("run exited %d with %q, want 125 and a line with %q", code, stderr.String(), msg)
	}
}
