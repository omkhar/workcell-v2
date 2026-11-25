// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C52 of S-1003 (I1, I4, I7, I9, I13). Moved here by fix unit S-F35.

//go:build linux

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestC52BindMountAliasEvadesWithin (I1, I4; I7, I9, I13): within() compares spellings, the kernel compares identities. A bind mount (`mount --bind repo /mnt/repo; cd /mnt/repo`) gives a tree a second name that Abs, EvalSymlinks and Rel never relate to the first, so the refusals of C28 (TMPDIR inside a mount export) and C19/C29 (cwd holds the data directory) do not fire. Needs root: the gate's runner is not, so the test re-runs itself through sudo -n, as escape/sandbox does, and skips only where that asks for a password. The arms are named short to keep the socket path under 108 bytes.
func TestC52BindMountAliasEvadesWithin(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("not root, and sudo -n fails:", err)
		}
		out, err := exec.Command("sudo", "-n", "env", "TMPDIR="+os.TempDir(), must(os.Executable()), "-test.run=^TestC52BindMountAliasEvadesWithin$", "-test.v", "-test.count=1").CombinedOutput()
		if t.Logf("as root:\n%s", out); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mount := range []bool{true, false} {
		t.Run(map[bool]string{true: "mount", false: "clone"}[mount], func(t *testing.T) { // mount: TMPDIR inside the export; clone: the data directory inside it
			real, alias, data, tmp := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "workcell"), t.TempDir() // all before TMPDIR moves; their removal runs after the unmount
			if err := unix.Mount(real, alias, "", unix.MS_BIND, ""); errors.Is(err, unix.EPERM) {
				t.Skip("not root, or the bind mount is refused:", err)
			} else {
				must(0, err)
			}
			t.Cleanup(func() { must(0, unix.Unmount(alias, unix.MNT_DETACH)) })
			sub := "workcell/audit.key" // where the effect shows in the guest's view, under alias
			if mount {
				tmp, sub = filepath.Join(real, "tmp"), "tmp"
				must(0, os.Mkdir(tmp, 0o700))
			} else {
				data = filepath.Join(real, "workcell")
			}
			t.Setenv("TMPDIR", tmp)
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(alias)
			r := session([]string{"true"}, limits{DiskMiB: 16}, mount, a, nil, nil)
			if r.err == nil || !strings.Contains(r.err.Error(), alias) {
				t.Errorf("session returned %v, want a refusal naming %s, a second name of %s", r.err, alias, real)
			}
			seen, _ := os.Stat(filepath.Join(alias, sub))
			if key, err := os.Stat(filepath.Join(data, "audit.key")); err == nil && os.SameFile(key, seen) {
				t.Errorf("audit.key was minted at %s, which is %s inside the exported tree %s (os.SameFile; I7, I9)", filepath.Join(data, "audit.key"), filepath.Join(alias, sub), alias)
			}
			for _, p := range must(filepath.Glob(filepath.Join(data, "sessions", "*", "vmm"))) { // a new session's boot record names the VMM's socket directory
				vmm := strings.TrimSpace(string(must(os.ReadFile(p))))
				if parent, err := os.Stat(filepath.Dir(vmm)); err == nil && os.SameFile(parent, seen) {
					t.Errorf("the VMM's socket directory %s was made in %s, which is %s inside the mount export %s (os.SameFile; I1, I4)", vmm, filepath.Dir(vmm), filepath.Join(alias, sub), alias)
				}
			}
		})
	}
}
