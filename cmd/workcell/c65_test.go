// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C65 of S-1003 (I1, I7, I9, I13, I14). Moved here by fix unit S-F48.

//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
	"golang.org/x/sys/unix"
)

// TestC65DataDirectoryBindMountedBeneathCwd (I7, I9, I13; I1 in mount mode; I14): the operator's data directory bind-mounted beneath the working directory (`mount --bind
// $XDG_DATA_HOME/workcell repo/data; cd repo`) is a layout holds() does not refuse: within() looks for the data directory's inode among the working directory's ancestors, and the other
// way round, and a bind mount is neither a symlink nor an ancestor. So a clone session's image carries the audit key and every other session's record, a mount session reaches boot with
// the data directory in its live view, and the pull writer, given a guest tree that names data/<vmm> and data/sessions/<id>/audit.log, puts the guest's bytes over the host's VMM binary
// and the other session's record: put opens "data" beneath the destination, and openat2 crosses the mount. Root is used once, for the bind mount that models the operator's own layout:
// the test re-runs itself through sudo -n, as c52 does, and skips only where that asks for a password. The rest is the product's own functions with dummy artifacts, and no VM.
func TestC65DataDirectoryBindMountedBeneathCwd(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("not root, and sudo -n fails:", err)
		}
		out, err := exec.Command("sudo", "-n", "env", "TMPDIR="+os.TempDir(), must(os.Executable()), "-test.run=^TestC65DataDirectoryBindMountedBeneathCwd$", "-test.v", "-test.count=1").CombinedOutput()
		if t.Logf("as root:\n%s", out); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mount := range []bool{false, true} {
		t.Run(map[bool]string{true: "mount", false: "clone"}[mount], func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			data, repo := filepath.Join(os.Getenv("XDG_DATA_HOME"), "workcell"), t.TempDir() // both before the mount: their removal runs after the unmount
			a, under := c19Data(t, data, repo), filepath.Join(repo, "data")
			if err := unix.Mount(data, must(under, os.Mkdir(under, 0o700)), "", unix.MS_BIND, ""); err == unix.EPERM || must(0, err) != 0 { // EPERM skips; any other failure is the test's own
				t.Skip("root without the right to bind mount:", err)
			}
			t.Cleanup(func() { must(0, unix.Unmount(under, unix.MNT_DETACH)) })
			t.Chdir(repo)
			if r := session([]string{"true"}, limits{DiskMiB: 16}, mount, a, nil, nil); r.err == nil || !strings.Contains(r.err.Error(), data) {
				t.Errorf("session returned %v, want a refusal naming %s, of which %s is a second name", r.err, data, under)
			}
			c19Untouched(t, data)
			key, _ := os.ReadFile(filepath.Join(data, "audit.key"))
			for _, p := range must(filepath.Glob(filepath.Join(data, "sessions", "*", "*"))) { // a new session's image and boot record
				switch b, _ := os.ReadFile(p); {
				case filepath.Base(p) == "vmm":
					t.Errorf("the session reached boot: %s was written, with %s in the guest's view (I1, I7)", p, under)
				case filepath.Base(p) == "workspace.ext4" && (bytes.Contains(b, []byte("C19-OTHER-SESSION-AUDIT-LOG")) || len(key) > 0 && bytes.Contains(b, key)):
					t.Errorf("%s, the guest's /workspace, holds the other session's audit log or the bytes of %s/audit.key (I7, I9)", p, data)
				}
			}
			vmm, log := filepath.Base(a.binary), "sessions/"+idOld+"/audit.log" // what the guest's tree names under data, and what pull would then put there
			err := write(openDir(t, repo), judged(t, []guest.Entry{dirEntry("data"), fileEntry("data/"+vmm, 5, true), dirEntry("data/sessions"), dirEntry("data/sessions/" + idOld), fileEntry("data/"+log, 5, false)}), from([]byte("GUESTGUEST")))
			for p, want := range map[string]string{vmm: "dummy " + vmm, log: "C19-OTHER-SESSION-AUDIT-LOG\n"} { // the host's VMM binary and the other session's record
				if b := must(os.ReadFile(filepath.Join(data, p))); string(b) != want {
					t.Errorf("after the pull writer (%v), %s holds %q, the guest's bytes written through %s, not %q (I7, I9, I14)", err, filepath.Join(data, p), b, under, want)
				}
			}
		})
	}
}
