// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestSteered checks the argv that runs the product under a resolv.conf of
// the session's own: sudo only when the suite is not root, the loader in a
// new mount namespace with the file, the caller's ids, the environment as
// K=V words (a word without = would be read as the command, so it is
// dropped), then the command; and the file it names.
func TestSteered(t *testing.T) {
	dir := t.TempDir()
	env := []string{"PATH=/usr/bin:/bin", "X=a=b", "bogus", "EMPTY="}
	got, err := steered(dir, "127.5.3.53", env, []string{"/x/workcell", "run", "--", "sh"})
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if len(got) < 2 || got[0] != "sudo" || got[1] != "-n" {
			t.Fatalf("not root, yet argv starts %q", got[:2])
		}
		got = got[2:]
	} else if got[0] == "sudo" {
		t.Fatal("root, yet argv starts with sudo")
	}
	file := filepath.Join(dir, "resolv.conf")
	want := []string{"unshare", "-m", "/bin/sh", "-c", resolverLoader, "sh", file, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()),
		"PATH=/usr/bin:/bin", "X=a=b", "EMPTY=", "/x/workcell", "run", "--", "sh"}
	if !slices.Equal(got, want) {
		t.Errorf("argv %q\nwant %q", got, want)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "nameserver 127.5.3.53\n" {
		t.Errorf("resolv.conf %q, %v", b, err)
	}
}

// TestSteeredRuns runs the loader with a stand-in for the product, which
// prints what the product would see: the session's resolver in
// /etc/resolv.conf, the caller's own ids, and only the environment given;
// and the host's own /etc/resolv.conf is as it was. It needs unshare and,
// unless the test is root, sudo without a password, as a hosted runner
// has; elsewhere it is skipped.
func TestSteeredRuns(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("not root, and sudo -n does not work here")
		}
	}
	before, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Skip("no /etc/resolv.conf to bind over")
	}
	argv, err := steered(t.TempDir(), "127.9.8.7", []string{"PATH=/usr/bin:/bin", "ESCAPE_X=1", "bogus"},
		[]string{"/bin/sh", "-c", `cat /etc/resolv.conf; id -u; id -g; echo "x=$ESCAPE_X"; env | grep -c . `})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := fmt.Sprintf("nameserver 127.9.8.7\n%d\n%d\nx=1\n", os.Getuid(), os.Getgid())
	if !strings.HasPrefix(string(out), want) {
		t.Errorf("the stand-in saw:\n%s\nwant it to start:\n%s", out, want)
	}
	// After the prefix, the count of environment variables: PATH, ESCAPE_X and
	// what the shell adds (PWD, SHLVL, _ and the like): a handful, not the
	// caller's whole environment.
	var n int
	if _, err := fmt.Sscanf(strings.TrimPrefix(string(out), want), "%d", &n); err != nil || n > 8 {
		t.Errorf("the stand-in saw %d environment variables (%v): %s", n, err, out)
	}
	if after, err := os.ReadFile("/etc/resolv.conf"); err != nil || !bytes.Equal(before, after) {
		t.Errorf("the host's /etc/resolv.conf changed: %q, %v", after, err)
	}
}
