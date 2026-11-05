// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	idOld = "20260101T000000.000000001Z-0000000a"
	idNew = "20260102T000000.000000001Z-0000000b"
)

func TestValidID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{idOld, true},
		{"", false},
		{"..", false},
		{"../x", false},
		{idOld + "/", false},
		{idOld + "/..", false},
		{"/etc", false},
		{"a/b", false},
		{idOld[:len(idOld)-1], false},
		{strings.ToUpper(idOld), false},
		{" " + idOld, false},
		{idOld + "\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			if got := validID(tc.id); got != tc.want {
				t.Errorf("validID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

// mkSession makes a session directory under sessions, with a repo record, and returns it.
func mkSession(t *testing.T, sessions, id, repo string) string {
	t.Helper()
	dir := filepath.Join(sessions, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "repo"), []byte(repo+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestListStateAndOrder(t *testing.T) {
	sessions := t.TempDir()
	mkSession(t, sessions, idNew, "/r/new")
	held := mkSession(t, sessions, idOld, "/r/old")
	lock, err := holdSession(held)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	os.Mkdir(filepath.Join(sessions, "stray"), 0o700)
	os.WriteFile(filepath.Join(sessions, idNew[:5]), nil, 0o600)

	want := []listing{{idOld, "running", "/r/old"}, {idNew, "exited", "/r/new"}}
	got, err := list(sessions)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("list = %v, want %v", got, want)
	}
	lock.Close()
	if got, _ = list(sessions); got[0].state != "exited" {
		t.Errorf("after the lock is released: %v", got)
	}
	if got, err = list(filepath.Join(sessions, "none")); err != nil || len(got) != 0 {
		t.Errorf("no sessions directory: %v, %v", got, err)
	}
}

// TestLockDiesWithProcess shows that a SIGKILLed holder no longer counts as running.
func TestLockDiesWithProcess(t *testing.T) {
	if dir := os.Getenv("HOLD_LOCK_DIR"); dir != "" { // the child: hold the lock until killed
		if _, err := holdSession(dir); err != nil {
			os.Exit(3)
		}
		os.Stdout.WriteString("held\n")
		select {}
	}
	dir := mkSession(t, t.TempDir(), idOld, "/r")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockDiesWithProcess$")
	cmd.Env = append(os.Environ(), "HOLD_LOCK_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "held\n" {
		t.Fatalf("child said %q", line)
	}
	if up, err := running(dir); err != nil || !up {
		t.Fatalf("running with a live holder = %v, %v", up, err)
	}
	if pid, err := supervisor(dir); err != nil || pid != cmd.Process.Pid {
		t.Errorf("supervisor = %d, %v, want %d", pid, err, cmd.Process.Pid)
	}
	if err := removeSession(filepath.Dir(dir), idOld); err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("rm of a running session: %v", err)
	}
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()
	if up, err := running(dir); err != nil || up {
		t.Errorf("running after SIGKILL = %v, %v", up, err)
	}
	if err := removeSession(filepath.Dir(dir), idOld); err != nil {
		t.Errorf("rm after SIGKILL: %v", err)
	}
}

func TestRemoveSession(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		setup   func(t *testing.T, sessions, outside string) (vmm string) // returns the temp dir to record, or ""
		wantErr bool
	}{
		{"bad id", "../x", nil, true},
		{"unknown", idNew, nil, true},
		{"plain", idOld, func(t *testing.T, sessions, _ string) string {
			os.WriteFile(filepath.Join(sessions, idOld, "workspace.ext4"), []byte("x"), 0o600)
			return ""
		}, false},
		{"symlink in the session is not followed", idOld, func(t *testing.T, sessions, outside string) string {
			if err := os.Symlink(outside, filepath.Join(sessions, idOld, "link")); err != nil {
				t.Fatal(err)
			}
			return ""
		}, false},
		{"recorded VMM directory goes too", idOld, func(t *testing.T, sessions, _ string) string {
			tmp, err := os.MkdirTemp("", "wc")
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(tmp, "vsock_1"), nil, 0o600)
			return tmp
		}, false},
		{"recorded VMM directory whose path holds a space goes too", idOld, func(t *testing.T, sessions, _ string) string {
			parent := filepath.Join(t.TempDir(), "a b")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			tmp, err := os.MkdirTemp(parent, "wc")
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(filepath.Join(tmp, "vsock_1"), nil, 0o600)
			return tmp
		}, false},
		{"recorded directory already gone", idOld, func(t *testing.T, sessions, _ string) string {
			return filepath.Join(t.TempDir(), "wcgone")
		}, false},
		{"recorded path that is a link is refused", idOld, func(t *testing.T, sessions, outside string) string {
			link := filepath.Join(t.TempDir(), "wclink")
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			return link
		}, true},
		{"recorded path of another name is refused", idOld, func(t *testing.T, sessions, outside string) string {
			return outside
		}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessions, outside := t.TempDir(), t.TempDir()
			keep := filepath.Join(outside, "keep")
			os.WriteFile(keep, []byte("x"), 0o600)
			var tmp string
			if tc.setup != nil {
				mkSession(t, sessions, idOld, "/r")
				if tmp = tc.setup(t, sessions, outside); tmp != "" {
					if err := recordBoot(filepath.Join(sessions, idOld), tmp); err != nil {
						t.Fatal(err)
					}
					defer os.RemoveAll(tmp)
				}
			}
			err := removeSession(sessions, tc.id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("removeSession: %v, wantErr %v", err, tc.wantErr)
			}
			if _, err := os.Stat(keep); err != nil {
				t.Errorf("a file outside the session was removed: %v", err)
			}
			if tc.setup == nil || tc.wantErr {
				return
			}
			if _, err := os.Lstat(filepath.Join(sessions, idOld)); err == nil {
				t.Error("the session directory is still there")
			}
			if _, err := os.Lstat(tmp); err == nil {
				t.Error("the recorded VMM directory is still there")
			}
		})
	}
}
