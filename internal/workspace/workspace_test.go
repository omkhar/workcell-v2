// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// debugfs runs one debugfs request against the image and returns what it printed, with
// white space collapsed.
func debugfs(t *testing.T, image, request string) string {
	t.Helper()
	out, _ := exec.Command("debugfs", "-R", request, image).CombinedOutput() // a missing path is a message, not a failure
	return strings.Join(strings.Fields(string(out)), " ")
}

// TestExport exports a tree that holds what a hostile repository holds and reads the image back.
func TestExport(t *testing.T) {
	for _, tool := range []string{"e2fsck", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH: %v", tool, err)
		}
	}
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("a/b/c.txt", "hello\n")
	write(".git/config", "[core]\n")
	write("empty", "")
	write("hard1", "linked\n")
	if err := os.Link(filepath.Join(dir, "hard1"), filepath.Join(dir, "hard2")); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"passwd": "/etc/passwd", "up": "../../..", "dangling": "nowhere", "a/dir": "/"} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "workspace.ext4")
	st, err := Export(context.Background(), dir, image, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stats %+v", st)
	if st.Files != 5 || st.Bytes != int64(len("hello\n[core]\nlinked\n")) || st.Cloned+st.Copied != 3 {
		t.Errorf("stats %+v, want 5 files (a hard link counts twice) with 20 bytes in 3 files with data", st)
	}
	if out, err := exec.Command("e2fsck", "-fn", image).CombinedOutput(); err != nil {
		t.Fatalf("e2fsck -fn: %v\n%s", err, out)
	}
	tests := []struct {
		request string
		want    string // in the output, or "" for "File not found"
	}{
		{"cat /a/b/c.txt", "hello"},
		{"cat /.git/config", "[core]"},
		{"stat /empty", "Size: 0"},
		{"stat /passwd", "Type: symlink Mode: 0777"},
		{"stat /passwd", `Fast link dest: "/etc/passwd"`},
		{"stat /up", `Fast link dest: "../../.."`},
		{"stat /dangling", `Fast link dest: "nowhere"`},
		{"stat /a/dir", `Fast link dest: "/"`},
		{"stat /hard1", "Links: 2"},
		{"stat /hard2", "Links: 2"},
		{"stat /fifo", ""},
		{"stat /a/b/c.txt", "Mode: 0640 Flags: 0x80000 Generation: 0 Version: 0x00000000:00000000 User: 0 Group: 0"},
	}
	for _, tc := range tests {
		got := debugfs(t, image, tc.request)
		switch {
		case tc.want == "" && !strings.Contains(got, "File not found"):
			t.Errorf("%s: %q, want File not found", tc.request, got)
		case tc.want != "" && !strings.Contains(got, tc.want):
			t.Errorf("%s: %q, want it to hold %q", tc.request, got, tc.want)
		}
	}
	// The two names of the hard link share one inode.
	if a, b := inodeOf(t, image, "/hard1"), inodeOf(t, image, "/hard2"); a == "" || a != b {
		t.Errorf("inodes of the hard link: %q and %q, want one", a, b)
	}
	if _, err := Export(context.Background(), dir, image, 0); err == nil {
		t.Error("an export over an existing image succeeded")
	}
}

func inodeOf(t *testing.T, image, path string) string {
	t.Helper()
	f := strings.Fields(debugfs(t, image, "stat "+path))
	for i, w := range f {
		if w == "Inode:" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// TestExportStopped checks that a cancelled export fails and leaves no image.
func TestExportStopped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	image := filepath.Join(t.TempDir(), "workspace.ext4")
	if _, err := Export(ctx, dir, image, 0); err == nil {
		t.Error("a cancelled export succeeded")
	}
	if _, err := os.Stat(image); !os.IsNotExist(err) {
		t.Errorf("the image after a failed export: %v, want gone", err)
	}
}
