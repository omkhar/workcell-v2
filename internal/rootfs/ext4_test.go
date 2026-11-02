// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// fullTree holds every entry kind, a file over 48 KiB, a directory over one block and
// ids over 65535.
func fullTree(t *testing.T) *Tree {
	t.Helper()
	tr := NewTree()
	long := strings.Repeat("../lib/", 12) + "target"
	puts := []struct {
		path string
		n    Node
	}{
		{"/bin", Node{Kind: Dir, Mode: 0o755}},
		{"/bin/sh", Node{Kind: File, Mode: 0o755, Data: []byte("#!/bin/true\n")}},
		{"/bin/busybox", Node{Kind: File, Mode: 0o755, Data: pattern(100 << 10)}},
		{"/bin/ash", Node{Kind: Symlink, Mode: 0o777, Target: "busybox"}},
		{"/etc", Node{Kind: Dir, Mode: 0o750, UID: 1, GID: 2}},
		{"/etc/empty", Node{Kind: File, Mode: 0o644}},
		{"/etc/odd", Node{Kind: File, Mode: 0o644, Data: pattern(5000)}},
		{"/etc/shadow", Node{Kind: File, Mode: 0o640, UID: 70000, GID: 80000, Data: []byte("root:*\n")}},
		{"/etc/long", Node{Kind: Symlink, Mode: 0o777, Target: long}},
		{"/usr", Node{Kind: Dir, Mode: 0o755}},
		{"/usr/bin", Node{Kind: Dir, Mode: 0o755}},
		{"/usr/bin/su", Node{Kind: File, Mode: 0o4755, Data: pattern(64)}},
		{"/usr/lib", Node{Kind: Dir, Mode: 0o1777}},
		{"/usr/lib/empty", Node{Kind: Dir, Mode: 0o755}},
		{"/many", Node{Kind: Dir, Mode: 0o755}},
		{"/dev", Node{Kind: Dir, Mode: 0o755}},
		{"/dev/null", Node{Kind: CharDev, Mode: 0o666, Major: 1, Minor: 3}},
		{"/dev/sda", Node{Kind: BlockDev, Mode: 0o660, Major: 8, Minor: 0}},
		{"/dev/big", Node{Kind: BlockDev, Mode: 0o660, Major: 259, Minor: 300}},
		{"/dev/fifo", Node{Kind: FIFO, Mode: 0o600}},
	}
	for _, p := range puts {
		if err := tr.Put(p.path, p.n); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 400 {
		if err := tr.Put(fmt.Sprintf("/many/file-%04d", i), Node{Kind: File, Mode: 0o644, Data: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Link("/bin/busybox", "/bin/ls"); err != nil {
		t.Fatal(err)
	}
	return tr
}

func image(t *testing.T, tr *Tree) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := tr.WriteExt4(&b, time.Time{}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDeterministic(t *testing.T) {
	a := image(t, fullTree(t))
	if b := image(t, fullTree(t)); !bytes.Equal(a, b) {
		t.Fatalf("same tree, different bytes: %x vs %x", sha256.Sum256(a), sha256.Sum256(b))
	}
	// Insertion order must not matter: remove and re-add entries in a different order.
	tr := fullTree(t)
	for _, p := range []string{"/many/file-0007", "/dev/null", "/bin"} {
		n := *tr.Lookup(p)
		if err := tr.Remove(p); err != nil {
			t.Fatal(err)
		}
		if n.Kind == Dir {
			continue
		}
		if err := tr.Put(p, n); err != nil {
			t.Fatal(err)
		}
	}
	if c := image(t, tr); bytes.Equal(a, c) {
		t.Fatal("removing /bin left the image unchanged")
	}
	tr = fullTree(t)
	_ = tr.Remove("/many/file-0007")
	_ = tr.Put("/many/file-0007", Node{Kind: File, Mode: 0o644, Data: []byte{7}})
	if c := image(t, tr); !bytes.Equal(a, c) {
		t.Fatalf("re-adding an entry changed the image: %x vs %x", sha256.Sum256(a), sha256.Sum256(c))
	}
	if len(a)%blockSize != 0 {
		t.Fatalf("image of %d bytes is not whole blocks", len(a))
	}
}

func TestMtime(t *testing.T) {
	var b bytes.Buffer
	if err := fullTree(t).WriteExt4(&b, time.Unix(-1, 0)); err != ErrMtime {
		t.Fatalf("negative mtime: %v", err)
	}
	if bytes.Equal(image(t, fullTree(t)), func() []byte {
		var o bytes.Buffer
		_ = fullTree(t).WriteExt4(&o, time.Unix(1_000_000_000, 0))
		return o.Bytes()
	}()) {
		t.Fatal("mtime did not reach the image")
	}
}

func e2fsck(t *testing.T, path string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "e2fsck", "-fn", path).CombinedOutput()
	if err != nil {
		t.Fatalf("e2fsck -fn: %v\n%s", err, out)
	}
	t.Logf("e2fsck: %s", lastLine(out))
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

func writeImage(t *testing.T, tr *Tree) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tr.WriteExt4(f, time.Time{}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestE2fsck(t *testing.T) {
	if _, err := exec.LookPath("e2fsck"); err != nil {
		t.Skipf("e2fsck not on PATH: %v", err)
	}
	path := writeImage(t, fullTree(t))
	e2fsck(t, path)

	if _, err := exec.LookPath("debugfs"); err != nil {
		t.Skipf("debugfs not on PATH: %v", err)
	}
	debugfs := func(cmd string) string {
		out, err := exec.Command("debugfs", "-R", cmd, path).CombinedOutput()
		if err != nil {
			t.Fatalf("debugfs %q: %v\n%s", cmd, err, out)
		}
		return strings.Join(strings.Fields(string(out)), " ")
	}
	tests := []struct {
		path string
		want []string
	}{
		{"/bin/busybox", []string{"Type: regular", "Mode: 0755", "Size: 102400", "Links: 2"}},
		{"/bin/ls", []string{"Type: regular", "Size: 102400", "Links: 2"}},
		{"/etc/shadow", []string{"Mode: 0640", "User: 70000 Group: 80000", "Size: 7"}},
		{"/etc/odd", []string{"Size: 5000", "EXTENTS: (0-1):"}},
		{"/usr/bin/su", []string{"Mode: 04755"}},
		{"/usr/lib", []string{"Type: directory", "Mode: 01777", "Links: 3"}},
		{"/bin/ash", []string{"Type: symlink", `Fast link dest: "busybox"`}},
		{"/etc/long", []string{"Type: symlink", "Size: 90", "EXTENTS:"}},
		{"/dev/null", []string{"Type: character special", "Device major/minor number: 01:03"}},
		{"/dev/big", []string{"Type: block special", "Device major/minor number: 259:300"}},
		{"/dev/fifo", []string{"Type: FIFO"}},
		{"/many", []string{"Size: 8192", "Links: 2"}},
	}
	for _, tc := range tests {
		got := debugfs("stat " + tc.path)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("stat %s: missing %q in %s", tc.path, w, got)
			}
		}
	}
	dump := filepath.Join(t.TempDir(), "busybox")
	debugfs("dump /bin/busybox " + dump)
	if got, err := os.ReadFile(dump); err != nil || !bytes.Equal(got, pattern(100<<10)) {
		t.Errorf("dumped busybox differs from the source (read error %v)", err)
	}
}

// TestMultiGroup writes a tree over 128 MiB, so over one group, and checks the file
// size against the block count in the superblock.
func TestMultiGroup(t *testing.T) {
	big := pattern(64 << 20)
	tr := NewTree()
	for _, n := range []string{"a", "b", "c"} {
		if err := tr.Put("/"+n, Node{Kind: File, Mode: 0o644, Data: big}); err != nil {
			t.Fatal(err)
		}
	}
	path := writeImage(t, tr)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sb := make([]byte, 8)
	if _, err := f.ReadAt(sb, 1024); err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	if blocks := le.Uint32(sb[4:]); int64(blocks)*blockSize != st.Size() || blocks <= blocksPerGroup {
		t.Fatalf("superblock says %d blocks, file has %d bytes", blocks, st.Size())
	}
	if _, err := exec.LookPath("e2fsck"); err != nil {
		t.Skipf("e2fsck not on PATH: %v", err)
	}
	e2fsck(t, path)
}
