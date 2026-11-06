// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// hostFile writes size bytes (a pattern, or a sparse file with marks at both ends when
// big) under dir and describes the file as a Source.
func hostFile(t *testing.T, dir, name string, size int64) (*HostFile, []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	var data []byte
	if size <= 1<<20 {
		data = pattern(int(size))
	} else {
		data = make([]byte, size)
		copy(data, "head")
		copy(data[size-4:], "tail")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if size <= 1<<20 {
		_, err = f.Write(data)
	} else if err = f.Truncate(size); err == nil {
		if _, err = f.WriteAt(data[:4], 0); err == nil {
			_, err = f.WriteAt(data[size-4:], size-4)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return &HostFile{Path: path, Size: size, Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, data
}

func imageFile(t *testing.T, tr *Tree, free int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workspace.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tr.WriteExt4File(f, time.Time{}, free); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestWriteExt4File checks that data taken from host files gives the image that the same
// data held in memory gives, byte for byte, however the files fall across blocks and groups.
func TestWriteExt4File(t *testing.T) {
	tests := []struct {
		name  string
		sizes []int64
	}{
		{"one block", []int64{4096}},
		{"unaligned", []int64{1, 5000, 100<<10 + 7}},
		{"several", []int64{4096, 4097, 8191, 8192, 1 << 20}},
		{"spans two groups", []int64{3, 130 << 20, 99}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mem, host := NewTree(), NewTree()
			for i, size := range tc.sizes {
				h, data := hostFile(t, dir, string(rune('a'+i)), size)
				name := "/" + string(rune('a'+i))
				if err := mem.Put(name, Node{Kind: File, Mode: 0o644, Data: data}); err != nil {
					t.Fatal(err)
				}
				if err := host.Put(name, Node{Kind: File, Mode: 0o644, Source: h}); err != nil {
					t.Fatal(err)
				}
			}
			want := image(t, mem)
			path := imageFile(t, host, 0)
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("the image from host files differs from the image from memory (%d and %d bytes)", len(got), len(want))
			}
		})
	}
}

// TestSourceChecks checks that a host file is refused when it is not the one the caller saw.
func TestSourceChecks(t *testing.T) {
	dir := t.TempDir()
	good, _ := hostFile(t, dir, "good", 5000)
	other, _ := hostFile(t, dir, "other", 5000)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good.Path, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		h    HostFile
		ok   bool
	}{
		{"as seen", *good, true},
		{"another inode", HostFile{good.Path, good.Size, good.Dev, other.Ino}, false},
		{"another size", HostFile{good.Path, good.Size + 1, good.Dev, good.Ino}, false},
		{"a symlink to it", HostFile{link, good.Size, good.Dev, good.Ino}, false},
		{"missing", HostFile{filepath.Join(dir, "missing"), 1, good.Dev, good.Ino}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTree()
			if err := tr.Put("/f", Node{Kind: File, Mode: 0o644, Source: &tc.h}); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(filepath.Join(t.TempDir(), "i"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := tr.WriteExt4File(f, time.Time{}, 0); (err == nil) != tc.ok {
				t.Errorf("WriteExt4File: %v, want success %v", err, tc.ok)
			}
		})
	}
	if err := NewTree().Put("/f", Node{Kind: File, Data: []byte{1}, Source: good}); err == nil {
		t.Error("a node with Data and a Source was accepted")
	}
}

// TestFreeSpace checks that an image with free space is consistent, sparse, and has room the
// guest can fill: debugfs writes a file into it.
func TestFreeSpace(t *testing.T) {
	for _, tool := range []string{"e2fsck", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH: %v", tool, err)
		}
	}
	tests := []struct {
		name string
		free int64
		size int64 // of the one file
	}{
		{"none", 0, 10000},
		{"one group", 64 << 20, 10000},
		{"unaligned", 100<<20 + 1, 5000},
		{"several groups", 1 << 30, 130 << 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := hostFile(t, t.TempDir(), "f", tc.size)
			tr := NewTree()
			if err := tr.Put("/f", Node{Kind: File, Mode: 0o644, Source: h}); err != nil {
				t.Fatal(err)
			}
			path := imageFile(t, tr, tc.free)
			e2fsck(t, path)
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if min := tc.free + tc.size; fi.Size() < min {
				t.Errorf("image of %d bytes, want at least %d", fi.Size(), min)
			}
			if used := fi.Sys().(*syscall.Stat_t).Blocks * 512; tc.size < 1<<20 && used > 4<<20 {
				t.Errorf("image uses %d bytes of disk, want a sparse file", used)
			}
			if tc.free == 0 {
				return
			}
			fill := filepath.Join(t.TempDir(), "fill")
			if err := os.WriteFile(fill, pattern(8<<20), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, cmd := range []string{"write " + fill + " fill", "mkdir d", "write " + fill + " d/fill"} {
				if out, err := exec.Command("debugfs", "-w", "-R", cmd, path).CombinedOutput(); err != nil {
					t.Fatalf("debugfs %q: %v\n%s", cmd, err, out)
				}
			}
			e2fsck(t, path)
		})
	}
}
