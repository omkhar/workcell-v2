// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
	"golang.org/x/sys/unix"
)

func dirEntry(p string) guest.Entry { return guest.Entry{Kind: guest.KindDir, Path: p} }
func fileEntry(p string, size int64, exec bool) guest.Entry {
	return guest.Entry{Kind: guest.KindFile, Path: p, Size: size, Exec: exec}
}
func linkEntry(p, target string) guest.Entry {
	return guest.Entry{Kind: guest.KindLink, Path: p, Target: target}
}

// from is a source of b, in chunks of at most 4 bytes so that a file spans several.
func from(b []byte) source {
	return func(n int) ([]byte, error) {
		if len(b) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		n = min(n, len(b), 4)
		out := b[:n]
		b = b[n:]
		return out, nil
	}
}

func judged(t *testing.T, entries []guest.Entry) *manifest {
	t.Helper()
	m := &manifest{limit: bounds{entries: 100, names: 1000, bytes: 1000}}
	for _, e := range entries {
		if err := m.add(e); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func openDir(t *testing.T, p string) int {
	t.Helper()
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()
}

func content(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestWrite runs the writer against prepared directories. dest lies in a parent that must
// stay untouched: the symlink cases bring updir -> .. there, as the I8 suite does.
func TestWrite(t *testing.T) {
	link := func(t *testing.T, dest string) { // what a first pull of the link shape leaves behind
		if err := os.Symlink("..", filepath.Join(dest, "updir")); err != nil {
			t.Fatal(err)
		}
	}
	full := func(t *testing.T, dest string) {
		if err := os.MkdirAll(filepath.Join(dest, "d"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dest, "d", "keep"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		entries []guest.Entry
		data    string
		wantErr string
		check   func(t *testing.T, parent, dest string)
	}{
		{"a tree lands", nil, []guest.Entry{dirEntry("a"), fileEntry("a/b", 6, false), fileEntry("run", 2, true), linkEntry("l", "/../x"), fileEntry("empty", 0, false)}, "abcdefok", "",
			func(t *testing.T, parent, dest string) {
				if got := content(t, filepath.Join(dest, "a", "b")); got != "abcdef" {
					t.Errorf("a/b holds %q", got)
				}
				if got := content(t, filepath.Join(dest, "run")); got != "ok" {
					t.Errorf("run holds %q", got)
				}
				if m := mode(t, filepath.Join(dest, "run")); m.Perm() != 0o755 {
					t.Errorf("run has mode %v, want 0755", m)
				}
				if m := mode(t, filepath.Join(dest, "a", "b")); m.Perm() != 0o644 {
					t.Errorf("a/b has mode %v, want 0644", m)
				}
				if target, err := os.Readlink(filepath.Join(dest, "l")); err != nil || target != "/../x" {
					t.Errorf("l -> %q, %v", target, err)
				}
				if m := mode(t, filepath.Join(dest, "empty")); !m.IsRegular() {
					t.Errorf("empty is %v", m)
				}
			}},
		{"the symlink of an earlier pull becomes a directory", link, []guest.Entry{dirEntry("updir"), fileEntry("updir/written", 6, false)}, "escape", "",
			func(t *testing.T, parent, dest string) {
				if m := mode(t, filepath.Join(dest, "updir")); !m.IsDir() {
					t.Errorf("updir is %v, want a directory", m)
				}
				if got := content(t, filepath.Join(dest, "updir", "written")); got != "escape" {
					t.Errorf("updir/written holds %q", got)
				}
			}},
		{"nothing is written through the symlink without its entry", link, []guest.Entry{fileEntry("updir/written", 6, false)}, "escape", "open its directory",
			func(t *testing.T, parent, dest string) {
				if m := mode(t, filepath.Join(dest, "updir")); m&os.ModeSymlink == 0 {
					t.Errorf("updir is %v, want the symlink", m)
				}
			}},
		{"an existing file is replaced", func(t *testing.T, dest string) {
			if err := os.WriteFile(filepath.Join(dest, "f"), []byte("old and longer"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, []guest.Entry{fileEntry("f", 3, false)}, "new", "",
			func(t *testing.T, parent, dest string) {
				if got, m := content(t, filepath.Join(dest, "f")), mode(t, filepath.Join(dest, "f")); got != "new" || m.Perm() != 0o644 {
					t.Errorf("f holds %q with mode %v", got, m)
				}
			}},
		{"an existing directory is kept", full, []guest.Entry{dirEntry("d"), fileEntry("d/new", 1, false)}, "n", "",
			func(t *testing.T, parent, dest string) {
				if got := content(t, filepath.Join(dest, "d", "keep")); got != "keep" {
					t.Errorf("d/keep holds %q", got)
				}
			}},
		{"a directory that is not empty is not replaced", full, []guest.Entry{fileEntry("d", 1, false)}, "n", "remove what is there",
			func(t *testing.T, parent, dest string) {
				if got := content(t, filepath.Join(dest, "d", "keep")); got != "keep" {
					t.Errorf("d/keep holds %q", got)
				}
			}},
		{"an empty directory is replaced by a file", func(t *testing.T, dest string) {
			if err := os.Mkdir(filepath.Join(dest, "d"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, []guest.Entry{fileEntry("d", 1, false)}, "n", "",
			func(t *testing.T, parent, dest string) {
				if m := mode(t, filepath.Join(dest, "d")); !m.IsRegular() {
					t.Errorf("d is %v, want a file", m)
				}
			}},
		{"a stream shorter than the manifest", nil, []guest.Entry{fileEntry("f", 5, false)}, "abc", "unexpected EOF", nil},
		{"a directory entry whose parent is missing", nil, []guest.Entry{fileEntry("a/b", 1, false)}, "x", "open its directory", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			if err := os.Mkdir(dest, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.prepare != nil {
				tc.prepare(t, dest)
			}
			err := write(openDir(t, dest), judged(t, tc.entries), from([]byte(tc.data)))
			if (err == nil) != (tc.wantErr == "") || err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("write: %v, want %q", err, tc.wantErr)
			}
			if tc.check != nil {
				tc.check(t, parent, dest)
			}
			beside, _ := os.ReadDir(parent)
			if len(beside) != 1 {
				t.Errorf("%d entries beside dest, want dest alone", len(beside))
			}
		})
	}
}

func TestCompare(t *testing.T) {
	// The host has: a dir d with d/same and d/gone, a file changed, an executable script,
	// a link l -> old, a .git with a hook, and a FIFO.
	tests := []struct {
		name    string
		entries []guest.Entry
		data    string
		want    string
	}{
		{"the same tree", []guest.Entry{dirEntry("d"), fileEntry("d/gone", 4, false), fileEntry("d/same", 4, false), fileEntry("changed", 3, false), fileEntry("script", 2, true), linkEntry("l", "old")},
			"gonesameoldok", ""},
		{"every kind of change", []guest.Entry{dirEntry("d"), fileEntry("d/same", 4, false), fileEntry("changed", 3, false), fileEntry("script", 2, false), linkEntry("l", "new"), fileEntry("added", 1, false), dirEntry("new"), fileEntry("new/f", 0, false)},
			"samenewoka", "M changed\nM script\nM l\nA added\nA new\nA new/f\nD d/gone\n"},
		{"a kind changes", []guest.Entry{dirEntry("changed"), fileEntry("d", 1, false)},
			"x", "M changed\nM d\nD d/gone\nD d/same\nD l\nD script\n"},
		{"a length changes", []guest.Entry{dirEntry("d"), fileEntry("d/gone", 4, false), fileEntry("d/same", 5, false), fileEntry("changed", 3, false), fileEntry("script", 2, true), linkEntry("l", "old")},
			"gonesame1oldok", "M d/same\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host := t.TempDir()
			for p, b := range map[string]string{"d/same": "same", "d/gone": "gone", "changed": "old", ".git/hooks/pre-commit": "#!/bin/sh\n"} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(host, p)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(host, p), []byte(b), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(host, "script"), []byte("ok"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("old", filepath.Join(host, "l")); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(filepath.Join(host, "fifo"), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			differs, err := compare(openDir(t, host), judged(t, tc.entries), from([]byte(tc.data)), &out)
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want || differs != (tc.want != "") {
				t.Errorf("compare printed %q, differs=%t; want %q", out.String(), differs, tc.want)
			}
		})
	}
}
