// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"math"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
)

func TestManifestAdd(t *testing.T) {
	dir := func(p string) guest.Entry { return guest.Entry{Kind: guest.KindDir, Path: p} }
	file := func(p string, size int64) guest.Entry { return guest.Entry{Kind: guest.KindFile, Path: p, Size: size} }
	link := func(p, target string) guest.Entry { return guest.Entry{Kind: guest.KindLink, Path: p, Target: target} }
	small := int64(100 + 3*block) // three entries and a hundred bytes of files
	tests := []struct {
		name  string
		limit int64
		in    []guest.Entry
		want  string // what the error of the last entry says; "" for none
	}{
		{"a tree", small, []guest.Entry{dir("a"), file("a/b", 50), link("l", "../x")}, ""}, {"a dotfile is fine", small, []guest.Entry{file(".gitignore", 1)}, ""},
		{"case differs across components", small, []guest.Entry{file("A/b", 1), file("a/B", 1)}, "case folding"},
		{"absolute", small, []guest.Entry{file("/etc/passwd", 1)}, "absolute"}, {"empty", small, []guest.Entry{file("", 1)}, "empty"},
		{"dotdot", small, []guest.Entry{file("../written", 1)}, `".." component`}, {"dot", small, []guest.Entry{file("a/./b", 1)}, `"." component`},
		{"empty component", small, []guest.Entry{file("a//b", 1)}, "empty component"}, {"trailing slash", small, []guest.Entry{dir("a/")}, "empty component"},
		{"NUL", small, []guest.Entry{file("a\x00b", 1)}, "NUL"}, {"not UTF-8", small, []guest.Entry{file("a\xffb", 1)}, "UTF-8"},
		{".git", small, []guest.Entry{dir(".git")}, ".git component"}, {".git under case folding", small, []guest.Entry{file("a/.GIT/hooks/pre-commit", 1)}, ".git component"},
		{"case collision", small, []guest.Entry{file("Readme", 1), file("readme", 1)}, "case folding"},
		{"case collision by Kelvin sign", small, []guest.Entry{file("k", 1), file("K", 1)}, "case folding"},
		{"the same path twice", small, []guest.Entry{dir("a"), file("a", 1)}, "case folding"}, {"link without a target", small, []guest.Entry{link("l", "")}, "target"},
		{"link target with NUL", small, []guest.Entry{link("l", "a\x00")}, "target"}, {"link target may be absolute or dotdot", small, []guest.Entry{link("l", "/../x")}, ""},
		{"too many bytes of names", small, []guest.Entry{link("l", strings.Repeat("t", guest.MaxNames))}, "bytes of names"},
		{"path over MaxPath", small, []guest.Entry{dir(strings.Repeat("p", guest.MaxPath+1))}, "longer than"},
		{"more bytes than the image", small, []guest.Entry{dir("a"), file("a/b", 60), file("c", 41)}, "image cannot hold"},
		{"more entries than the image", small, []guest.Entry{dir("a"), file("a/b", 0), link("l", "x"), dir("d")}, "image cannot hold"},
		{"a size that would wrap the sum", small, []guest.Entry{file("a", 1), file("b", math.MaxInt64)}, "image cannot hold"},
		{"exactly the image", small, []guest.Entry{dir("a"), file("a/b", 60), file("c", 40)}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &manifest{limit: tc.limit}
			var err error
			for i, e := range tc.in {
				if err = m.add(e); err != nil && i < len(tc.in)-1 {
					t.Fatalf("entry %d, %+v: %v", i, e, err)
				}
			}
			got := ""
			if err != nil {
				got = err.Error()
			}
			if (err == nil) != (tc.want == "") || !strings.Contains(got, tc.want) {
				t.Errorf("add(%+v) = %q, want %q", tc.in[len(tc.in)-1], got, tc.want)
			}
			if kept := len(m.entries); err == nil && kept != len(tc.in) || err != nil && kept != len(tc.in)-1 {
				t.Errorf("%d entries kept, want all but a refused one", kept)
			}
		})
	}
	full := &manifest{entries: make([]guest.Entry, guest.MaxEntries)}
	if err := full.add(dir("a")); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Errorf("entry %d: %v, want too many entries", guest.MaxEntries+1, err)
	}
}

func TestFold(t *testing.T) {
	tests := []struct {
		a, b string
		same bool
	}{
		{"Readme", "readme", true}, {"k", "K", true}, // the Kelvin sign folds to k
		{"σ", "ς", true},                                   // final sigma
		{"a/b", "A/B", true}, {"straße", "strasse", false}, // ß has no simple fold
		{"a", "b", false}, {"", "", true},
	}
	for _, tc := range tests {
		if got := fold(tc.a) == fold(tc.b); got != tc.same || got != strings.EqualFold(tc.a, tc.b) {
			t.Errorf("fold(%q) == fold(%q) is %t, want %t and the same as EqualFold", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestShown(t *testing.T) {
	tests := []struct{ in, want string }{{"a/b.txt", "a/b.txt"}, {"with space", "with space"}, {"café", "café"}, {"new\nline", `"new\nline"`}, {"esc\x1b[0m", `"esc\x1b[0m"`}, {`quo"te`, `"quo\"te"`}}
	for _, tc := range tests {
		if got := shown(tc.in); got != tc.want {
			t.Errorf("shown(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// FuzzPath (T5) feeds any bytes as a guest path to checkPath, fold, shown and a fresh manifest's add, and checks what they promise for every input: none panics; shown never carries a byte a terminal would obey; fold is idempotent and preserves EqualFold; add keeps only what checkPath admits, and never the same path twice.
func FuzzPath(f *testing.F) {
	for _, s := range []string{"README", "a/b.txt", "Ünïcode/ſ", "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME", ".git/x", "a//b", "\xff", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if i := strings.IndexFunc(shown(p), func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
			t.Errorf("shown(%q) carries control byte 0x%02x at %d", p, shown(p)[i], i)
		}
		if fp := fold(p); fold(fp) != fp || !strings.EqualFold(p, fp) {
			t.Errorf("fold(%q) = %q: fold(fold) = %q", p, fp, fold(fp))
		}
		m := &manifest{limit: 2 * block}
		err := m.add(guest.Entry{Kind: guest.KindFile, Path: p})
		if (err == nil) != (checkPath(p) == nil) || (err == nil) != (len(m.entries) == 1) {
			t.Errorf("add(%q) = %v, checkPath = %v, kept %d", p, err, checkPath(p), len(m.entries))
		}
		if err == nil && m.add(guest.Entry{Kind: guest.KindFile, Path: p}) == nil {
			t.Errorf("add(%q) accepted the same path twice", p)
		}
	})
}
