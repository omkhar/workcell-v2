// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
)

func TestManifestAdd(t *testing.T) {
	dir := func(p string) guest.Entry { return guest.Entry{Kind: guest.KindDir, Path: p} }
	file := func(p string, size int64) guest.Entry { return guest.Entry{Kind: guest.KindFile, Path: p, Size: size} }
	link := func(p, target string) guest.Entry { return guest.Entry{Kind: guest.KindLink, Path: p, Target: target} }
	small := bounds{entries: 3, names: 20, bytes: 100}
	tests := []struct {
		name  string
		limit bounds
		in    []guest.Entry
		want  string // what the error of the last entry says; "" for none
	}{
		{"a tree", small, []guest.Entry{dir("a"), file("a/b", 50), link("l", "../x")}, ""},
		{"a dotfile is fine", small, []guest.Entry{file(".gitignore", 1)}, ""},
		{"case differs across components", small, []guest.Entry{file("A/b", 1), file("a/B", 1)}, "case folding"},
		{"absolute", small, []guest.Entry{file("/etc/passwd", 1)}, "absolute"},
		{"empty", small, []guest.Entry{file("", 1)}, "empty"},
		{"dotdot", small, []guest.Entry{file("../written", 1)}, `".." component`},
		{"dot", small, []guest.Entry{file("a/./b", 1)}, `"." component`},
		{"empty component", small, []guest.Entry{file("a//b", 1)}, "empty component"},
		{"trailing slash", small, []guest.Entry{dir("a/")}, "empty component"},
		{"NUL", small, []guest.Entry{file("a\x00b", 1)}, "NUL"},
		{"not UTF-8", small, []guest.Entry{file("a\xffb", 1)}, "UTF-8"},
		{".git", small, []guest.Entry{dir(".git")}, ".git component"},
		{".git under case folding", small, []guest.Entry{file("a/.GIT/hooks/pre-commit", 1)}, ".git component"},
		{"case collision", small, []guest.Entry{file("Readme", 1), file("readme", 1)}, "case folding"},
		{"case collision by Kelvin sign", small, []guest.Entry{file("k", 1), file("K", 1)}, "case folding"},
		{"the same path twice", small, []guest.Entry{dir("a"), file("a", 1)}, "case folding"},
		{"link without a target", small, []guest.Entry{link("l", "")}, "target"},
		{"link target with NUL", small, []guest.Entry{link("l", "a\x00")}, "target"},
		{"link target may be absolute or dotdot", small, []guest.Entry{link("l", "/../x")}, ""},
		{"too many entries", small, []guest.Entry{dir("a"), dir("b"), dir("c"), dir("d")}, "more than 3 entries"},
		{"too many bytes of names", small, []guest.Entry{link("l", strings.Repeat("t", 20))}, "more than 20 bytes of names"},
		{"path over MaxPath", bounds{10, guest.MaxPath * 2, 1}, []guest.Entry{dir(strings.Repeat("p", guest.MaxPath+1))}, "longer than"},
		{"more bytes than the image", small, []guest.Entry{file("a", 60), file("b", 41)}, "image cannot hold"},
		{"exactly the image", small, []guest.Entry{file("a", 60), file("b", 40)}, ""},
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
}

func TestFold(t *testing.T) {
	tests := []struct {
		a, b string
		same bool
	}{
		{"Readme", "readme", true},
		{"k", "K", true}, // the Kelvin sign folds to k
		{"σ", "ς", true}, // final sigma
		{"a/b", "A/B", true},
		{"straße", "strasse", false}, // ß has no simple fold
		{"a", "b", false},
		{"", "", true},
	}
	for _, tc := range tests {
		if got := fold(tc.a) == fold(tc.b); got != tc.same || got != strings.EqualFold(tc.a, tc.b) {
			t.Errorf("fold(%q) == fold(%q) is %t, want %t and the same as EqualFold", tc.a, tc.b, got, tc.same)
		}
	}
}

func TestShown(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a/b.txt", "a/b.txt"},
		{"with space", "with space"},
		{"café", "café"},
		{"new\nline", `"new\nline"`},
		{"esc\x1b[0m", `"esc\x1b[0m"`},
		{`quo"te`, `"quo\"te"`},
	}
	for _, tc := range tests {
		if got := shown(tc.in); got != tc.want {
			t.Errorf("shown(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
