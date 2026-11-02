// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"errors"
	"strings"
	"testing"
)

func TestTreeOps(t *testing.T) {
	file := Node{Kind: File, Mode: 0o644, Data: []byte("x")}
	dir := Node{Kind: Dir, Mode: 0o755}
	long := strings.Repeat("n", 256)
	tests := []struct {
		name string
		do   func(tr *Tree) error
		want error
		then func(t *testing.T, tr *Tree)
	}{
		{"empty path", func(tr *Tree) error { return tr.Put("", file) }, ErrPath, nil},
		{"root path", func(tr *Tree) error { return tr.Put("/", dir) }, ErrPath, nil},
		{"empty component", func(tr *Tree) error { return tr.Put("a//b", file) }, ErrPath, nil},
		{"trailing slash", func(tr *Tree) error { return tr.Put("a/", file) }, ErrPath, nil},
		{"dot", func(tr *Tree) error { return tr.Put("/.", file) }, ErrPath, nil},
		{"dotdot", func(tr *Tree) error { return tr.Put("/a/..", file) }, ErrPath, nil},
		{"nul", func(tr *Tree) error { return tr.Put("/a\x00b", file) }, ErrPath, nil},
		{"long name", func(tr *Tree) error { return tr.Put("/"+long, file) }, ErrPath, nil},
		{"parent missing", func(tr *Tree) error { return tr.Put("/no/f", file) }, ErrNotFound, nil},
		{"parent is a file", func(tr *Tree) error {
			_ = tr.Put("/f", file)
			return tr.Put("/f/g", file)
		}, ErrNotDir, nil},
		{"bad kind", func(tr *Tree) error { return tr.Put("/f", Node{Kind: 9}) }, ErrBadNode, nil},
		{"bad mode", func(tr *Tree) error { return tr.Put("/f", Node{Kind: File, Mode: 0o10000}) }, ErrBadNode, nil},
		{"empty target", func(tr *Tree) error { return tr.Put("/l", Node{Kind: Symlink}) }, ErrBadNode, nil},
		{"big minor", func(tr *Tree) error { return tr.Put("/d", Node{Kind: CharDev, Minor: 1 << 20}) }, ErrBadNode, nil},
		{"link to missing", func(tr *Tree) error { return tr.Link("/no", "/l") }, ErrNotFound, nil},
		{"link to dir", func(tr *Tree) error {
			_ = tr.Put("/d", dir)
			return tr.Link("/d", "/l")
		}, ErrLinkDir, nil},
		{"remove missing", func(tr *Tree) error { return tr.Remove("/no") }, ErrNotFound, nil},
		{"remove root", func(tr *Tree) error { return tr.Remove("/") }, ErrPath, nil},
		{"clear a file", func(tr *Tree) error {
			_ = tr.Put("/f", file)
			return tr.Clear("/f")
		}, ErrNotDir, nil},
		{"remove dir removes children", func(tr *Tree) error {
			_ = tr.Put("/d", dir)
			_ = tr.Put("/d/f", file)
			return tr.Remove("/d")
		}, nil, func(t *testing.T, tr *Tree) {
			if tr.Lookup("/d") != nil || tr.Lookup("/d/f") != nil {
				t.Error("directory or child survived Remove")
			}
		}},
		{"file replaced by dir and back", func(tr *Tree) error {
			_ = tr.Put("/x", file)
			if err := tr.Put("/x", dir); err != nil {
				return err
			}
			if err := tr.Put("/x/y", file); err != nil {
				return err
			}
			return tr.Put("/x", file)
		}, nil, func(t *testing.T, tr *Tree) {
			if n := tr.Lookup("/x"); n == nil || n.Kind != File || tr.Lookup("/x/y") != nil {
				t.Errorf("replace left %+v", n)
			}
		}},
		{"opaque clear", func(tr *Tree) error {
			_ = tr.Put("/d", dir)
			_ = tr.Put("/d/f", file)
			_ = tr.Put("/d/s", dir)
			_ = tr.Put("/d/s/g", file)
			return tr.Clear("/d")
		}, nil, func(t *testing.T, tr *Tree) {
			if tr.Lookup("/d") == nil || tr.Lookup("/d/f") != nil || tr.Lookup("/d/s") != nil {
				t.Error("Clear did not empty the directory only")
			}
		}},
		{"hard links share a node", func(tr *Tree) error {
			_ = tr.Put("/a", file)
			if err := tr.Link("/a", "/b"); err != nil {
				return err
			}
			if err := tr.Remove("/a"); err != nil {
				return err
			}
			tr.Lookup("/b").Mode = 0o600
			return nil
		}, nil, func(t *testing.T, tr *Tree) {
			if n := tr.Lookup("b"); n == nil || n.Mode != 0o600 || tr.Lookup("/a") != nil {
				t.Errorf("link survivor %+v", n)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTree()
			if err := tc.do(tr); !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if tc.then != nil {
				tc.then(t, tr)
			}
		})
	}
}
