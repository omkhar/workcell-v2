// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C38 of S-1016c (the quoting rule of C20 and C31), moved here from escape/_pending/S-F29/ by unit S-F29.
// Export names a repository file in an error only quoted, so control and bidi runes in a path never reach a terminal raw.

package workspace

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/omkhar/workcell/v2/internal/rootfs"
)

// TestC38ExportErrorQuotesFilePath (I12 in spirit, hardening as C20 and C31): the image writer names a repository
// file only quoted, both one that a checkout put past PATH_MAX and one that is no longer the file the walk saw.
func TestC38ExportErrorQuotesFilePath(t *testing.T) {
	const name = "\x1b]0;owned\x07\u009b2J‮README"
	dir := t.TempDir()
	t.Chdir(dir)
	for _, seg := range append([]string{name}, slices.Repeat([]string{strings.Repeat("d", 255)}, 17)...) {
		if err := errors.Join(os.Mkdir(seg, 0o755), os.Chdir(seg)); err != nil {
			t.Fatal(err)
		}
	}
	tree, img := rootfs.NewTree(), filepath.Join(t.TempDir(), "ws.ext4")
	f, err := os.Create(img + ".2")
	src := &rootfs.HostFile{Path: filepath.Join(dir, name), Size: 1} // a directory now, where the walk saw a file
	if err = errors.Join(err, os.WriteFile("f", []byte("x"), 0o644), tree.Put("f", rootfs.Node{Kind: rootfs.File, Mode: 0o644, Source: src})); err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, long := Export(context.Background(), dir, img, 0)
	for _, err := range []error{long, tree.WriteExt4File(f, time.Time{}, 0)} {
		if err == nil {
			t.Fatal("the export took a file it cannot open by its path, or one that is not the file the walk saw")
		}
		if got := err.Error(); strings.ContainsFunc(got, func(r rune) bool { return r == utf8.RuneError || !strconv.IsPrint(r) }) {
			t.Errorf("the error carries a rune the terminal would obey: %.150q", got)
		}
	}
}
