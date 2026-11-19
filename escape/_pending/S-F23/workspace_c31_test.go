// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C31 of S-1013. Fix unit S-F23 first moves this file to internal/workspace/c31_test.go, package workspace,
// no build tag, as workspace.go, as this comment says.

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC31ExportErrorQuotesPath (I12, hardening as C20): Export's error names an unopenable repository directory only quoted.
func TestC31ExportErrorQuotesPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME"), 0); err != nil {
		t.Fatal(err)
	}
	_, err := Export(context.Background(), dir, filepath.Join(t.TempDir(), "ws.ext4"), 0)
	if err == nil {
		t.Skip("the mode-0 directory opened: this process overrides directory permissions")
	}
	if got := err.Error(); strings.ContainsFunc(got, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		t.Errorf("the error carries a raw control byte the terminal would obey: %q", got)
	}
}
