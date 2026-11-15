// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Regression test for C21 of S-1009 (I13): a relative XDG_CONFIG_HOME, XDG_DATA_HOME or HOME is ignored, as the XDG base directory spec says.

package main

import "os"
import "path/filepath"
import "testing"

func TestC21RelativeXDGDirs(t *testing.T) { // I13
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "~/.config/workcell"), 0o755)
	os.WriteFile(filepath.Join(repo, "~/.config/workcell/config.toml"), []byte("[network]\nallow = [\"evil.test\"]\n"), 0o644)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "~/.config")
	t.Setenv("XDG_DATA_HOME", "data")
	t.Chdir(repo)
	if allow, _, _, file, err := loadPolicy(nil, os.Stderr); err != nil || allow != nil || !filepath.IsAbs(file) {
		t.Errorf("loadPolicy: file=%q err=%v allow=%v", file, err, allow)
	}
	if d, err := dataDir(); err != nil || !filepath.IsAbs(d) {
		t.Errorf("dataDir: %q err=%v", d, err)
	}
}
