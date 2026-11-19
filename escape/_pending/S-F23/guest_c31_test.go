// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C31 of S-1013. Fix unit S-F23 first moves this file to internal/guest/c31_test.go, package guest,
// build tag `linux || darwin` as walk.go, as this comment says.

//go:build linux || darwin

package guest

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestC31WalkErrorQuotesName (I12, hardening as C20): Walk's error names an unopenable guest-named directory only quoted.
func TestC31WalkErrorQuotesName(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil || unix.Mkdirat(fd, "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME", 0) != nil {
		t.Fatal("cannot set up the mode-0 directory", err)
	}
	if err = Walk(fd, func(Entry) error { return nil }); err == nil {
		t.Skip("the mode-0 directory opened: this process overrides directory permissions")
	}
	if got := err.Error(); strings.ContainsFunc(got, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		t.Errorf("the error carries a raw control byte the terminal would obey: %q", got)
	}
}
