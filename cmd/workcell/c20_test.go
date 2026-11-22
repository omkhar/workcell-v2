// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C20 of S-1008 (I8, I12). Fix unit S-F13 first moves this file to cmd/workcell/c20_test.go, as this comment says.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
	"golang.org/x/sys/unix"
)

// c20Path is a valid, NUL-free UTF-8 name the manifest accepts that holds terminal control bytes.
const c20Path = "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME"

// c20NoFileGrowth makes every write that would grow a regular file fail with EFBIG for the rest of the test, by lowering the soft RLIMIT_FSIZE to zero.
func c20NoFileGrowth(t *testing.T) {
	t.Helper()
	var was unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &was); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 0, Max: was.Max}); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &was); err != nil {
			t.Errorf("restore RLIMIT_FSIZE: %v", err)
		}
	})
}

// c20Control is the index of the first byte of s a terminal would obey (below 0x20 or 0x7f), or -1.
func c20Control(s string) int {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// TestC20PullWriteErrorQuotesGuestPath (I8, I12): when the write of a guest-named file fails after it is
// open, the one line pull prints carries the guest path only quoted, as shown renders every refusal.
func TestC20PullWriteErrorQuotesGuestPath(t *testing.T) {
	dest := t.TempDir()
	m := judged(t, []guest.Entry{fileEntry(c20Path, 4, false)})
	c20NoFileGrowth(t)
	err := write(openDir(t, dest), m, from([]byte("pwnd")))
	if err == nil {
		t.Fatal("write succeeded; the destination write was meant to fail")
	}
	got := err.Error()
	if !strings.Contains(got, shown(c20Path)) {
		t.Errorf("the error does not name the path quoted: %q", got)
	}
	if i := c20Control(got); i >= 0 {
		t.Errorf("the error carries a raw control byte 0x%02x at %d, which the terminal would obey: %q", got[i], i, got)
	}
	if beside, _ := os.ReadDir(dest); len(beside) != 1 || beside[0].Name() != filepath.Base(c20Path) {
		t.Errorf("dest holds %d entries after the failed write", len(beside))
	}
}
