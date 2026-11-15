// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

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

// c20Path is a guest-chosen file name that is a valid, NUL-free UTF-8 path, so the
// manifest accepts it, but holds terminal control bytes: set the title, clear the screen,
// turn the text red.
const c20Path = "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME"

// c20NoFileGrowth makes every write that would grow a regular file fail with EFBIG for the
// rest of the test, by lowering the soft RLIMIT_FSIZE to zero. It needs no privilege and
// is restored when the test ends. The Go runtime ignores SIGXFSZ, so the write just fails.
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

// c20Control is the first byte of s that a terminal would obey rather than show: anything
// below 0x20 or 0x7f. It is -1 when there is none.
func c20Control(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return i
		}
	}
	return -1
}

// TestC20PullWriteErrorQuotesGuestPath (I8, I12): when the write of a file the guest named
// fails after the file is open, the one line `workcell pull` prints must carry the guest's
// path only quoted, as every other refusal does through shown. The raw path in the write's
// PathError would otherwise reach the operator's terminal and be obeyed as control bytes.
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
		t.Errorf("the error does not name the path quoted:\n%q", got)
	}
	if i := c20Control(got); i >= 0 {
		t.Errorf("the error carries a raw control byte 0x%02x at %d, which the terminal would obey:\n%q", got[i], i, got)
	}
	// The failed file is the only thing the pull may leave behind, and nothing beside it.
	if beside, _ := os.ReadDir(dest); len(beside) != 1 || beside[0].Name() != filepath.Base(c20Path) {
		t.Errorf("dest holds %d entries after the failed write", len(beside))
	}
}
