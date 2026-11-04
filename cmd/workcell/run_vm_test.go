// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLastLines(t *testing.T) {
	tests := []struct {
		name, in string
		n        int
		want     string
	}{
		{"empty", "", 3, ""},
		{"fewer lines than asked", "a\nb\n", 3, "a\nb"},
		{"the last two", "a\nb\nc\nd\n", 2, "c\nd"},
		{"no final newline", "a\nb", 1, "b"},
		{"carriage returns go", "a\r\nb\r\n", 2, "a\nb"},
		{"escape sequences are defused", "\x1b]0;x\x07ok\x00", 1, "?]0;x?ok?"},
		{"non-ASCII is defused", "caf\xc3\xa9", 1, "caf?"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastLines([]byte(tc.in), tc.n); got != tc.want {
				t.Errorf("lastLines(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestTailIsBounded(t *testing.T) {
	var c tail
	for range 100 {
		_, _ = c.Write([]byte(strings.Repeat("x", 1000)))
	}
	_, _ = c.Write([]byte("end"))
	if b := c.bytes(); len(b) != 4096 || !strings.HasSuffix(string(b), "xend") {
		t.Errorf("tail holds %d bytes ending %q, want 4096 ending xend", len(b), b[len(b)-4:])
	}
}

// TestOnceTakesOneConnection is the regression test for the channel connect flood (I12): once the
// init's connection is in, a later connection to the port is refused rather than queued on the
// host with whatever the guest writes on it, and the first one goes on working.
func TestOnceTakesOneConnection(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "vsock_5000")
	raw, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	ln := once{raw}
	defer ln.Close()
	first, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	queued, err := net.Dial("unix", addr) // in the backlog before the host accepts
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if c, err := net.Dial("unix", addr); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("a connection after the first Accept: %v, want ENOENT", err)
		if err == nil {
			_ = c.Close()
		}
	}
	if _, err := os.Stat(addr); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket %s after the first Accept: %v, want gone", addr, err)
	}
	if err := queued.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := queued.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection queued before the first Accept still stands: %v", err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("a second Accept returned a connection")
	}
	go func() { _, _ = first.Write([]byte("hi")) }()
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hi" {
		t.Errorf("the first connection after the listener closed: %q, %v", got, err)
	}
}
