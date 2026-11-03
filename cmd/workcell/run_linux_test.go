// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"strings"
	"testing"
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
