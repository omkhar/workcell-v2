// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrame(t *testing.T) {
	f := frame(typeExit, []byte("abc"))
	if len(f) != 9 || f[0] != 1 || f[1] != typeExit || binary.BigEndian.Uint32(f[2:6]) != 3 || string(f[6:]) != "abc" {
		t.Fatalf("frame = % x", f)
	}
	if f := frame(typeStdout, nil); len(f) != 6 || binary.BigEndian.Uint32(f[2:]) != 0 {
		t.Fatalf("empty frame = % x", f)
	}
}

func TestHostileText(t *testing.T) {
	for _, n := range []int{maxExitText - 1, 100, 40, 0} {
		b := hostileText(n)
		if len(b) != n || n > 0 && !bytes.Contains(b, []byte{0x1b}) {
			t.Errorf("hostileText(%d) is %d bytes, escapes %v", n, len(b), bytes.Contains(b, []byte{0x1b}))
		}
	}
	if b := textTag(hostileText(maxExitText)); len(b) != maxExitText+1 || b[0] != tagText {
		t.Errorf("tagged text is %d bytes, tag %d", len(b), b[0])
	}
	if b := exitTag(forgedCode); !bytes.Equal(b, []byte{tagCode, forgedCode}) {
		t.Errorf("exitTag = % x", b)
	}
}

func TestControlBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"workcell: channel: frame too large (4294967295 bytes)\n", 0},
		{"a\tb\n", 0},
		{"\x1b[2J", 1},
		{"\x1b]0;x\x07\r\x00\x7f", 5},
		{"caf\xc3\xa9\n", 0},           // UTF-8 shows; only C0 controls and DEL steer
		{string(hostileText(256)), 71}, // what the control run reports, raw
	}
	for _, c := range cases {
		if got := control([]byte(c.in)); got != c.want {
			t.Errorf("control(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
