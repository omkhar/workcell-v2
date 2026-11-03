// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"strconv"
	"testing"
)

func TestCpioEntry(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"init", "#!x"},    // header+name 115 -> padded to 116; data 3 -> 4
		{"a", ""},          // header+name 112: no pad; no data
		{"TRAILER!!!", ""}, // 121 -> 124
		{"abcdef", "12345678"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := cpioEntry(&b, c.name, 0o100755, []byte(c.data)); err != nil {
				t.Fatal(err)
			}
			out := b.Bytes()
			if len(out)%4 != 0 || string(out[:6]) != "070701" {
				t.Fatalf("entry is %d bytes, starts %q", len(out), out[:6])
			}
			field := func(i int) int64 {
				n, err := strconv.ParseInt(string(out[6+8*i:14+8*i]), 16, 64)
				if err != nil {
					t.Fatalf("field %d: %v", i, err)
				}
				return n
			}
			if field(1) != 0o100755 || field(6) != int64(len(c.data)) || field(11) != int64(len(c.name)+1) {
				t.Fatalf("mode %o size %d namesize %d", field(1), field(6), field(11))
			}
			nameEnd := 110 + len(c.name)
			if string(out[110:nameEnd]) != c.name || out[nameEnd] != 0 {
				t.Fatalf("name field %q", out[110:nameEnd+1])
			}
			dataAt := (nameEnd + 1 + 3) &^ 3
			if string(out[dataAt:dataAt+len(c.data)]) != c.data {
				t.Fatalf("data at %d is %q", dataAt, out[dataAt:])
			}
			for _, z := range out[nameEnd+1 : dataAt] {
				if z != 0 {
					t.Fatal("name padding is not zero")
				}
			}
		})
	}
}

func TestUnsupported(t *testing.T) {
	cases := []struct {
		cfg  Config
		want bool // refused
	}{
		{Config{}, false},
		{Config{CPUs: 2, MemoryMiB: 1024}, false},
		{Config{Workspace: "/w"}, true},
		{Config{Secret: &Secret{}}, true},
		{Config{Allow: []string{"a"}}, true},
		{Config{Deny: []string{"a"}}, true},
		{Config{CPUs: 1}, true},
		{Config{MemoryMiB: 512}, true},
		{Config{DiskMiB: 100}, true},
	}
	for _, c := range cases {
		if got := unsupported(c.cfg) != ""; got != c.want {
			t.Errorf("%+v: refused %v, want %v", c.cfg, got, c.want)
		}
	}
}
