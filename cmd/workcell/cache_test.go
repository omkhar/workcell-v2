// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

func TestParseCaches(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []vmm.Cache // nil when refused
	}{
		{"none", nil, nil},
		{"read-only and writable, in order", []string{"go", "npm:rw"}, []vmm.Cache{{Name: "go"}, {Name: "npm", Writable: true}}},
		{"the longest name", []string{strings.Repeat("a", 32)}, []vmm.Cache{{Name: strings.Repeat("a", 32)}}},
		{"too long", []string{strings.Repeat("a", 33)}, nil},
		{"digits, _ and -", []string{"0_-"}, []vmm.Cache{{Name: "0_-"}}},
		{"empty", []string{""}, nil},
		{"capital", []string{"Go"}, nil},
		{"a dot or a slash", []string{"../x"}, nil},
		{"leading dash", []string{"-go"}, nil},
		{"another mode", []string{"go:ro"}, nil},
		{"a colon and no mode", []string{"go:"}, nil},
		{"twice", []string{"go", "go:rw"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCaches(tc.in)
			if (err == nil) != (tc.want != nil || len(tc.in) == 0) || !slices.Equal(got, tc.want) {
				t.Errorf("parseCaches(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestCacheLine(t *testing.T) {
	tests := []struct {
		c      vmm.Cache
		exists bool
		want   string
	}{
		{vmm.Cache{Name: "go"}, true, "cache go: /cache/go, read-only (the session may write there; nothing it writes is kept)"},
		{vmm.Cache{Name: "go"}, false, "cache go: does not exist yet; workcell run refuses it until --cache go:rw creates it"},
		{vmm.Cache{Name: "go", Writable: true}, true, "cache go: /cache/go, writable (persists in /d/go.ext4 for later sessions)"},
		{vmm.Cache{Name: "go", Writable: true}, false, "cache go: /cache/go, writable (persists in /d/go.ext4 for later sessions; it does not exist yet, the first session creates it)"},
	}
	for _, tc := range tests {
		if got := cacheLine(tc.c, "/d/go.ext4", tc.exists); got != tc.want {
			t.Errorf("cacheLine(%+v, %v) = %q, want %q", tc.c, tc.exists, got, tc.want)
		}
	}
}
