// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"io"
	"slices"
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int // 0: refused
	}{
		{"256MiB", 256},
		{"4GiB", 4096},
		{"20GiB", 20480},
		{"512", 512},
		{"1", 1},
		{"", 0},
		{"0", 0},
		{"0GiB", 0},
		{"GiB", 0},
		{"-1MiB", 0},
		{"+4GiB", 0},
		{"1.5GiB", 0},
		{" 4GiB", 0},
		{"4 GiB", 0},
		{"4gib", 0},
		{"4GB", 0},
		{"4MiBGiB", 0},
		{"99999999999MiB", 0},
		{"4194304GiB", 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSize(tc.in)
			if (err != nil) != (tc.want == 0) || got != tc.want {
				t.Errorf("parseSize(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestParseRun(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		caps  limits
		mount bool
		argv  []string // nil: refused
	}{
		{"defaults", []string{"--", "ls"}, limits{2, 1024, 0}, false, []string{"ls"}},
		{"no separator", []string{"ls", "-l"}, limits{2, 1024, 0}, false, []string{"ls", "-l"}},
		{"all three", []string{"--cpus", "1", "--memory", "256MiB", "--disk", "64MiB", "--", "sh"}, limits{1, 256, 64}, false, []string{"sh"}},
		{"equals form", []string{"--cpus=4", "--memory=2GiB", "--disk=1GiB", "x"}, limits{4, 2048, 1024}, false, []string{"x"}},
		{"flags after the command belong to it", []string{"--", "ls", "--cpus", "9"}, limits{2, 1024, 0}, false, []string{"ls", "--cpus", "9"}},
		{"the floor", []string{"--memory", "128MiB", "x"}, limits{2, 128, 0}, false, []string{"x"}},
		{"mount", []string{"--mount", "--", "sh"}, limits{2, 1024, 0}, true, []string{"sh"}},
		{"mount with caps", []string{"--mount", "--cpus", "1", "--disk", "64MiB", "x"}, limits{1, 1024, 64}, true, []string{"x"}},
		{"mount after the command belongs to it", []string{"--", "x", "--mount"}, limits{2, 1024, 0}, false, []string{"x", "--mount"}},
		{"no command", []string{"--cpus", "1"}, limits{}, false, nil},
		{"mount and no command", []string{"--mount"}, limits{}, false, nil},
		{"nothing", nil, limits{}, false, nil},
		{"no cpus", []string{"--cpus", "0", "x"}, limits{}, false, nil},
		{"too many cpus", []string{"--cpus", "33", "x"}, limits{}, false, nil},
		{"not a number of cpus", []string{"--cpus", "two", "x"}, limits{}, false, nil},
		{"memory below the floor", []string{"--memory", "127MiB", "x"}, limits{}, false, nil},
		{"memory nonsense", []string{"--memory", "lots", "x"}, limits{}, false, nil},
		{"disk nonsense", []string{"--disk", "1TB", "x"}, limits{}, false, nil},
		{"unknown flag", []string{"--net", "x"}, limits{}, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps, mount, _, _, argv, ok := parseRun(tc.args, io.Discard)
			if ok != (tc.argv != nil) || !slices.Equal(argv, tc.argv) || (ok && (caps != tc.caps || mount != tc.mount)) {
				t.Errorf("parseRun(%q) = %+v, %v, %q, %v; want %+v, %v, %q", tc.args, caps, mount, argv, ok, tc.caps, tc.mount, tc.argv)
			}
		})
	}
}

func TestCmdline(t *testing.T) {
	tests := []struct {
		l    limits
		want string
	}{
		{limits{2, 1024, 0}, "root=/dev/vda ro"},
		{limits{1, 256, 64}, "root=/dev/vda ro workcell.disk=64"},
	}
	for _, tc := range tests {
		if got := tc.l.cmdline(); got != tc.want {
			t.Errorf("%+v.cmdline() = %q, want %q", tc.l, got, tc.want)
		}
	}
}

func TestParseRunAllow(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
		ok   bool
	}{
		{"none", []string{"x"}, nil, true},
		{"repeated, in order", []string{"--allow", "a.example", "--allow=b.example:80", "x"}, []string{"a.example", "b.example:80"}, true},
		{"after the command belongs to it", []string{"x", "--allow", "a.example"}, nil, true},
		{"without a value", []string{"--allow"}, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, allow, _, _, ok := parseRun(tc.args, io.Discard)
			if ok != tc.ok || !slices.Equal(allow, tc.want) {
				t.Errorf("parseRun(%q) allow = %q, %v; want %q, %v", tc.args, allow, ok, tc.want, tc.ok)
			}
		})
	}
}
