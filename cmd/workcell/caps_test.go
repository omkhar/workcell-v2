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
		name string
		args []string
		caps limits
		argv []string // nil: refused
	}{
		{"defaults", []string{"--", "ls"}, limits{2, 1024, 0}, []string{"ls"}},
		{"no separator", []string{"ls", "-l"}, limits{2, 1024, 0}, []string{"ls", "-l"}},
		{"all three", []string{"--cpus", "1", "--memory", "256MiB", "--disk", "64MiB", "--", "sh"}, limits{1, 256, 64}, []string{"sh"}},
		{"equals form", []string{"--cpus=4", "--memory=2GiB", "--disk=1GiB", "x"}, limits{4, 2048, 1024}, []string{"x"}},
		{"flags after the command belong to it", []string{"--", "ls", "--cpus", "9"}, limits{2, 1024, 0}, []string{"ls", "--cpus", "9"}},
		{"the floor", []string{"--memory", "128MiB", "x"}, limits{2, 128, 0}, []string{"x"}},
		{"no command", []string{"--cpus", "1"}, limits{}, nil},
		{"nothing", nil, limits{}, nil},
		{"no cpus", []string{"--cpus", "0", "x"}, limits{}, nil},
		{"too many cpus", []string{"--cpus", "33", "x"}, limits{}, nil},
		{"not a number of cpus", []string{"--cpus", "two", "x"}, limits{}, nil},
		{"memory below the floor", []string{"--memory", "127MiB", "x"}, limits{}, nil},
		{"memory nonsense", []string{"--memory", "lots", "x"}, limits{}, nil},
		{"disk nonsense", []string{"--disk", "1TB", "x"}, limits{}, nil},
		{"unknown flag", []string{"--net", "x"}, limits{}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps, argv, ok := parseRun(tc.args, io.Discard)
			if ok != (tc.argv != nil) || !slices.Equal(argv, tc.argv) || (ok && caps != tc.caps) {
				t.Errorf("parseRun(%q) = %+v, %q, %v; want %+v, %q", tc.args, caps, argv, ok, tc.caps, tc.argv)
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
