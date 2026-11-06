// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"fmt"
	"slices"
	"testing"
)

// parse is one row of a cmdline reader's table: the kernel command line, and what is read from it.
type parse[T any] struct {
	name, cmdline string
	want          T
}

func parses[T any](t *testing.T, read func(string) T, tests []parse[T]) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := read(tc.cmdline); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("(%q) = %v, want %v", tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestRootDevice(t *testing.T) {
	parses(t, rootDevice, []parse[string]{
		{"none", "console=ttyS0 reboot=k panic=-1 pci=off quiet", ""},
		{"empty", "", ""},
		{"set", "console=ttyS0 root=/dev/vda ro", "/dev/vda"},
		{"newline", "quiet root=/dev/vda ro\n", "/dev/vda"},
		{"the last wins", "root=/dev/vdb root=/dev/vda ro", "/dev/vda"},
		{"not a device", "root=UUID=1234 ro", ""},
		{"a name that only ends in root=", "chroot=/dev/vda ro", ""},
	})
}

func TestWorkspaceDevice(t *testing.T) {
	parses(t, workspaceDevice, []parse[string]{
		{"none", "root=/dev/vda ro", ""},
		{"set", "root=/dev/vda ro workcell.workspace=/dev/vdb", "/dev/vdb"},
		{"another name", "other.workcell.workspace=/dev/vdb", ""},
	})
}

func TestLayers(t *testing.T) {
	parses(t, layers, []parse[[]layer]{
		{"none", "root=/dev/vda ro workcell.workspace=/dev/vdb", nil},
		{"one", "root=/dev/vda workcell.layer=claude:/dev/vdc\n", []layer{{"claude", "/dev/vdc"}}},
		{"two, in order", "workcell.layer=codex:/dev/vdc workcell.layer=claude:/dev/vdd", []layer{{"codex", "/dev/vdc"}, {"claude", "/dev/vdd"}}},
		{"not a device", "workcell.layer=claude:vdc workcell.layer=codex:/dev/vdd", []layer{{"codex", "/dev/vdd"}}},
		{"no device", "workcell.layer=claude", nil},
		{"no name", "workcell.layer=:/dev/vdc", nil},
		{"a name with a slash or a dot", "workcell.layer=../etc:/dev/vdc workcell.layer=a/b:/dev/vdd", nil},
		{"another name", "other.workcell.layer=claude:/dev/vdc", nil},
	})
}

func TestMounted(t *testing.T) {
	parses(t, mounted, []parse[bool]{
		{"none", "root=/dev/vda ro", false},
		{"set", "root=/dev/vda ro workcell.mount=1", true},
		{"newline", "ro workcell.mount=1\n", true},
		{"zero", "workcell.mount=0", false},
		{"empty", "workcell.mount=", false},
		{"the last wins", "workcell.mount=1 workcell.mount=0", false},
		{"the last wins when on", "workcell.mount=0 workcell.mount=1", true},
		{"another name", "other.workcell.mount=1", false},
		{"no value", "workcell.mount", false},
	})
}

func TestDiskMiB(t *testing.T) {
	parses(t, diskMiB, []parse[int]{
		{"none", "root=/dev/vda ro", 0},
		{"set", "root=/dev/vda ro workcell.disk=64", 64},
		{"newline", "ro workcell.disk=20480\n", 20480},
		{"the last wins", "workcell.disk=1 workcell.disk=2", 2},
		{"not a number", "workcell.disk=lots", 0},
		{"negative", "workcell.disk=-5", 0},
		{"too large", "workcell.disk=99999999999", 0},
		{"another name", "other.workcell.disk=64", 0},
	})
}

func TestPorts(t *testing.T) {
	tests := []struct {
		name, cmdline string
		want          []uint16
		ok            bool
	}{
		{"none", "root=/dev/vda ro", nil, true},
		{"empty", "root=/dev/vda ro workcell.ports= quiet", nil, true},
		{"one", "workcell.ports=443", []uint16{443}, true},
		{"many", "ro workcell.ports=443,80,8443\n", []uint16{443, 80, 8443}, true},
		{"the last wins", "workcell.ports=443 workcell.ports=80", []uint16{80}, true},
		{"the last wins when empty", "workcell.ports=443 workcell.ports=", nil, true},
		{"another name", "other.workcell.ports=443", nil, true},
		{"not a number", "workcell.ports=https", nil, false},
		{"zero", "workcell.ports=0", nil, false},
		{"too large", "workcell.ports=65536", nil, false},
		{"negative", "workcell.ports=-1", nil, false},
		{"a blank entry", "workcell.ports=443,", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ports(tc.cmdline)
			if (err == nil) != tc.ok || !slices.Equal(got, tc.want) {
				t.Errorf("ports(%q) = %v, %v; want %v, ok=%t", tc.cmdline, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestTmpfsSize(t *testing.T) {
	if none, some := tmpfsSize(0), tmpfsSize(64); none != "" || some != "size=64m" {
		t.Errorf("tmpfsSize(0), tmpfsSize(64) = %q, %q; want none and size=64m", none, some)
	}
}

func TestCaches(t *testing.T) {
	parses(t, caches, []parse[[]cache]{
		{"none", "root=/dev/vda ro workcell.layer=claude:/dev/vdc", nil},
		{"two, in order", "workcell.cache=go:/dev/vdd:ro workcell.cache=npm:/dev/vde:rw\n", []cache{{"go", "/dev/vdd", false}, {"npm", "/dev/vde", true}}},
		{"not a device", "workcell.cache=go:vdd:ro", nil},
		{"another mode", "workcell.cache=go:/dev/vdd:rx workcell.cache=go:/dev/vdd", nil},
		{"no name", "workcell.cache=:/dev/vdd:ro", nil},
		{"a name with a slash or a dot", "workcell.cache=../etc:/dev/vdd:ro workcell.cache=a/b:/dev/vdd:rw", nil},
		{"another name", "other.workcell.cache=go:/dev/vdd:ro", nil},
	})
}
