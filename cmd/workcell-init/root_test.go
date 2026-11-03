// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"slices"
	"testing"
)

func TestRootDevice(t *testing.T) {
	tests := []struct{ name, cmdline, want string }{
		{"none", "console=ttyS0 reboot=k panic=-1 pci=off quiet", ""},
		{"empty", "", ""},
		{"set", "console=ttyS0 root=/dev/vda ro", "/dev/vda"},
		{"newline", "quiet root=/dev/vda ro\n", "/dev/vda"},
		{"the last wins", "root=/dev/vdb root=/dev/vda ro", "/dev/vda"},
		{"not a device", "root=UUID=1234 ro", ""},
		{"a name that only ends in root=", "chroot=/dev/vda ro", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rootDevice(tc.cmdline); got != tc.want {
				t.Errorf("rootDevice(%q) = %q, want %q", tc.cmdline, got, tc.want)
			}
		})
	}
}

func TestDiskMiB(t *testing.T) {
	tests := []struct {
		name, cmdline string
		want          int
	}{
		{"none", "root=/dev/vda ro", 0},
		{"set", "root=/dev/vda ro workcell.disk=64", 64},
		{"newline", "ro workcell.disk=20480\n", 20480},
		{"the last wins", "workcell.disk=1 workcell.disk=2", 2},
		{"not a number", "workcell.disk=lots", 0},
		{"negative", "workcell.disk=-5", 0},
		{"too large", "workcell.disk=99999999999", 0},
		{"another name", "other.workcell.disk=64", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := diskMiB(tc.cmdline); got != tc.want {
				t.Errorf("diskMiB(%q) = %d, want %d", tc.cmdline, got, tc.want)
			}
		})
	}
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
	if got := tmpfsSize(0); got != "" {
		t.Errorf("tmpfsSize(0) = %q, want none", got)
	}
	if got := tmpfsSize(64); got != "size=64m" {
		t.Errorf("tmpfsSize(64) = %q, want size=64m", got)
	}
}
