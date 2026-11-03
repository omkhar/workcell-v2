// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import "testing"

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
