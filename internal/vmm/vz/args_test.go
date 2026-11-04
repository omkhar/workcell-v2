// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package vz

import "testing"

func TestCmdline(t *testing.T) {
	tests := []struct{ name, extra, want string }{
		{"nothing to add", "", "console=hvc0 panic=-1 quiet"},
		{"the init's keys follow", "root=/dev/vda ro workcell.workspace=/dev/vdb", "console=hvc0 panic=-1 quiet root=/dev/vda ro workcell.workspace=/dev/vdb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdline(tc.extra); got != tc.want {
				t.Errorf("cmdline(%q) = %q, want %q", tc.extra, got, tc.want)
			}
		})
	}
}
