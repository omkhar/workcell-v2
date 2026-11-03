// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import "testing"

func TestPortsArg(t *testing.T) {
	tests := []struct {
		name string
		in   []uint16
		want string
	}{
		{"none", nil, "workcell.ports="},
		{"one", []uint16{443}, "workcell.ports=443"},
		{"many, in the order given", []uint16{443, 80, 8443}, "workcell.ports=443,80,8443"},
		{"the largest", []uint16{65535}, "workcell.ports=65535"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := portsArg(tc.in); got != tc.want {
				t.Errorf("portsArg(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
