// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package version

import "testing"

func TestString(t *testing.T) {
	tests := []struct{ version, want string }{
		{"v2-dev", "workcell v2-dev"},
		{"v2.0.0", "workcell v2.0.0"},
	}
	for _, tt := range tests {
		Version = tt.version
		if got := String(); got != tt.want {
			t.Errorf("String() with %q = %q, want %q", tt.version, got, tt.want)
		}
	}
}
