// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import "testing"

func TestParseBench(t *testing.T) {
	for _, tc := range []struct {
		in   string
		p50  int
		fail bool
	}{
		{"bench start n=20 p50=699ms min=650ms max=812ms\n", 699, false},
		{"bench start n=20 p50=0ms min=0ms max=0ms\n", 0, false},
		{"bench start n=20 p50=699ms min=650ms max=812ms", 0, true},      // no newline
		{"bench start n=20 p50=699ms min=650ms max=812ms\nx\n", 0, true}, // a second line
		{"bench start n=19 p50=699ms min=650ms max=812ms\n", 0, true},    // too few samples
		{"bench start n=20 p50=699ms min=700ms max=812ms\n", 0, true},    // min over p50
		{"bench start n=20 p50=900ms min=650ms max=812ms\n", 0, true},    // p50 over max
		{"bench start n=20 p50=699ms min=650ms max=812ms extra\n", 0, true},
		{"bench start n=20 p50=699.5ms min=650ms max=812ms\n", 0, true},
		{"bench start n=20 p50=+699ms min=650ms max=812ms\n", 0, true}, // not the product's spelling
		{"", 0, true},
		{"usage: workcell bench start\n", 0, true},
	} {
		p50, err := parseBench([]byte(tc.in))
		if (err != nil) != tc.fail || p50 != tc.p50 {
			t.Errorf("parseBench(%q) = %d, %v; want %d, fail=%v", tc.in, p50, err, tc.p50, tc.fail)
		}
	}
}
