// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"testing"
	"time"
)

func TestBenchLine(t *testing.T) {
	ms := func(v ...float64) []time.Duration {
		var d []time.Duration
		for _, x := range v {
			d = append(d, time.Duration(x*float64(time.Millisecond)))
		}
		return d
	}
	tests := []struct {
		name string
		in   []time.Duration
		want string
	}{
		{"one", ms(5), "bench start n=1 p50=5ms min=5ms max=5ms"},
		{"odd count, unsorted", ms(30, 10, 20), "bench start n=3 p50=20ms min=10ms max=30ms"},
		{"even count takes the mean of the middle two", ms(40, 10, 30, 20), "bench start n=4 p50=25ms min=10ms max=40ms"},
		{"truncated, not rounded", ms(10.9, 11.9), "bench start n=2 p50=11ms min=10ms max=11ms"},
		{"twenty", ms(700, 650, 812, 699, 701, 660, 670, 680, 690, 710, 720, 730, 740, 750, 760, 770, 780, 790, 800, 705),
			"bench start n=20 p50=715ms min=650ms max=812ms"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := benchLine(tc.in); got != tc.want {
				t.Errorf("benchLine = %q, want %q", got, tc.want)
			}
		})
	}
}
