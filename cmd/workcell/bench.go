// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"time"
)

// benchSamples is how many timed starts P1 asks for.
const benchSamples = 20

// bench is `workcell bench start`, the only bench verb. It prints the warm start time and does
// not judge it: the budget (P1) differs by machine.
func bench(args []string, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "start" {
		fmt.Fprintln(stderr, "usage: workcell bench start")
		return 2
	}
	return benchStart(os.Stdout, stderr)
}

// benchLine is the one output line for a set of start times: the median (the mean of the two
// middle values for an even count), the least and the greatest, in whole milliseconds.
func benchLine(samples []time.Duration) string {
	s := slices.Sorted(slices.Values(samples))
	n := len(s)
	p50 := (s[(n-1)/2] + s[n/2]) / 2
	return fmt.Sprintf("bench start n=%d p50=%dms min=%dms max=%dms", n, p50.Milliseconds(), s[0].Milliseconds(), s[n-1].Milliseconds())
}
