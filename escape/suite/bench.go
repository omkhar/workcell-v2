// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// SPEC P1: warm session start p50 under 2.5 s on a hosted CI runner, measured
// by `workcell bench start` over 20 samples. The product does the timing; the
// judge only runs it, reads its one line and holds it to the budget.
const (
	benchSamples  = 20
	benchBudgetMs = 2500
	// benchBound gives the twenty-one boots room to be slow and still end
	// as a measured fail, not a timeout: seven seconds each, and teardown.
	benchBound = 150 * time.Second
)

// benchJudge runs the benchmark through the adapter. A start the product
// could not do, a line it did not print as SPEC P1 says, or a median not
// under the budget (the product prints whole milliseconds, truncated, so
// 2500 may stand for 2500.9) is a fail, with the product's own words as
// the detail so that the number is in the run log.
func benchJudge(ctx context.Context, s Session) (bool, string, error) {
	out, err := s.Bench(ctx)
	if err != nil {
		return false, "", err
	}
	if out.Exit != 0 {
		line, _, _ := bytes.Cut(bytes.TrimSpace(out.Stderr), []byte("\n"))
		return false, clean(fmt.Sprintf("bench start exited %d: %s", out.Exit, line), maxDetail, isPrint, '?'), nil
	}
	p50, err := parseBench(out.Stdout)
	if err != nil {
		return false, clean("bench start printed: "+err.Error(), maxDetail, isPrint, '?'), nil
	}
	return p50 < benchBudgetMs, clean(string(bytes.TrimSpace(out.Stdout)), maxDetail, isPrint, '?'), nil
}

// parseBench reads the one line `bench start n=20 p50=<ms> min=<ms> max=<ms>`
// and returns the median. It is strict: the whole output must be that line
// and nothing else, with n the sample count and min <= p50 <= max.
func parseBench(b []byte) (int, error) {
	line, ok := bytes.CutSuffix(b, []byte("\n"))
	if !ok || bytes.IndexByte(line, '\n') >= 0 {
		return 0, fmt.Errorf("not exactly one line: %q", b)
	}
	const format = "bench start n=%d p50=%dms min=%dms max=%dms"
	var n, p50, lo, hi int
	if _, err := fmt.Sscanf(string(line), format, &n, &p50, &lo, &hi); err != nil || fmt.Sprintf(format, n, p50, lo, hi) != string(line) {
		return 0, fmt.Errorf("not the P1 line: %q", line)
	}
	if n != benchSamples || lo > p50 || p50 > hi || lo < 0 {
		return 0, fmt.Errorf("not a measurement of %d samples: %q", benchSamples, line)
	}
	return p50, nil
}
