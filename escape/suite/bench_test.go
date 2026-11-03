// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

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

// bench is an adapter whose benchmark prints the line it is given.
type bench struct {
	idle
	line string
}

func (b bench) Bench(context.Context) (sandbox.Output, error) {
	return sandbox.Output{Stdout: []byte(b.line)}, nil
}

func TestBenchJudgeBudget(t *testing.T) {
	for _, tc := range []struct {
		p50  int
		pass bool
	}{{2499, true}, {2500, false}, {2501, false}} { // the product truncates: 2500 may be 2500.9
		line := fmt.Sprintf("bench start n=20 p50=%dms min=2400ms max=2600ms\n", tc.p50)
		pass, detail, err := benchJudge(context.Background(), Session{Observe: bench{line: line}})
		if err != nil || pass != tc.pass || detail != strings.TrimSpace(line) {
			t.Errorf("p50=%d: pass=%v detail=%q err=%v; want pass=%v", tc.p50, pass, detail, err, tc.pass)
		}
	}
}
