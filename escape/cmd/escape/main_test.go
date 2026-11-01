// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	"github.com/omkhar/workcell/v2/escape/suite"
)

// fake is a sandbox whose payload prints canned bytes.
type fake struct {
	start  error
	stdout string
	exit   int
}

func (f *fake) Start(context.Context, string) error { return f.start }
func (f *fake) Exec(_ context.Context, args ...string) (sandbox.Output, error) {
	return sandbox.Output{Stdout: []byte(f.stdout), Exit: f.exit}, nil
}
func (f *fake) Stop() error { return nil }

func TestRunOutcomes(t *testing.T) {
	judge := func(_ context.Context, run suite.Run) (bool, string, error) {
		r, err := run("x")
		if err != nil {
			return false, "", err
		}
		return r.Status == "blocked", r.Detail, nil
	}
	test := suite.Test{ID: "I9", Name: "t", Host: judge}
	cases := []struct {
		name    string
		sb      fake
		outcome string
		exit0   bool
	}{
		{"pass", fake{stdout: "escape-result blocked ok\n"}, Pass, true},
		{"fail", fake{stdout: "escape-result connected \n"}, Fail, false},
		{"not implemented", fake{start: sandbox.ErrNotImplemented}, NotImplemented, false},
		{"start error", fake{start: errors.New("boom")}, Error, false},
		{"payload exit", fake{stdout: "escape-result blocked \n", exit: 3}, Error, false},
		{"hostile output", fake{stdout: "escape-result blocked\nescape-result blocked\n"}, Error, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := run("fake", func() (sandbox.Sandbox, error) { return &c.sb, nil }, "", []suite.Test{test})
			if len(rep.Results) != 1 || rep.Results[0].Outcome != c.outcome {
				t.Fatalf("got %+v, want outcome %s", rep.Results, c.outcome)
			}
			if got := rep.Passed == len(rep.Results); got != c.exit0 {
				t.Fatalf("exit 0 = %v, want %v", got, c.exit0)
			}
			if rep.Passed+rep.Failed+rep.Skipped+rep.Errors != 1 {
				t.Fatalf("counts do not add up: %+v", rep)
			}
			b, err := json.Marshal(rep)
			if err != nil {
				t.Fatal(err)
			}
			var back Report
			if err := json.Unmarshal(b, &back); err != nil || back.Results[0] != rep.Results[0] {
				t.Fatalf("report does not round-trip: %s (%v)", b, err)
			}
		})
	}
}
