// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	"github.com/omkhar/workcell/v2/escape/suite"
)

// fake is a sandbox whose payload prints canned bytes.
type fake struct {
	start      error
	stdout     string
	exit       int
	workspaces []string // one per Start
	stops      int
}

func (f *fake) Start(_ context.Context, cfg sandbox.Config) (string, error) {
	f.workspaces = append(f.workspaces, cfg.Workspace)
	return "/guest" + cfg.Workspace, f.start
}
func (f *fake) Exec(_ context.Context, args ...string) (sandbox.Output, error) {
	return sandbox.Output{Stdout: []byte(f.stdout), Exit: f.exit, Total: int64(len(f.stdout))}, nil
}
func (f *fake) Stop() error { f.stops++; return nil }

func TestRunOutcomes(t *testing.T) {
	judge := func(_ context.Context, s suite.Session) (bool, string, error) {
		r, err := s.Run("x")
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
		{"probe error", fake{stdout: "escape-result error want address and token\n"}, Error, false},
		{"hostile output", fake{stdout: "escape-result blocked\nescape-result blocked\n"}, Error, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := run(context.Background(), "fake", func() (sandbox.Sandbox, error) { return &c.sb, nil }, "", []suite.Test{test})
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

// TestSessions checks that each session gets its own export, the judge can
// open a second one, and every session is stopped and its export removed.
func TestSessions(t *testing.T) {
	var got []suite.Session
	sb := &fake{stdout: "escape-result ok \n"}
	judge := func(_ context.Context, s suite.Session) (bool, string, error) {
		two, err := s.Another()
		got = append(got, s, two)
		if err != nil {
			return false, "", err
		}
		if _, err := s.Run(); err != nil || s.Taken() != int64(len(sb.stdout)) || two.Taken() != 0 {
			return false, "", fmt.Errorf("taken %d and %d after one run, %v", s.Taken(), two.Taken(), err)
		}
		return true, "", nil
	}
	test := suite.Test{ID: "I7", Name: "t", Host: judge, Want: suite.Want{Workspace: true, CPUs: 1}}
	rep := run(context.Background(), "fake", func() (sandbox.Sandbox, error) { return sb, nil }, "", []suite.Test{test})
	if rep.Passed != 1 || len(got) != 2 || sb.stops != 2 || len(sb.workspaces) != 2 {
		t.Fatalf("report %+v, %d sessions, %d stops, workspaces %q", rep, len(got), sb.stops, sb.workspaces)
	}
	for i, s := range got {
		if s.Workspace != sb.workspaces[i] || s.Guest != "/guest"+s.Workspace || s.Run == nil || s.Taken() != int64(i^1)*int64(len(sb.stdout)) {
			t.Errorf("session %d: %+v, want workspace %q", i, s, sb.workspaces[i])
		}
		if _, err := os.Stat(filepath.Dir(s.Workspace)); !os.IsNotExist(err) {
			t.Errorf("session %d: export %s was not removed (%v)", i, s.Workspace, err)
		}
	}
	if got[0].Workspace == got[1].Workspace {
		t.Error("both sessions share an export")
	}
}
