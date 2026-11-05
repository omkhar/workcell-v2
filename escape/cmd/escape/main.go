// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Escape runs the escape suite against a sandbox and prints a JSON report.
//
//	escape -sandbox control|workcell [-list] [-only I1,I2,...]
//
// It exits 0 only when every selected test passed. "not-implemented" and
// "error" exit non-zero too: an invariant that was not tested is not proven.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	"github.com/omkhar/workcell/v2/escape/suite"
)

// Outcomes of one test.
const (
	Pass           = "pass"
	Fail           = "fail"
	NotImplemented = "not-implemented"
	Error          = "error"
)

// perTest bounds one test, sandbox start to stop (SPEC: under 20 seconds),
// unless the test states its own Bound.
const perTest = 20 * time.Second

// Report is the JSON the runner prints.
type Report struct {
	Sandbox string   `json:"sandbox"`
	Results []Result `json:"results"`
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	Skipped int      `json:"not_implemented"`
	Errors  int      `json:"errors"`
}

// Result is one test's line in the report.
type Result struct {
	Invariant string `json:"invariant"`
	Name      string `json:"name"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail,omitempty"`
}

func main() { os.Exit(app()) }

// app is main without os.Exit, so that the deferred cleanup runs.
func app() int {
	name := flag.String("sandbox", "", "adapter: control or workcell")
	list := flag.Bool("list", false, "list the tests and exit")
	only := flag.String("only", "", "run only the tests for these invariant IDs, comma-separated")
	flag.Parse()
	tests, err := suite.Select(*only)
	if err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	if *list {
		for _, t := range tests {
			fmt.Printf("%s\t%s\n", t.ID, t.Name)
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // an interrupt still lets a judge clean up
	defer stop()
	dir, err := os.MkdirTemp("", "escape-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	defer os.RemoveAll(dir)
	payload, err := sandbox.BuildPayload(ctx, dir)
	var roots string
	if err == nil {
		roots, err = suite.Roots(dir) // the suite's authority, which every session's host side trusts upstream
	}
	if err == nil {
		err = sandbox.Prepare(ctx, *name, dir) // once, outside any test's time
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	rep := run(ctx, *name, func() (sandbox.Sandbox, error) { return sandbox.New(*name) }, payload, roots, tests)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(rep)
	if rep.Passed != len(rep.Results) {
		return 1
	}
	return 0
}

// run gives every test a fresh sandbox and judges it.
func run(ctx context.Context, name string, fresh func() (sandbox.Sandbox, error), payload, roots string, tests []suite.Test) Report {
	rep := Report{Sandbox: name, Results: []Result{}}
	for _, t := range tests {
		outcome, detail := runOne(ctx, fresh, payload, roots, t)
		fmt.Fprintf(os.Stderr, "escape: %s: %s %s: %s %s\n", name, t.ID, t.Name, outcome, detail) // as it goes, so that a log shows where a hang was
		rep.Results = append(rep.Results, Result{Invariant: t.ID, Name: t.Name, Outcome: outcome, Detail: detail})
		switch outcome {
		case Pass:
			rep.Passed++
		case Fail:
			rep.Failed++
		case NotImplemented:
			rep.Skipped++
		default:
			rep.Errors++
		}
	}
	return rep
}

// runOne starts the test's first session, lets the judge open more, and stops
// them all, last first, when the judge is done.
func runOne(ctx context.Context, fresh func() (sandbox.Sandbox, error), payload, roots string, t suite.Test) (string, string) {
	bound := perTest
	if t.Bound > 0 {
		bound = t.Bound
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	var sessions []session
	defer func() {
		for i := len(sessions) - 1; i >= 0; i-- {
			sessions[i].stop()
		}
	}()
	var open func() (suite.Session, error)
	open = func() (suite.Session, error) {
		sb, err := fresh()
		if err != nil {
			return suite.Session{}, err
		}
		s := session{sb: sb}
		sessions = append(sessions, s)
		cfg := sandbox.Config{Payload: payload, Mount: t.Want.Mount, CPUs: t.Want.CPUs, MemoryMiB: t.Want.MemoryMiB, DiskMiB: t.Want.DiskMiB, Allow: t.Want.Allow, Deny: t.Want.Deny, Resolver: t.Want.Resolver, Isolated: t.Want.Isolated, Roots: roots}
		if t.Want.Secret {
			sec := suite.NewSecret(t.Want)
			cfg.Secret = &sec
		}
		if t.Want.Workspace {
			if s.root, err = os.MkdirTemp("", "escape-ws-"); err != nil {
				return suite.Session{}, err
			}
			sessions[len(sessions)-1] = s
			cfg.Workspace = filepath.Join(s.root, "workspace")
			if err := os.Mkdir(cfg.Workspace, 0o755); err != nil {
				return suite.Session{}, err
			}
			if t.Want.Policy != "" { // the hostile repository's own policy, there before the session starts
				if err := os.WriteFile(filepath.Join(cfg.Workspace, "workcell.toml"), []byte(t.Want.Policy), 0o644); err != nil {
					return suite.Session{}, err
				}
			}
		}
		guest, err := sb.Start(ctx, cfg)
		if err != nil {
			return suite.Session{}, err
		}
		ses := suite.Session{Run: probe(ctx, sb, t.Name), Workspace: cfg.Workspace, Guest: guest, Allow: cfg.Allow, Deny: cfg.Deny, Payload: payload, Another: open,
			Exec: func(ctx context.Context, args ...string) (sandbox.Output, error) {
				return sb.Exec(ctx, append([]string{t.Name}, args...)...)
			},
			Pull: func(dest string) error { return sb.Pull(ctx, dest) }, Observe: sb}
		if cfg.Secret != nil {
			ses.Secret = *cfg.Secret
		}
		return ses, nil
	}
	first, err := open()
	if err != nil {
		return classify(err)
	}
	pass, detail, err := t.Host(ctx, first)
	if err != nil {
		return classify(err)
	}
	if pass {
		return Pass, detail
	}
	return Fail, detail
}

// session is one sandbox and the directory made for its export.
type session struct {
	sb   sandbox.Sandbox
	root string
}

func (s session) stop() {
	s.sb.Stop()
	if s.root != "" {
		os.RemoveAll(s.root)
	}
}

// probe runs the test's probe inside the sandbox and parses its one line.
func probe(ctx context.Context, sb sandbox.Sandbox, name string) suite.Run {
	return func(args ...string) (suite.Result, error) {
		out, err := sb.Exec(ctx, append([]string{name}, args...)...)
		if err != nil {
			return suite.Result{}, err
		}
		if out.Exit != 0 {
			return suite.Result{}, fmt.Errorf("payload exited %d: %s", out.Exit, out.Stderr)
		}
		r, err := suite.ParseResult(out.Stdout)
		if err == nil && r.Status == "error" { // the probe did not run, or could not: never a judge's pass
			err = fmt.Errorf("probe error: %s", r.Detail)
		}
		return r, err
	}
}

func classify(err error) (string, string) {
	if errors.Is(err, sandbox.ErrNotImplemented) {
		return NotImplemented, err.Error()
	}
	return Error, err.Error()
}
