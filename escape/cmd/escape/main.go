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

// perTest bounds one test, sandbox start to stop (SPEC: under 20 seconds).
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
	if _, err := sandbox.New(*name); err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	dir, err := os.MkdirTemp("", "escape-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	defer os.RemoveAll(dir)
	payload, err := sandbox.BuildPayload(context.Background(), dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "escape:", err)
		return 2
	}
	rep := run(*name, func() (sandbox.Sandbox, error) { return sandbox.New(*name) }, payload, tests)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(rep)
	if rep.Passed != len(rep.Results) {
		return 1
	}
	return 0
}

// run gives every test a fresh sandbox and judges it.
func run(name string, fresh func() (sandbox.Sandbox, error), payload string, tests []suite.Test) Report {
	rep := Report{Sandbox: name, Results: []Result{}}
	for _, t := range tests {
		outcome, detail := runOne(fresh, payload, t)
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

func runOne(fresh func() (sandbox.Sandbox, error), payload string, t suite.Test) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), perTest)
	defer cancel()
	sb, err := fresh()
	if err != nil {
		return Error, err.Error()
	}
	defer sb.Stop()
	if err := sb.Start(ctx, payload); err != nil {
		return classify(err)
	}
	probe := func(args ...string) (suite.Result, error) {
		out, err := sb.Exec(ctx, append([]string{t.Name}, args...)...)
		if err != nil {
			return suite.Result{}, err
		}
		if out.Exit != 0 {
			return suite.Result{}, fmt.Errorf("payload exited %d: %s", out.Exit, out.Stderr)
		}
		return suite.ParseResult(out.Stdout)
	}
	pass, detail, err := t.Host(ctx, probe)
	if err != nil {
		return classify(err)
	}
	if pass {
		return Pass, detail
	}
	return Fail, detail
}

func classify(err error) (string, string) {
	if errors.Is(err, sandbox.ErrNotImplemented) {
		return NotImplemented, err.Error()
	}
	return Error, err.Error()
}
