// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command bump moves the rows of pins/ to their next verified release: once a
// day, at most one pull request per class, merged when the gate is green (B13).
// With -dry-run it prints the plan and posts and writes nothing.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/advisory"
	"github.com/omkhar/workcell/v2/internal/bump"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t := bump.Tool{Pins: "pins", Upstream: http.DefaultClient, OSV: advisory.OSV, PinTime: 3 * time.Minute, Now: time.Now(), Out: os.Stdout}
	t.GitHub.Client = &http.Client{Timeout: time.Minute}
	code := run(ctx, os.Args[1:], os.Getenv, t, os.Stderr)
	stop()
	os.Exit(code)
}

// run reads the flags and the GitHub Actions environment into t and runs it.
// It exits 2 on refused data and 1 on a failed step.
func run(ctx context.Context, args []string, getenv func(string) string, t bump.Tool, stderr io.Writer) int {
	fs := flag.NewFlagSet("bump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&t.DryRun, "dry-run", false, "print the plan; post and write nothing")
	fs.StringVar(&t.GitHub.API, "api", cmp.Or(getenv("GITHUB_API_URL"), "https://api.github.com"), "the GitHub API root")
	fs.StringVar(&t.GitHub.Repo, "repo", getenv("GITHUB_REPOSITORY"), "the repository, owner/name")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	t.GitHub.Token = getenv("GITHUB_TOKEN")
	err := t.Run(ctx)
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "bump:", err)
	if errors.As(err, new(bump.Refused)) {
		return 2
	}
	return 1
}
