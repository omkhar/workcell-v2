// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command workcell runs coding agents in short-lived microVMs.
package main

import (
	"fmt"
	"os"

	"github.com/omkhar/workcell/v2/internal/version"
)

func main() {
	switch {
	case len(os.Args) == 2 && os.Args[1] == "--version":
		fmt.Println(version.String())
	case len(os.Args) >= 2 && os.Args[1] == "run":
		os.Exit(run(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "ls":
		os.Exit(ls(os.Args[2:], os.Stdout, os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "stop":
		os.Exit(stop(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "rm":
		os.Exit(rm(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "diff":
		os.Exit(diff(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "pull":
		os.Exit(pull(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "explain":
		os.Exit(explain(os.Args[2:], os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "log":
		os.Exit(logs(os.Args[2:], os.Stdout, os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "update":
		os.Exit(update(os.Args[2:], os.Stdout, os.Stderr))
	case len(os.Args) >= 2 && os.Args[1] == "bench":
		os.Exit(bench(os.Args[2:], os.Stderr))
	default:
		fmt.Fprintln(os.Stderr, "workcell v2 is under construction; see loop/state/PLAN.md")
		os.Exit(2)
	}
}
