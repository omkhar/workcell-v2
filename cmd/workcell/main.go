// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command workcell runs coding agents in short-lived microVMs.
package main

import (
	"fmt"
	"os"

	"github.com/omkhar/workcell/v2/internal/version"
)

// verbs is each verb's entry point, which takes the arguments after the verb and returns the exit code.
var verbs = map[string]func([]string) int{
	"run":     func(a []string) int { return run(a, os.Stderr) },
	"ls":      func(a []string) int { return ls(a, os.Stdout, os.Stderr) },
	"attach":  func(a []string) int { return attach(a, os.Stderr) },
	"stop":    func(a []string) int { return stop(a, os.Stderr) },
	"rm":      func(a []string) int { return rm(a, os.Stderr) },
	"diff":    func(a []string) int { return diff(a, os.Stderr) },
	"pull":    func(a []string) int { return pull(a, os.Stderr) },
	"explain": func(a []string) int { return explain(a, os.Stderr) },
	"log":     func(a []string) int { return logs(a, os.Stdout, os.Stderr) },
	"verify":  func(a []string) int { return verify(a, os.Stdout, os.Stderr) },
	"update":  func(a []string) int { return update(a, os.Stdout, os.Stderr) },
	"doctor":  func(a []string) int { return doctor(a, os.Stdout, os.Stderr) },
	"bench":   func(a []string) int { return bench(a, os.Stderr) },
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version.String())
		return
	}
	if len(os.Args) >= 2 && verbs[os.Args[1]] != nil {
		os.Exit(verbs[os.Args[1]](os.Args[2:]))
	}
	fmt.Fprintln(os.Stderr, "workcell v2 is under construction; see loop/state/PLAN.md")
	os.Exit(2)
}
