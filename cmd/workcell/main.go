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
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version.String())
		return
	}
	fmt.Fprintln(os.Stderr, "workcell v2 is under construction; see loop/state/PLAN.md")
	os.Exit(2)
}
