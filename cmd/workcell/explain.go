// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"io"
	"os"
)

// explain is `workcell explain [--mount]`: it prints what a session started here by `workcell
// run`, with `--mount` or without, can reach. The output is the whole assurance story (SPEC
// section 5); the network's part of it comes with the allowlist (U-308).
func explain(args []string, stderr io.Writer) int {
	mount := len(args) == 1 && args[0] == "--mount"
	if len(args) > 1 || len(args) == 1 && !mount {
		fmt.Fprintln(stderr, "usage: workcell explain [--mount]\n  says what a session run here with the same flag can reach")
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "workcell explain:", err)
		return 2
	}
	fmt.Print(explanation(mount, cwd))
	return 0
}

// explanation is the text for a session of dir: what its guest sees as /workspace, in plain words.
func explanation(mount bool, dir string) string {
	if mount {
		return "workspace: " + dir + ", live (--mount)\n" +
			"  The agent writes directly to the real tree: every change it makes lands there as it is\n" +
			"  made, and workcell pull and diff have nothing to bring back.\n"
	}
	return "workspace: a copy of " + dir + "\n" +
		"  The agent works in the copy; the real tree does not change until workcell pull brings\n" +
		"  the work back, and workcell diff lists it first.\n"
}
