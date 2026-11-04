// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux && !(darwin && arm64 && cgo)

package main

import (
	"fmt"
	"io"
)

// vmmBinary is empty: there is no backend here (ADR-001 names Linux and macOS arm64).
const vmmBinary = ""

// run has no backend here.
func run(_ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "workcell: no backend for this OS yet")
	return 125
}

// diff and pull have none either.
func diff(_ []string, stderr io.Writer) int { return run(nil, stderr) }
func pull(_ []string, stderr io.Writer) int { return run(nil, stderr) }

// benchStart has no backend here either.
func benchStart(_, stderr io.Writer) int {
	fmt.Fprintln(stderr, "workcell: bench start needs Linux or macOS arm64")
	return 1
}
