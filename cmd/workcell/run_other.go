// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package main

import (
	"fmt"
	"io"
)

// run has no backend here yet; the macOS one is a later unit.
func run(_ []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "workcell: no backend for this OS yet")
	return 125
}
