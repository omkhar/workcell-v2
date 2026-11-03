// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

// Command workcell-init is PID 1 of the guest. The guest is Linux; this build only
// keeps the package visible to every build.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "workcell-init runs only as PID 1 of a Linux guest")
	os.Exit(1)
}
