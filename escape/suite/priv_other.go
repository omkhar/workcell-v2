// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"fmt"
	"os"
)

// Bind is the payload's privileged helper, on Linux only.
func Bind(network, addr, _ string) int {
	fmt.Fprintf(os.Stderr, "bind %s %s: Linux only\n", network, addr)
	return 1
}

func Hold(string, string) int {
	fmt.Fprintln(os.Stderr, "netns: Linux only")
	return 1
}
