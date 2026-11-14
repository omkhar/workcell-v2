// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"fmt"
	"os"
)

// Bind and Hold are the payload's privileged verbs, on Linux only.
func Bind(network, addr, _ string) int {
	fmt.Fprintf(os.Stderr, "bind %s %s: Linux only\n", network, addr)
	return 1
}

func Hold(string) int {
	fmt.Fprintln(os.Stderr, "netns: Linux only")
	return 1
}
