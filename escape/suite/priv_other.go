// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"fmt"
	"os"
)

// Bind, Hold and Routed are the payload's privileged verbs, on Linux only.
func Bind(network, addr, _ string) int {
	fmt.Fprintf(os.Stderr, "bind %s %s: Linux only\n", network, addr)
	return 1
}
func Hold(string, bool) int { fmt.Fprintln(os.Stderr, "netns: Linux only"); return 1 }
func Routed() int           { fmt.Fprintln(os.Stderr, "routed: Linux only"); return 1 }

var linuxRows []Test // the rows that need Hold's on-link layout, which this host has no way to lay out (priv_linux.go)
