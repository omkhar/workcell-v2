// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Payload runs one escape probe inside the guest, as root, and prints its
// result as a single line for the runner on the host to parse.
//
//	payload <test name> [args...]
package main

import (
	"os"

	"github.com/omkhar/workcell/v2/escape/suite"
)

func main() {
	r := suite.Result{Status: "error", Detail: "usage: payload <test name> [args...]"}
	if len(os.Args) >= 2 {
		if t, ok := suite.Lookup(os.Args[1]); ok {
			r = t.Probe(os.Args[2:])
		} else {
			r.Detail = "unknown test " + os.Args[1]
		}
	}
	os.Stdout.Write(suite.Format(r))
}
