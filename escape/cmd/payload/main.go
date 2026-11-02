// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Payload runs one escape probe inside the guest, as root, and prints its
// result as a single line for the runner on the host to parse. It is also
// every helper of the control sandbox (SPEC T2), which enforces nothing.
//
//	payload <test name> [args...]
//	payload supervisor <unix socket path>
package main

import (
	"os"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	"github.com/omkhar/workcell/v2/escape/suite"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "supervisor" {
		sandbox.ControlSupervisor(os.Args[2])
		os.Exit(1)
	}
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
