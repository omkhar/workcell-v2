// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Payload runs one escape probe inside the guest, as root, and prints its
// result as a single line for the runner on the host to parse. It is also
// every helper of the control sandbox (SPEC T2), a process that enforces
// nothing and whose death changes nothing.
//
// And it is the judge's hand on the test host for what needs root there
// (suite.Bind), run through sudo, and the holder of a session's own network
// namespace (suite.Hold).
//
//	payload <test name> [args...]
//	payload helper <name>
//	payload bind <network> <address> <unix socket>
//	payload netns <unix socket> <address>
package main

import (
	"os"
	"time"

	"github.com/omkhar/workcell/v2/escape/suite"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "helper" {
		for { // not select {}: with no other goroutine the runtime calls that a deadlock and exits
			time.Sleep(time.Hour)
		}
	}
	if len(os.Args) == 5 && os.Args[1] == "bind" {
		os.Exit(suite.Bind(os.Args[2], os.Args[3], os.Args[4]))
	}
	if len(os.Args) == 4 && os.Args[1] == "netns" {
		os.Exit(suite.Hold(os.Args[2], os.Args[3]))
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
