// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

// icmpProbe runs only in a Linux guest.
func icmpProbe([]string) Result {
	return Result{Status: "error", Detail: "the ICMP probe is Linux only"}
}
