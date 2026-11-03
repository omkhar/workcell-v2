// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// benchStart boots the guest once untimed, so that what follows is a warm start, then
// benchSamples times. A sample runs from just before the VMM starts to the guest's connection.
// It runs nothing in the guest, and each VM is gone before the next boots (the CID is fixed).
func benchStart(stdout, stderr io.Writer) int {
	dir, err := dataDir()
	var a artifacts
	if err == nil {
		a, err = findArtifacts(dir)
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell:", err)
		return 1
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	caps := defaults()
	var samples []time.Duration
	for i := 0; i <= benchSamples; i++ { // boot 0 is the warm-up
		b, code, err := boot(a, caps, sigs, "")
		if b == nil {
			if err != nil {
				fmt.Fprintln(stderr, "workcell:", err)
				return 1
			}
			return code // interrupted
		}
		b.close()
		if i > 0 {
			samples = append(samples, b.took)
		}
	}
	fmt.Fprintln(stdout, benchLine(samples))
	return 0
}
