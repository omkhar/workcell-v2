// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Smallest and largest guest this build will start. 128 MiB is what the kernel, the
// initramfs the init runs from and a Go init need to come up with a little room to spare; the
// 32 vCPUs are Firecracker's own limit, said here so that the denial is ours and clear (I10).
const (
	minMemoryMiB = 128
	maxCPUs      = 32
)

// limits are the resource caps of one session. DiskMiB 0 means no cap.
type limits struct{ CPUs, MemoryMiB, DiskMiB int }

// parseSize reads a size such as "256MiB" or "4GiB" (the spelling of SPEC section 5) into
// whole MiB. Digits alone count as MiB. It never returns zero without an error.
func parseSize(s string) (int, error) {
	digits, unit := s, "MiB"
	for _, u := range []string{"MiB", "GiB"} {
		if d, ok := strings.CutSuffix(s, u); ok {
			digits, unit = d, u
		}
	}
	n, err := strconv.ParseUint(digits, 10, 32) // digits only: no sign, no space, no fraction
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a size: use a whole number with MiB or GiB, such as 256MiB or 4GiB", s)
	}
	if unit == "GiB" {
		n *= 1024
	}
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return int(n), nil
}

// cmdline is what the init is told on the kernel command line. The disk size is a courtesy to
// the guest, so that it sees ENOSPC at the cap; the memory cap above is what holds on the host (A1).
func (l limits) cmdline() string {
	if l.DiskMiB == 0 {
		return "root=/dev/vda ro"
	}
	return "root=/dev/vda ro workcell.disk=" + strconv.Itoa(l.DiskMiB)
}

// defaults are run's caps when no flag is given, for the verbs that take none.
func defaults() limits {
	l, _, _, _ := parseRun([]string{"true"}, io.Discard)
	return l
}

// parseRun splits the arguments of `workcell run` into caps, the workspace mode and the
// command. Flags come before the command, and -- ends them. mount is true for `--mount`: the
// guest's /workspace is the current directory itself, live, instead of a copy (A5, ADR-005).
// A bad invocation is reported on stderr, and ok is false.
func parseRun(args []string, stderr io.Writer) (l limits, mount bool, argv []string, ok bool) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usage := func() {
		fmt.Fprintln(stderr, "usage: workcell run [--mount] [--cpus N] [--memory SIZE] [--disk SIZE] [--] <cmd> [args...]")
	}
	fs.Usage = func() { usage(); fs.PrintDefaults() }
	live := fs.Bool("mount", false, "serve the current directory itself into the guest, live, instead of a copy")
	cpus := fs.Int("cpus", 2, "virtual CPUs for the guest")
	memory := fs.String("memory", "1GiB", "guest memory, such as 512MiB or 4GiB")
	disk := fs.String("disk", "", "cap on what the guest may write, such as 20GiB (default: only the memory cap)")
	if err := fs.Parse(args); err != nil {
		return l, false, nil, false
	}
	fail := func(err error) (limits, bool, []string, bool) {
		fmt.Fprintln(stderr, "workcell run:", err)
		return l, false, nil, false
	}
	if *cpus < 1 || *cpus > maxCPUs {
		return fail(fmt.Errorf("--cpus must be between 1 and %d", maxCPUs))
	}
	l.CPUs = *cpus
	var err error
	if l.MemoryMiB, err = parseSize(*memory); err != nil {
		return fail(fmt.Errorf("--memory: %w", err))
	}
	if l.MemoryMiB < minMemoryMiB {
		return fail(fmt.Errorf("--memory must be at least %d MiB: the guest cannot boot with less", minMemoryMiB))
	}
	if *disk != "" {
		if l.DiskMiB, err = parseSize(*disk); err != nil {
			return fail(fmt.Errorf("--disk: %w", err))
		}
	}
	if fs.NArg() == 0 {
		usage()
		return l, false, nil, false
	}
	return l, *live, fs.Args(), true
}
