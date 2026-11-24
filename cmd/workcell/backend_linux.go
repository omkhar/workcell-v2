// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"os"

	"github.com/omkhar/workcell/v2/internal/vmm"
	fc "github.com/omkhar/workcell/v2/internal/vmm/firecracker"
)

// mountTable is the kernel's own list of the mounts this process sees, for holds() to find a second name of workcell's directory (C65).
func mountTable() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// vmmBinary is the pinned VMM the data directory must hold here: Firecracker (ADR-001).
const vmmBinary = "firecracker"

// probeEvery is zero, never: a guest that restarts ends Firecracker (reboot=k), and the channel with it.
const probeEvery = 0

// newMachine is the Linux backend: Firecracker, a child of this process.
func newMachine(a artifacts, c vmm.Config) vmm.Machine { c.Binary = a.binary; return fc.New(c) }
