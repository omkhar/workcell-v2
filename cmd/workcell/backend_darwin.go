// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package main

import (
	"time"

	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/vmm/vz"
)

// vmmBinary is empty: Virtualization.framework is part of the OS (ADR-001).
const vmmBinary = ""

// mountTable is empty: nothing unprivileged gives a directory a second name beneath another here, and a firmlink is found by inode (within).
func mountTable() ([]byte, error) { return nil, nil }

// probeEvery is how often a session writes to its guest. The framework boots a guest that restarts again, reports no change of state and leaves the channel
// open: only a write from the host then ends it, at once (measured, S-F24). So within two of these a session whose guest restarted ends (I12).
const probeEvery = 2 * time.Second

// newMachine is the macOS backend: the framework, inside this process.
func newMachine(_ artifacts, cfg vmm.Config) vmm.Machine { return vz.New(cfg) }
