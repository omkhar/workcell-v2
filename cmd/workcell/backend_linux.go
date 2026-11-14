// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"github.com/omkhar/workcell/v2/internal/vmm"
	fc "github.com/omkhar/workcell/v2/internal/vmm/firecracker"
)

// vmmBinary is the pinned VMM the data directory must hold here: Firecracker (ADR-001).
const vmmBinary = "firecracker"

// newMachine is the Linux backend: Firecracker, a child of this process.
func newMachine(a artifacts, c vmm.Config) vmm.Machine { c.Binary = a.binary; return fc.New(c) }
