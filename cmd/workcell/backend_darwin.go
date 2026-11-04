// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package main

import (
	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/vmm/vz"
)

// vmmBinary is empty: Virtualization.framework is part of the OS (ADR-001).
const vmmBinary = ""

// newMachine is the macOS backend: the framework, inside this process.
func newMachine(_ artifacts, cfg vmm.Config) vmm.Machine { return vz.New(cfg) }
