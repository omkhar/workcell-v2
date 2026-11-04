// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package vz is the macOS arm64 backend of ADR-001: Virtualization.framework,
// driven in the supervisor's own process through github.com/Code-Hex/vz, so
// the VM dies with the supervisor (A9). The code builds on darwin/arm64 with
// cgo only; this file keeps the package visible to every build.
package vz
