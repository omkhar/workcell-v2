// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package firecracker is the Linux backend of ADR-001: the supervisor execs the
// pinned Firecracker binary as a child that dies with it (A9). The code builds
// on Linux only; this file keeps the package visible to every build.
package firecracker
