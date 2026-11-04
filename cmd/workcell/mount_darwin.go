// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package main

import "errors"

// openMount has no file service here yet: internal/fileserve runs on Linux (ADR-005).
func openMount(string, int64) (mountService, error) {
	return nil, errors.New("--mount is not available on macOS yet; run without it for a copy of the directory")
}
