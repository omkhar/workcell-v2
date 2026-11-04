// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import "github.com/omkhar/workcell/v2/internal/fileserve"

// openMount serves the directory dir to the guest, live, with limit bytes of growth (I10).
func openMount(dir string, limit int64) (mountService, error) {
	s, err := fileserve.Open(dir, limit)
	if err != nil {
		return nil, err
	}
	return s, nil
}
