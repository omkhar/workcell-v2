// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package main

import "golang.org/x/sys/unix"

// The ioctls that read and write a terminal's settings here.
const (
	termiosGet = unix.TIOCGETA
	termiosSet = unix.TIOCSETA
)
