// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import "golang.org/x/sys/unix"

// The ioctls that read and write a terminal's settings here.
const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)
