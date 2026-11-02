// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import "errors"

// The I10 judges read the host's load from /proc, so they run on a Linux
// host. A macOS host gets an error, never a pass.
var errLinuxHost = errors.New("reading the host's load is Linux only")

func hostProcs() (int64, error)        { return 0, errLinuxHost }
func hostMemAvailable() (int64, error) { return 0, errLinuxHost }
func hostFiles() (int64, error)        { return 0, errLinuxHost }
func hostBusy() (int64, error)         { return 0, errLinuxHost }
func hostDiskFree() (int64, error)     { return 0, errLinuxHost }
func helperAlive(int) (bool, error)    { return false, errLinuxHost }
