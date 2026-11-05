// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux && !(darwin && cgo)

package suite

import "errors"

// The I10 judges read the host's load from /proc on Linux and from Mach on
// a Mac with cgo. Any other host gets an error, never a pass.
var errLinuxHost = errors.New("reading the host's load is Linux or macOS with cgo only")

func hostProcs() (int64, error)        { return 0, errLinuxHost }
func hostMemAvailable() (int64, error) { return 0, errLinuxHost }
func hostFiles() (int64, error)        { return 0, errLinuxHost }
func hostBusy() (int64, error)         { return 0, errLinuxHost }
func hostDiskFree() (int64, error)     { return 0, errLinuxHost }
func helperAlive(int) (bool, error)    { return false, errLinuxHost }
func processGroup(int) (int, error)    { return 0, errLinuxHost }
func descendants(int) ([]int, error)   { return nil, errLinuxHost }
func groupMembers(int) ([]int, error)  { return nil, errLinuxHost }
