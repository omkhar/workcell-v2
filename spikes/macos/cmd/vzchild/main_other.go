// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !(darwin && arm64 && cgo)

// Command vzchild needs Virtualization.framework, cgo and Apple silicon.
package main

func main() {}
