// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !(darwin && arm64)

// Command krunchild needs libkrun's macOS build and Apple silicon.
package main

func main() {}
