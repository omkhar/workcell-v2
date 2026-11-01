// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package version holds the build version.
package version

// Version is set at build time with -ldflags "-X .../internal/version.Version=v2.x.y".
var Version = "v2-dev"

// String returns the line that "workcell --version" prints.
func String() string { return "workcell " + Version }
