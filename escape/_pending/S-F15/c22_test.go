// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Waits for S-F15 (C22 of S-1009): move to cmd/workcell/c22_test.go.

package main

import "strings"
import "testing"
import "github.com/omkhar/workcell/v2/internal/policy"

func TestC22AllowFlagWhitespace(t *testing.T) { // I13
	if _, err := allowlist(policy.Policy{Allow: []policy.Entry{{Text: "a.example:443\rb.example:22"}}}, "config.toml"); err == nil || !strings.Contains(err.Error(), "invalid endpoint") {
		t.Errorf("err=%v, want invalid endpoint", err)
	}
}
