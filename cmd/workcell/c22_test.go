// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Regression test for C22 of S-1009 (I13): one --allow value is one host.

package main

import "strings"
import "testing"
import "github.com/omkhar/workcell/v2/internal/policy"

func TestC22AllowFlagWhitespace(t *testing.T) { // I13
	for _, sep := range []string{"\r", " ", "　"} {
		if _, err := allowlist(policy.Policy{Allow: []policy.Entry{{Text: "a.example:443" + sep + "b.example:22"}}}, "config.toml"); err == nil || !strings.Contains(err.Error(), "invalid endpoint") {
			t.Errorf("sep %q: err=%v, want invalid endpoint", sep, err)
		}
	}
}
