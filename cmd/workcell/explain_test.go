// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"strings"
	"testing"
)

func TestExplanation(t *testing.T) {
	tests := []struct {
		name  string
		mount bool
		dir   string
		want  []string // each in the text
		not   []string // none in the text
	}{
		{"clone", false, "/home/me/repo", []string{"workspace: a copy of /home/me/repo", "workcell pull", "workcell diff"}, []string{"--mount", "directly"}},
		{"mount", true, "/home/me/repo", []string{"workspace: /home/me/repo, live (--mount)", "writes directly to the real tree"}, []string{"a copy of"}},
		{"mount names the directory as given", true, "/tmp/with space", []string{"/tmp/with space, live"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := explanation(tc.mount, tc.dir)
			if !strings.HasPrefix(got, "workspace: ") || !strings.HasSuffix(got, "\n") {
				t.Errorf("explanation(%v, %q) = %q: not one labelled line", tc.mount, tc.dir, got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("explanation(%v, %q) = %q: lacks %q", tc.mount, tc.dir, got, w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("explanation(%v, %q) = %q: holds %q", tc.mount, tc.dir, got, n)
				}
			}
		})
	}
}
