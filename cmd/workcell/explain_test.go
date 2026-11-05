// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/policy"
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

// TestReach: the network text names where the policy came from, each name once with how it is
// reached, and says that all else is refused; an empty policy says there is no network.
func TestReach(t *testing.T) {
	list := func(texts ...string) policy.Policy {
		var p policy.Policy
		for _, s := range texts {
			p.Allow = append(p.Allow, policy.Entry{Text: s})
		}
		return p
	}
	tests := []struct {
		name          string
		exists, flags bool
		allow         policy.Policy
		want          string
	}{
		{"no file, no flag", false, false, list(), "network: no config file at /c/config.toml\n  The guest has no network.\n"},
		{"names from the file", true, false, list("b.example", "a.example", "z.example:8443", "m.example:22"),
			"network: from /c/config.toml\n  https://a.example  (443, terminated by the session proxy)\n  https://b.example  (443, terminated by the session proxy)\n" +
				"  m.example:22  (tcp, forwarded as is)\n  z.example:8443  (tcp, forwarded as is)\n  Everything else is refused, and DNS answers only these names.\n"},
		{"a flag and no file", false, true, list("npm.example"),
			"network: no config file at /c/config.toml and --allow\n  https://npm.example  (443, terminated by the session proxy)\n  Everything else is refused, and DNS answers only these names.\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := allowlist(tc.allow, "/c/config.toml")
			if err != nil {
				t.Fatal(err)
			}
			if got := reach("/c/config.toml", tc.exists, tc.flags, a); got != tc.want {
				t.Errorf("reach = %q, want %q", got, tc.want)
			}
		})
	}
}
