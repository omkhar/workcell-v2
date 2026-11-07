// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package bump

import (
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

func TestGrammar(t *testing.T) {
	check := func(s string, name, version, row bool) { // NameOK(s), VersionOK(s), PathOK("pins/"+s+".json")
		if NameOK(s) != name || VersionOK(s) != version || PathOK("pins/"+s+".json") != row {
			t.Errorf("%q: name %v version %v row %v, want %v %v %v", s, NameOK(s), VersionOK(s), PathOK("pins/"+s+".json"), name, version, row)
		}
	}
	for _, s := range []string{"debian", "claude-code.v2_x", strings.Repeat("a", 64), "trixie-20261027-slim"} {
		check(s, true, true, true)
	}
	check("1.2.3+build", false, true, false)
	check("Debian", false, true, false)
	check("a..b", false, true, false)
	for _, s := range []string{strings.Repeat("a", 65), "", ".x", "-x", "../x", "../.github/workflows/x", "/etc/x", `..\x`, "a/b", "x\x00", "x\ny",
		"1.2.3\n", "${{ github.token }}", "`id`", "[x](http://evil)", "<b>", "@omkhar", "https://evil.example/x", strings.Repeat("1", 4096)} {
		check(s, false, false, false)
	}
}

func TestPathOK(t *testing.T) {
	for _, p := range []string{"pins/../x", "Pins/x.json", "pins", "pins/", "pinsx/y.json", "./pins/x.json", "pins//x.json",
		`pins\x.json`, "pins/sub/x.json", "pins/x.yaml", "pins/x.json/", "pins/.json", ".github/workflows/ci.yml", "go.mod", "escape/enforced.txt"} {
		if PathOK(p) {
			t.Errorf("%q passes", p)
		}
	}
}

func TestFilesOK(t *testing.T) {
	row := file{"pins/x.json", "modified", "@@ -1 +1 @@\n-a\n+b"}
	added := file{"pins/y.json", "added", "@@ -0,0 +1,3 @@\n+{\n+}"}
	cases := []struct {
		name    string
		files   []file
		changed int
		ok      bool
	}{
		{"a modified row", []file{row}, 1, true},
		{"an added row", []file{added}, 1, true},
		{"two rows", []file{row, added}, 2, true},
		{"a row and a workflow", []file{row, {".github/workflows/ci.yml", "modified", "@@ -1 +1 @@\n+x"}}, 2, false},
		{"a row and go.mod", []file{row, {"go.mod", "modified", "@@ -1 +1 @@\n+x"}}, 2, false},
		{"none listed, one changed", nil, 1, false},
		{"none at all", nil, 0, false},
		{"fewer listed than changed", []file{row}, 2, false},
		{"renamed", []file{{"pins/x.json", "renamed", "@@ -1 +1 @@\n+x"}}, 1, false},
		{"removed", []file{{"pins/x.json", "removed", "@@ -1 +0,0 @@\n-x"}}, 1, false},
		{"changed type", []file{{"pins/x.json", "changed", "@@ -1 +1 @@\n+x"}}, 1, false},
		{"a symbolic link", []file{{"pins/x.json", "added", "@@ -0,0 +1 @@\n+../.github/workflows/x\n\\ No newline at end of file"}}, 1, false},
		{"no patch", []file{{"pins/x.json", "modified", ""}}, 1, false},
	}
	for _, tc := range cases {
		if got := FilesOK(tc.files, tc.changed); got != tc.ok {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestGreen(t *testing.T) {
	const sha = "abc"
	ok := func(name string) checkRun { return checkRun{name, "completed", "success", sha} }
	cases := []struct {
		name  string
		runs  []checkRun
		total int // -1: len(runs)
		green bool
	}{
		{"gate green", []checkRun{ok("gate")}, -1, true},
		{"gate and guard green", []checkRun{ok("guard"), ok("gate")}, -1, true},
		{"no runs", nil, -1, false},
		{"gate absent, gate-macos green", []checkRun{ok("gate-macos")}, -1, false},
		{"gate with a trailing space", []checkRun{ok("gate ")}, -1, false},
		{"Gate", []checkRun{ok("Gate")}, -1, false},
		{"gate (amd64)", []checkRun{ok("gate (amd64)")}, -1, false},
		{"two gates, one failed", []checkRun{ok("gate"), {"gate", "completed", "failure", sha}}, -1, false},
		{"gate green on another head", []checkRun{{"gate", "completed", "success", "def"}}, -1, false},
		{"another run queued", []checkRun{ok("gate"), {"guard", "queued", "", sha}}, -1, false},
		{"another run in progress", []checkRun{ok("gate"), {"guard", "in_progress", "", sha}}, -1, false},
		{"more runs than listed", []checkRun{ok("gate")}, 2, false},
	}
	for _, c := range []string{"skipped", "neutral", "cancelled", "timed_out", "action_required", "stale", "failure", ""} {
		cases = append(cases, struct {
			name  string
			runs  []checkRun
			total int
			green bool
		}{"gate " + c, []checkRun{{"gate", "completed", c, sha}}, -1, false})
	}
	for _, tc := range cases {
		total := tc.total
		if total < 0 {
			total = len(tc.runs)
		}
		if got := Green(tc.runs, total, sha); got != tc.green {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.green)
		}
	}
}

// TestBody: the pull request body holds templated fields only, never what
// upstream wrote about a release.
func TestBody(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c := Change{Security: true,
		Old: pins.Pin{Name: "x", Release: pins.Release{Version: "1.2.0"}},
		New: pins.Pin{Name: "x", Release: pins.Release{Version: "1.3.0", Artifacts: map[string]pins.Artifact{
			"arm64": {URL: "https://evil.example/[x](http://evil)", SHA256: "bb"}, "amd64": {SHA256: "aa"}}},
			Timestamps: []time.Time{now.Add(-50 * time.Hour), now.Add(-49 * time.Hour)}}}
	want := "- x: 1.2.0 to 1.3.0, age 49h, security: an advisory affects the pinned version and this release fixes it\n" +
		"  - amd64 sha256 aa\n  - arm64 sha256 bb\n"
	if got := body([]Change{c}, now); got != want {
		t.Errorf("body\n%q, want\n%q", got, want)
	}
}
