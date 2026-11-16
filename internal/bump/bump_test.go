// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package bump

import (
	"cmp"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

func TestGrammar(t *testing.T) {
	check := func(name, version, row bool, ss ...string) { // NameOK(s), VersionOK(s), PathOK("pins/"+s+".json")
		for _, s := range ss {
			if NameOK(s) != name || VersionOK(s) != version || PathOK("pins/"+s+".json") != row {
				t.Errorf("%q: name %v version %v row %v, want %v %v %v", s, NameOK(s), VersionOK(s), PathOK("pins/"+s+".json"), name, version, row)
			}
		}
	}
	check(true, true, true, "debian", "claude-code.v2_x", strings.Repeat("a", 64), "trixie-20261027-slim")
	check(false, true, false, "1.2.3+build", "Debian", "a..b")
	check(false, false, false, strings.Repeat("a", 65), "", ".x", "-x", "../x", "../.github/workflows/x", "/etc/x", `..\x`, "a/b", "x\x00", "x\ny",
		"1.2.3\n", "${{ github.token }}", "`id`", "[x](http://evil)", "<b>", "@omkhar", "https://evil.example/x", strings.Repeat("1", 4096))
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
	check := func(name string, ok bool, changed int, files ...file) {
		if got := FilesOK(files, changed); got != ok {
			t.Errorf("%s: %v, want %v", name, got, ok)
		}
	}
	check("a modified row", true, 1, row)
	check("an added row", true, 1, added)
	check("two rows", true, 2, row, added)
	check("a row and a workflow", false, 2, row, file{".github/workflows/ci.yml", "modified", "@@ -1 +1 @@\n+x"})
	check("a row and go.mod", false, 2, row, file{"go.mod", "modified", "@@ -1 +1 @@\n+x"})
	check("none listed, one changed", false, 1)
	check("none at all", false, 0)
	check("fewer listed than changed", false, 2, row)
	check("renamed", false, 1, file{"pins/x.json", "renamed", "@@ -1 +1 @@\n+x"})
	check("removed", false, 1, file{"pins/x.json", "removed", "@@ -1 +0,0 @@\n-x"})
	check("changed type", false, 1, file{"pins/x.json", "changed", "@@ -1 +1 @@\n+x"})
	check("a symbolic link", false, 1, file{"pins/x.json", "added", "@@ -0,0 +1 @@\n+../.github/workflows/x\n\\ No newline at end of file"})
	check("no patch", false, 1, file{"pins/x.json", "modified", ""})
}

func TestGreen(t *testing.T) {
	const sha = "abc"
	ok := func(name string) checkRun { return checkRun{name, "completed", "success", sha} }
	check := func(name string, green bool, total int, runs ...checkRun) { // total 0: len(runs)
		if got := Green(runs, cmp.Or(total, len(runs)), sha); got != green {
			t.Errorf("%s: %v, want %v", name, got, green)
		}
	}
	check("gate green", true, 0, ok("gate"))
	check("gate and guard green", true, 0, ok("guard"), ok("gate"))
	check("no runs", false, 0)
	check("gate absent, gate-macos green", false, 0, ok("gate-macos"))
	check("gate with a trailing space", false, 0, ok("gate "))
	check("Gate", false, 0, ok("Gate"))
	check("gate (amd64)", false, 0, ok("gate (amd64)"))
	check("two gates, one failed", false, 0, ok("gate"), checkRun{"gate", "completed", "failure", sha})
	check("gate green on another head", false, 0, checkRun{"gate", "completed", "success", "def"})
	check("another run queued", false, 0, ok("gate"), checkRun{"guard", "queued", "", sha})
	check("another run in progress", false, 0, ok("gate"), checkRun{"guard", "in_progress", "", sha})
	check("more runs than listed", false, 2, ok("gate"))
	for _, c := range []string{"skipped", "neutral", "cancelled", "timed_out", "action_required", "stale", "failure", ""} {
		check("gate "+c, false, 0, checkRun{"gate", "completed", c, sha})
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
