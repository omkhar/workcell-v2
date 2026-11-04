// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package bump is the daily bump of pins/: it plans each pin's next release,
// verifies it, and opens at most one pull request per class through GitHub's
// REST API, and merges a bump pull request once the gate is green (B5, B6, B13).
// It prints only templated fields, never text an upstream or the API sent.
package bump

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/internal/advisory"
	"github.com/omkhar/workcell/v2/internal/artifact"
	"github.com/omkhar/workcell/v2/internal/pins"
)

// Refused is hostile data: the run stops before it writes or posts anything more.
type Refused string

func (r Refused) Error() string { return "refused: " + string(r) }

// Stopped is a failed step: never read as "nothing to do".
type Stopped string

func (s Stopped) Error() string { return "stopped: " + string(s) }

// securityNote marks a trusted security bump in the pull request it opens with,
// so the tool never merges it (B4), even if adding the label failed.
const securityNote = "security: an advisory affects the pinned version and this release fixes it"

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	classes   = []pins.Class{pins.Guest, pins.Trusted}
)

// NameOK reports whether s may name a pin and its file pins/<s>.json.
func NameOK(s string) bool { return nameRE.MatchString(s) && !strings.Contains(s, "..") }

// VersionOK reports whether s may stand in a row, a branch-free title or a body.
func VersionOK(s string) bool { return versionRE.MatchString(s) }

// PathOK reports whether a changed path is exactly pins/<name>.json (B6).
func PathOK(p string) bool {
	rest, ok := strings.CutPrefix(p, "pins/")
	name, ok2 := strings.CutSuffix(rest, ".json")
	return ok && ok2 && NameOK(name)
}

// Tool is one run. Upstream fetches listings, artifacts and advisories; OSV is
// the advisory database; PinTime bounds the planning of one pin (W8); Now is
// the clock Select reads.
type Tool struct {
	Pins     string
	Upstream *http.Client
	OSV      string
	PinTime  time.Duration
	GitHub   GitHub
	DryRun   bool
	Now      time.Time
	Out      io.Writer
}

// Change is a pin that moves, and the row it moves to. Security marks a
// trusted security bump, which waits for the maintainer (B4).
type Change struct {
	Old, New pins.Pin
	Security bool
}

// Load reads every row of dir, sorted by name. A file or pin name outside the
// grammar, a class other than guest or trusted, or a bad version is refused.
func Load(dir string) ([]pins.Pin, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, Stopped("read pins")
	}
	var ps []pins.Pin
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !NameOK(name) || !e.Type().IsRegular() {
			return nil, Refused("pin name")
		}
		var p pins.Pin
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || json.Unmarshal(b, &p) != nil {
			return nil, Stopped("read pins")
		}
		switch {
		case p.Name != name:
			return nil, Refused("pin name")
		case !slices.Contains(classes, p.Class):
			return nil, Refused("class")
		case p.Version != "" && !VersionOK(p.Version):
			return nil, Refused("version")
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// Run plans every pin, then opens issues, merges and opens pull requests.
func (t Tool) Run(ctx context.Context) error {
	ps, err := Load(t.Pins)
	if err != nil {
		return err
	}
	if t.DryRun {
		fmt.Fprintln(t.Out, "dry-run: nothing is posted or written")
	}
	changes := map[pins.Class][]Change{}
	var failed []string
	for _, p := range ps {
		c, token, err := t.plan(ctx, p)
		if err != nil {
			return err
		}
		fmt.Fprintln(t.Out, p.Name, p.Class, cmp.Or(p.Version, "-"), cmp.Or(c.New.Version, "none"), token)
		switch {
		case token == "verify-failed":
			failed = append(failed, p.Name)
		case token == "eligible":
			changes[p.Class] = append(changes[p.Class], c)
		}
	}
	g := t.GitHub
	for _, name := range failed {
		if err := t.issue(ctx, name); err != nil {
			return err
		}
	}
	open := map[pins.Class]bool{}
	if g.Repo != "" || !t.DryRun {
		prs, err := list[pull](ctx, g, "list pull requests", g.url("/pulls?state=open&base=main&per_page=100"))
		if err != nil {
			return err
		}
		for _, pr := range prs {
			if class, ok := g.class(pr); ok && !open[class] {
				open[class] = true
				if err := t.merge(ctx, pr.Number); err != nil {
					return err
				}
			}
		}
	}
	for _, class := range classes {
		switch {
		case open[class]:
			fmt.Fprintln(t.Out, "already open:", class)
		case len(changes[class]) > 0 && t.DryRun:
			fmt.Fprintln(t.Out, "would open pull request:", class)
		case len(changes[class]) > 0:
			if err := t.propose(ctx, class, changes[class]); err != nil {
				return err
			}
		}
	}
	return nil
}

// plan decides one pin. Only a hostile chosen version is an error; anything an
// upstream fails at is a reason token, so one upstream never blocks the rest (W8).
func (t Tool) plan(ctx context.Context, p pins.Pin) (Change, string, error) {
	ctx, cancel := context.WithTimeout(ctx, t.PinTime)
	defer cancel()
	cands, err := pins.Candidates(ctx, t.Upstream, p)
	if err != nil {
		return Change{}, "source-error", nil
	}
	adv, err := advisory.Lookup(ctx, t.Upstream, t.OSV, p)
	if err != nil {
		fmt.Fprintln(t.Out, "advisory unavailable:", p.Name)
	}
	r, err := pins.Select(p, cands, adv, 0, t.Now)
	switch {
	case err != nil:
		return Change{}, "not-semver", nil
	case r.Chosen == nil && len(r.Skipped) == 0:
		return Change{}, "backwards", nil
	case r.Chosen == nil && r.Skipped[0].Reason == "cooling off":
		return Change{}, "cool-off", nil
	case r.Chosen == nil:
		return Change{}, strings.ReplaceAll(r.Skipped[0].Reason, " ", "-"), nil
	case !VersionOK(r.Chosen.Version):
		return Change{}, "", Refused("version")
	}
	rel, err := artifact.Verifier{Client: t.Upstream}.Verify(ctx, p, *r.Chosen)
	if err != nil { // no fall-through to an older release (B5)
		return Change{Old: p, New: pins.Pin{Release: pins.Release{Version: r.Chosen.Version}}}, "verify-failed", nil
	}
	n := p
	n.Release, n.Previous, n.Timestamps, n.Released = rel, &p.Release, r.Chosen.Timestamps, t.Now.UTC().Truncate(time.Second)
	return Change{Old: p, New: n, Security: !r.AutoMerge}, "eligible", nil
}

// Row is the file a pin is stored in: the same bytes as pins/debian.json.
func Row(p pins.Pin) []byte {
	b, _ := json.MarshalIndent(p, "", "  ")
	return append(b, '\n')
}

// body is the pull request's text: templated fields only.
func body(cs []Change, now time.Time) string {
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "- %s: %s to %s, age %dh", c.Old.Name, cmp.Or(c.Old.Version, "-"), c.New.Version,
			int(now.Sub(slices.MaxFunc(append(c.New.Timestamps, time.Time{}), time.Time.Compare)).Hours()))
		if c.Security {
			b.WriteString(", " + securityNote) // the merge reads it if the label is lost
		}
		b.WriteString("\n")
		for _, arch := range slices.Sorted(maps.Keys(c.New.Artifacts)) {
			fmt.Fprintf(&b, "  - %s sha256 %s\n", arch, c.New.Artifacts[arch].SHA256)
		}
	}
	return b.String()
}
