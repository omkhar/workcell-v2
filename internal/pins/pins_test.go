// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package pins

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	hour = time.Hour
	day  = 24 * time.Hour
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// cand is a candidate first published age before now.
func cand(v string, age time.Duration) Candidate {
	return Candidate{Release: Release{Version: v}, Timestamps: []time.Time{now.Add(-age)}}
}

func pin(class Class, v string) Pin {
	return Pin{Name: "tool", Class: class, Release: Release{Version: v}}
}

func with(c Candidate, f func(*Candidate)) Candidate { f(&c); return c }

func skips(reason string, versions ...string) []Skip {
	var s []Skip
	for _, v := range versions {
		s = append(s, Skip{v, reason})
	}
	return s
}

func TestSelect(t *testing.T) {
	guest, trusted := pin(Guest, "1.0.0"), pin(Trusted, "1.0.0")
	adv := &Advisory{ID: "GHSA-test", Introduced: "1.0.0", Fixed: "1.0.1"}
	digest := strings.Repeat("ab", 32)
	withdrawn := guest
	withdrawn.Withdrawn = []string{digest}
	fresh := pin(Guest, "")
	tests := []struct {
		name     string
		pin      Pin
		cands    []Candidate
		adv      *Advisory
		extra    time.Duration
		want     string // chosen version, "" when the pin stays
		skipped  []Skip
		security bool
		err      bool
	}{
		{"cool-off edge: guest exactly 48h", guest, []Candidate{cand("1.1.0", 48*hour)}, nil, 0, "1.1.0", nil, false, false},
		{"cool-off edge: guest one nanosecond short", guest, []Candidate{cand("1.1.0", 48*hour-1)}, nil, 0, "", skips("cooling off", "1.1.0"), false, false},
		{"cool-off edge: trusted exactly 7 days", trusted, []Candidate{cand("1.1.0", 7*day)}, nil, 0, "1.1.0", nil, false, false},
		{"cool-off edge: trusted one nanosecond short", trusted, []Candidate{cand("1.1.0", 7*day-1)}, nil, 0, "", skips("cooling off", "1.1.0"), false, false},
		{"cool-off edge: future timestamp", guest, []Candidate{cand("1.1.0", -1)}, nil, 0, "", skips("timestamp in the future", "1.1.0"), false, false},
		{"cool-off edge: user extra lengthens", guest, []Candidate{cand("1.1.0", 48*hour)}, nil, hour, "", skips("cooling off", "1.1.0"), false, false},
		{"cool-off edge: negative extra never shortens", guest, []Candidate{cand("1.1.0", 47*hour)}, nil, -47 * hour, "", skips("cooling off", "1.1.0"), false, false},
		{"cool-off edge: the largest extra never overflows", guest, []Candidate{cand("1.1.0", hour)}, nil, time.Duration(math.MaxInt64), "", skips("cooling off", "1.1.0"), false, false},
		{"latest-of-timestamps: republished resets cool-off", guest, []Candidate{with(cand("1.1.0", 30*day), func(c *Candidate) {
			c.Timestamps = append(c.Timestamps, now.Add(-hour))
		})}, nil, 0, "", skips("cooling off", "1.1.0"), false, false},
		{"latest-of-timestamps: order does not matter", guest, []Candidate{with(cand("1.1.0", hour), func(c *Candidate) {
			c.Timestamps = append(c.Timestamps, now.Add(-30*day))
		})}, nil, 0, "", skips("cooling off", "1.1.0"), false, false},
		{"latest-of-timestamps: missing timestamp", guest, []Candidate{{Release: Release{Version: "1.1.0"}}}, nil, 0, "", skips("no timestamp", "1.1.0"), false, false},
		{"latest-of-timestamps: zero timestamp is missing", guest, []Candidate{with(cand("1.1.0", 0), func(c *Candidate) {
			c.Timestamps = []time.Time{{}}
		})}, nil, 0, "", skips("no timestamp", "1.1.0"), false, false},
		{"pre-release: suffixes, words and short forms", guest, []Candidate{
			cand("1.2.3-rc.1", 30*day), cand("1.2.3+build", 30*day), cand("2.0.0-0", 30*day), cand("latest", 30*day),
			cand("nightly-2026-11-01", 30*day), cand("1.2", 30*day), cand("V1.2.3", 30*day), cand("1.1.0", 30*day),
			with(cand("1.3.0", 30*day), func(c *Candidate) { c.PreRelease = true }),
		}, nil, 0, "1.1.0", skips("pre-release", "1.2.3-rc.1", "1.2.3+build", "2.0.0-0", "latest", "nightly-2026-11-01", "1.2", "V1.2.3", "1.3.0"), false, false},
		{"pre-release: 1.10.0 above 1.9.0", guest, []Candidate{cand("1.10.0", 30*day), cand("1.9.0", 30*day)}, nil, 0, "1.10.0", nil, false, false},
		{"pre-release: leading v is stable", guest, []Candidate{cand("v1.1.0", 30*day)}, nil, 0, "v1.1.0", nil, false, false},
		{"yanked: skipped for an older stable", guest, []Candidate{with(cand("1.2.0", 30*day), func(c *Candidate) { c.Yanked = true }), cand("1.1.0", 30*day)}, nil, 0, "1.1.0", skips("yanked", "1.2.0"), false, false},
		{"deprecated: skipped", guest, []Candidate{with(cand("1.2.0", 30*day), func(c *Candidate) { c.Deprecated = true })}, nil, 0, "", skips("deprecated", "1.2.0"), false, false},
		{"deprecated: flag off again counts from latest timestamp", guest, []Candidate{with(cand("1.2.0", 30*day), func(c *Candidate) {
			c.Timestamps = append(c.Timestamps, now.Add(-2*hour))
		})}, nil, 0, "", skips("cooling off", "1.2.0"), false, false},
		{"withdrawn digest is not selected", withdrawn, []Candidate{with(cand("1.1.0", 30*day), func(c *Candidate) {
			c.Artifacts = map[string]Artifact{"amd64": {"https://example.test/a", digest}}
		})}, nil, 0, "", skips("withdrawn", "1.1.0"), false, false},
		{"never backwards: newest eligible older than pin", pin(Guest, "2.0.0"), []Candidate{cand("1.9.0", 30*day), cand("2.1.0", hour)}, nil, 0, "", skips("cooling off", "2.1.0"), false, false},
		{"never backwards: pin absent from candidates", pin(Guest, "2.0.0"), []Candidate{cand("1.5.0", 30*day), cand("1.9.0", 30*day)}, nil, 0, "", nil, false, false},
		{"never backwards: pin yanked", pin(Guest, "2.0.0"), []Candidate{with(cand("2.0.0", 30*day), func(c *Candidate) { c.Yanked = true }), cand("1.9.0", 30*day)}, nil, 0, "", nil, false, false},
		{"never backwards: same version stays", guest, []Candidate{cand("1.0.0", 30*day)}, nil, 0, "", nil, false, false},
		{"new row takes the newest eligible", fresh, []Candidate{cand("1.0.0", 30*day), cand("1.1.0", 30*day)}, nil, 0, "1.1.0", nil, false, false},
		{"security lane: guest 12h auto-merges", guest, []Candidate{cand("1.0.1", 12*hour)}, adv, 0, "1.0.1", nil, true, false},
		{"security lane: guest one nanosecond short", guest, []Candidate{cand("1.0.1", 12*hour-1)}, adv, 0, "", skips("cooling off", "1.0.1"), false, false},
		{"security lane: trusted immediate and waiting", trusted, []Candidate{cand("1.0.1", 0)}, adv, 0, "1.0.1", nil, true, false},
		{"security lane: fix only in a pre-release", guest, []Candidate{cand("1.0.1-rc.1", 30*day)}, adv, 0, "", skips("pre-release", "1.0.1-rc.1"), false, false},
		{"security lane: nil advisory means normal cool-off", guest, []Candidate{cand("1.0.1", 13*hour)}, nil, 0, "", skips("cooling off", "1.0.1"), false, false},
		{"security lane: pin below introduced is not affected", pin(Guest, "0.9.0"), []Candidate{cand("1.0.1", 13*hour)}, adv, 0, "", skips("cooling off", "1.0.1"), false, false},
		{"security lane: fixed pin is not affected", pin(Guest, "1.0.1"), []Candidate{cand("1.0.2", 13*hour)}, adv, 0, "", skips("cooling off", "1.0.2"), false, false},
		{"security lane: release below the fix keeps normal cool-off", pin(Guest, "1.0.0"), []Candidate{cand("1.0.1", 13*hour), cand("0.9.9", 30*day)},
			&Advisory{Fixed: "1.0.2"}, 0, "", skips("cooling off", "1.0.1"), false, false},
		{"security lane: the user extra still adds", guest, []Candidate{cand("1.0.1", 12*hour)}, adv, hour, "", skips("cooling off", "1.0.1"), false, false},
		{"unknown class", pin("", "1.0.0"), nil, nil, 0, "", nil, false, true},
		{"pinned version not stable", pin(Guest, "1.0.0-rc.1"), nil, nil, 0, "", nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Select(tt.pin, tt.cands, tt.adv, tt.extra, now)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want error %v", err, tt.err)
			} else if err != nil {
				return
			}
			got := ""
			if r.Chosen != nil {
				got = r.Chosen.Version
			}
			if got != tt.want || (got == "") != (r.Why != "") {
				t.Errorf("chosen %q (why %q), want %q", got, r.Why, tt.want)
			}
			if !slices.Equal(r.Skipped, tt.skipped) {
				t.Errorf("skipped %v, want %v", r.Skipped, tt.skipped)
			}
			auto := got != "" && !(tt.security && tt.pin.Class == Trusted)
			if r.Security != tt.security || r.AutoMerge != auto {
				t.Errorf("security %v auto-merge %v, want %v %v", r.Security, r.AutoMerge, tt.security, auto)
			}
		})
	}
}

// TestFourHourly is an upstream that ships 1.0.i every four hours for ten
// days: the newest cooled release wins, whatever the order upstream lists them in.
func TestFourHourly(t *testing.T) {
	var cands []Candidate
	for i := range 60 {
		cands = append(cands, cand(fmt.Sprintf("1.0.%d", i), time.Duration(59-i)*4*hour))
	}
	reversed := slices.Clone(cands)
	slices.Reverse(reversed)
	tests := []struct {
		name  string
		class Class
		later time.Duration
		want  string
	}{
		{"guest", Guest, 0, "1.0.47"},
		{"guest an hour later", Guest, hour, "1.0.47"},
		{"guest four hours later", Guest, 4 * hour, "1.0.48"},
		{"trusted", Trusted, 0, "1.0.17"},
		{"trusted a day later", Trusted, day, "1.0.23"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, cs := range [][]Candidate{cands, reversed} {
				r, err := Select(pin(tt.class, "0.9.0"), cs, nil, 0, now.Add(tt.later))
				if err != nil || r.Chosen == nil || r.Chosen.Version != tt.want {
					t.Fatalf("got %+v, %v, want %s", r.Chosen, err, tt.want)
				}
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want version
		ok   bool
	}{
		{"1.2.3", version{1, 2, 3}, true},
		{"v0.0.0", version{0, 0, 0}, true},
		{"1.10.0", version{1, 10, 0}, true},
		{"18446744073709551615.0.0", version{1<<64 - 1, 0, 0}, true},
		{"18446744073709551616.0.0", version{}, false},
		{"01.2.3", version{}, false},
		{"1.2.3.4", version{}, false},
		{"1.2.-3", version{}, false},
		{"1.2.+3", version{}, false},
		{" 1.2.3", version{}, false},
		{"vv1.2.3", version{}, false},
		{"1..3", version{}, false},
		{"", version{}, false},
	}
	for _, tt := range tests {
		if got, ok := parseVersion(tt.in); got != tt.want || ok != tt.ok {
			t.Errorf("parseVersion(%q) = %v, %v, want %v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

// FuzzParseVersion checks that every version that parses is in canonical form,
// so two different strings never name the same release.
func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "v0.0.0", "1.2.3-rc.1", "01.2.3", "18446744073709551616.0.0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := parseVersion(s); ok && fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) != strings.TrimPrefix(s, "v") {
			t.Fatalf("parseVersion(%q) = %v is not canonical", s, v)
		}
	})
}
