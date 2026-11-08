// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package pins holds the data model of an upstream pin (B1, B2) and the
// stateless selector that decides which release a pin moves to (B3, B4).
package pins

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Class decides a pin's cool-off (B2).
type Class string

const (
	Guest   Class = "guest"   // anything that runs only inside the guest, such as a provider CLI
	Trusted Class = "trusted" // Go modules, actions, the VMM, the guest kernel, the base image and build tools
)

// Source is the kind of place an upstream publishes in. Adding an upstream of a
// known source is one row and no code (B15).
type Source string

const (
	NPM            Source = "npm"             // an npm registry package document
	GitHubReleases Source = "github-releases" // the releases of a GitHub repository
	VendorManifest Source = "vendor-manifest" // a release manifest the vendor serves
	OCI            Source = "oci"             // an image in an OCI registry, pinned by digest
)

// Artifact is the file of a release for one architecture.
type Artifact struct {
	URL       string // the https URL the client fetches on the host (B8)
	SHA256    string // 64 lowercase hex digits, computed from the downloaded file (B5)
	Integrity string // the npm SRI of the tarball, "sha512-<base64>", as the registry publishes it
	Bundle    string // the https URL of the Sigstore bundle asset that Signing.Bundles names
}

// Signing says what upstream signs and how (B5). The zero value means upstream
// signs nothing, so only its published digests are checked.
type Signing struct {
	Identity string            // the Fulcio SAN; the literal {version} stands for the release version
	Issuer   string            // the OIDC issuer the certificate names
	Bundles  map[string]string // architecture to the GitHub release asset that holds the Sigstore bundle
	Members  map[string]string // architecture to the member of the gzip tarball the bundle signs; unset: the asset itself
}

// Release is a version as upstream writes it, and its artifacts keyed by
// architecture ("amd64", "arm64").
type Release struct {
	Version   string
	Artifacts map[string]Artifact
}

// Package names a package as the advisory database does: the OSV ecosystem and
// name, both case-sensitive.
type Package struct{ Ecosystem, Name string }

// Pin is one row of pins/ (B1).
type Pin struct {
	Name   string // the upstream, such as "claude"
	Class  Class
	Source Source
	// Locator is the https URL of the upstream's listing: the npm package document,
	// the GitHub releases API URL, the vendor release root, or the OCI repository
	// API root, https://registry/v2/name (see sources.go).
	Locator string
	// TagPrefix and TagSuffix: the GitHub releases and OCI sources read only tags that start and end with them; the rest is the version. The GitHub source strips
	// the prefix. Empty means every tag.
	TagPrefix, TagSuffix string `json:",omitempty"`
	// Package is the pin's name in the advisory database. Empty means the pin has
	// no advisory feed, so the security lane never opens for it (B4).
	Package Package
	// Assets maps an architecture to the GitHub asset name or the vendor manifest
	// platform key of that architecture. The npm and OCI sources need none.
	Assets  map[string]string
	Signing Signing
	Release
	Timestamps []time.Time // every timestamp upstream publishes for the pinned release
	Released   time.Time   // when this version was selected; B10's cool-off and the manifest count from it
	Previous   *Release    // the version pinned before this one, one deep: the manifest's previous
	Withdrawn  []string    // SHA-256 digests the maintainer withdrew; none is selected again
}

// Candidate is one release as upstream lists it. The source sets the flags;
// the selector only honours them.
type Candidate struct {
	Release
	PreRelease bool        // upstream marks it a pre-release or a draft
	Deprecated bool        // upstream marks it deprecated
	Timestamps []time.Time // every timestamp upstream publishes for it, in any order
}

// Advisory is a published advisory: it affects every version from Introduced
// up to, not including, Fixed.
type Advisory struct {
	ID         string // the advisory's identifier, such as a GHSA ID
	Introduced string // the first affected version; empty means every version below Fixed
	Fixed      string // the first version that is not affected
}

// Skip is a release newer than the pin that the selector did not take.
type Skip struct {
	Version string
	Reason  string
}

// Result is what the selector decided.
type Result struct {
	Chosen    *Candidate // the release to pin; nil when the pin stays
	Skipped   []Skip     // releases newer than the pin that are not eligible, in input order
	Security  bool       // the advisory affects the pin and Chosen fixes it (B4)
	AutoMerge bool       // the bump may merge once the gate is green; false when it waits for the maintainer
	Since     time.Time  // when the oldest eligible release was published
}

// Cooloff holds the normal and the security-lane cool-off of each class.
var Cooloff = map[Class][2]time.Duration{
	Guest:   {48 * time.Hour, 12 * time.Hour},
	Trusted: {7 * 24 * time.Hour, 0},
}

// Select picks the newest stable release that is not a pre-release,
// deprecated or withdrawn, and whose latest timestamp is at least the cool-off
// before now. extra lengthens the cool-off and never shortens it (B10). A pin
// never moves backwards. It reads nothing but its arguments (B3).
func Select(cur Pin, cands []Candidate, adv *Advisory, extra time.Duration, now time.Time) (Result, error) {
	cool, ok := Cooloff[cur.Class]
	if !ok {
		return Result{}, fmt.Errorf("pin %q: unknown class %q", cur.Name, cur.Class)
	}
	curV, hasCur := cur.version(cur.Version)
	if !hasCur && cur.Version != "" {
		return Result{}, fmt.Errorf("pin %q: version %q is not a stable X.Y.Z", cur.Name, cur.Version)
	}
	fix, affected := adv.affects(curV, hasCur)
	var r Result
	var best Version
	for i := range cands {
		c := &cands[i]
		v, stable := cur.version(c.Version)
		if stable && hasCur && Compare(v, curV) <= 0 {
			continue // never backwards
		}
		wait := cool[0]
		if affected && Compare(v, fix) >= 0 {
			wait = cool[1]
		}
		latest := Latest(c.Timestamps)
		why := ""
		switch {
		case !stable || c.PreRelease:
			why = "pre-release"
		case c.Deprecated:
			why = "deprecated"
		case slices.ContainsFunc(cur.Withdrawn, func(d string) bool {
			return d != "" && slices.ContainsFunc(slices.Collect(maps.Values(c.Artifacts)), func(a Artifact) bool { return a.SHA256 == d })
		}):
			why = "withdrawn"
		case latest.IsZero():
			why = "no timestamp"
		case latest.After(now):
			why = "timestamp in the future"
		case now.Sub(latest)-wait < max(extra, 0): // not age < wait+extra, which overflows
			why = "cooling off"
		}
		if why == "" && (r.Since.IsZero() || latest.Before(r.Since)) {
			r.Since = latest
		}
		if why != "" {
			r.Skipped = append(r.Skipped, Skip{c.Version, why})
		} else if r.Chosen == nil || Compare(v, best) > 0 {
			r.Chosen, best = c, v
		}
	}
	if r.Chosen == nil {
		return r, nil
	}
	r.Security = affected && Compare(best, fix) >= 0
	r.AutoMerge = !(r.Security && cur.Class == Trusted)
	return r, nil
}

// affects reports whether a affects the pinned version cur, and returns the fix.
// A nil advisory, or one whose versions do not parse, affects nothing.
func (a *Advisory) affects(cur Version, hasCur bool) (Version, bool) {
	if a == nil || !hasCur {
		return Version{}, false
	}
	fix, ok := ParseVersion(a.Fixed)
	from, okFrom := ParseVersion(a.Introduced)
	if !ok || (!okFrom && a.Introduced != "") {
		return Version{}, false
	}
	return fix, Compare(from, cur) <= 0 && Compare(cur, fix) < 0
}

// Latest returns the latest non-zero timestamp, or the zero time if there is none.
func Latest(ts []time.Time) time.Time {
	return slices.MaxFunc(append([]time.Time{{}}, ts...), time.Time.Compare)
}

// Version is a stable semantic version: major, minor, patch.
type Version [3]uint64

// Compare orders two versions as slices.Compare does.
func Compare(a, b Version) int { return slices.Compare(a[:], b[:]) }

// version reads a tag of p's source: the prefix and suffix stripped where present, then X.Y.Z or a date, yyyymmdd, which orders as {yyyy, mm, dd}.
func (p Pin) version(tag string) (Version, bool) {
	s := strings.TrimSuffix(strings.TrimPrefix(tag, p.TagPrefix), p.TagSuffix)
	if n, err := strconv.ParseUint(s, 10, 32); err == nil && len(s) == 8 {
		return Version{n / 10000, n / 100 % 100, n % 100}, true
	}
	return ParseVersion(s)
}

// ParseVersion reads a plain stable version, X.Y.Z with an optional leading
// "v". Any other form, a pre-release or build suffix included, does not parse.
func ParseVersion(s string) (Version, bool) {
	var v Version
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != len(v) {
		return Version{}, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil || (len(p) > 1 && p[0] == '0') {
			return Version{}, false
		}
		v[i] = n
	}
	return v, true
}
