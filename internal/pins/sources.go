// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package pins

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	maxBytes     = 64 << 20 // the most any one body may hold; an npm packument can be tens of MiB
	maxRedirects = 3
	maxOCITags   = 30 // the newest version tags whose manifests are read
	fetchTimeout = 2 * time.Minute
	ociAccept    = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
)

// Candidates lists the releases of p.Source at p.Locator. Any failure, whether the network, a status, a parse, the size cap, a missing field or a bad
// timestamp, returns an error and no candidates; it never looks like an upstream with nothing new. A well-formed listing of no release returns an empty slice
// and no error. It sends no credential except the anonymous pull token a registry hands out when it answers 401 with a Bearer challenge.
func Candidates(ctx context.Context, client *http.Client, p Pin) ([]Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	c := *client
	c.CheckRedirect = Redirect
	g := getter{ctx, &c}
	var cands []Candidate
	var err error
	switch p.Source {
	case NPM:
		cands, err = g.npm(p)
	case GitHubReleases:
		cands, err = g.github(p)
	case VendorManifest:
		cands, err = g.vendor(p)
	case OCI:
		cands, err = g.oci(p)
	default:
		err = fmt.Errorf("unknown source %q", p.Source)
	}
	if err != nil {
		return nil, fmt.Errorf("pin %q: %w", p.Name, err)
	}
	return append([]Candidate{}, cands...), nil
}

type getter struct {
	ctx    context.Context
	client *http.Client
}

// statusError is a response that was not a 200.
type statusError struct {
	url    string
	status string
	code   int
	header http.Header
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: %s", e.url, e.status) }

// get returns the body of a 200 response to an https GET, read up to the cap.
// On a 401 with a Bearer challenge it fetches a token from the challenge's
// https realm and retries once, with the token sent to the challenged URL only.
func (g getter) get(rawURL, accept string) ([]byte, http.Header, error) {
	body, h, err := g.fetch(rawURL, accept, "")
	var se *statusError
	if !errors.As(err, &se) || se.code != http.StatusUnauthorized {
		return body, h, err
	}
	params := BearerParams(se.header.Get("WWW-Authenticate"))
	realm, err := url.Parse(params["realm"])
	if err != nil || HTTPSURL(realm.String()) != nil {
		return nil, nil, fmt.Errorf("%w; the challenge realm %q is not an https URL", se, params["realm"])
	}
	q := realm.Query()
	q.Set("service", params["service"])
	q.Set("scope", params["scope"])
	realm.RawQuery = q.Encode()
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	tokBody, _, err := g.fetch(realm.String(), "", "")
	if err == nil {
		err = json.Unmarshal(tokBody, &tok)
	}
	if err != nil || cmp.Or(tok.Token, tok.AccessToken) == "" {
		return nil, nil, fmt.Errorf("%w; no token from %s", se, realm.Host)
	}
	return g.fetch(rawURL, accept, cmp.Or(tok.Token, tok.AccessToken))
}

// BearerParams reads the quoted key="value" pairs of a Bearer challenge. A
// header of another scheme yields none.
func BearerParams(h string) map[string]string {
	m := map[string]string{}
	rest, ok := strings.CutPrefix(h, "Bearer ")
	for ok {
		var k, v string
		if k, rest, ok = strings.Cut(strings.TrimLeft(rest, ", "), `="`); !ok {
			break
		}
		if v, rest, ok = strings.Cut(rest, `"`); ok {
			m[k] = v
		}
	}
	return m
}

func (g getter) fetch(rawURL, accept, bearer string) ([]byte, http.Header, error) {
	if err := HTTPSURL(rawURL); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(g.ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &statusError{rawURL, resp.Status, resp.StatusCode, resp.Header}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("GET %s: body exceeds %d bytes", rawURL, maxBytes)
	}
	return body, resp.Header, nil
}

func (g getter) json(rawURL, accept string, v any) (http.Header, error) {
	body, h, err := g.get(rawURL, accept)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", rawURL, err)
	}
	return h, nil
}

// Redirect is the redirect policy of every fetch of upstream bytes: at most three, https only,
// and the credential dropped when the host changes.
func Redirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errors.New("too many redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header.Del("Authorization")
	}
	return HTTPSURL(req.URL.String())
}

// Bare maps a transport error to a fixed phrase after prefix, so that an error names the
// failure and nothing upstream sent: no URL, status line or certificate name.
func Bare(prefix string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New(prefix + ": timed out")
	case errors.Is(err, context.Canceled):
		return errors.New(prefix + ": cancelled")
	}
	return errors.New(prefix + ": transport failure")
}

// HTTPSURL refuses a URL that is not https, in a fixed phrase.
func HTTPSURL(s string) error {
	if u, err := url.Parse(s); err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("not an https URL")
	}
	return nil
}

// parseTimes reads RFC 3339 timestamps, skips empty ones, and fails on a bad
// one or when none is left.
func parseTimes(raw ...string) ([]time.Time, error) {
	var ts []time.Time
	for _, s := range raw {
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, err
		}
		ts = append(ts, t.UTC())
	}
	if len(ts) == 0 {
		return nil, errors.New("no timestamp")
	}
	return ts, nil
}

// IsSHA256 reports whether s is 64 lowercase hex digits.
var IsSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString

// npm reads a package document: every version in versions, with its time entry.
// The tarball is the same file for every architecture. npm publishes no SHA-256.
func (g getter) npm(p Pin) ([]Candidate, error) {
	var doc struct {
		Versions map[string]struct {
			Deprecated string `json:"deprecated"`
			Dist       struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
		Time map[string]string `json:"time"`
	}
	if _, err := g.json(p.Locator, "", &doc); err != nil {
		return nil, err
	}
	if doc.Versions == nil {
		return nil, errors.New("no versions object")
	}
	var cands []Candidate
	for v, e := range doc.Versions {
		ts, err := parseTimes(doc.Time[v])
		if err != nil {
			return nil, fmt.Errorf("version %s: %w", v, err)
		}
		if err := HTTPSURL(e.Dist.Tarball); err != nil {
			return nil, fmt.Errorf("version %s: tarball: %w", v, err)
		}
		a := Artifact{URL: e.Dist.Tarball, Integrity: e.Dist.Integrity}
		_, stable := ParseVersion(v)
		cands = append(cands, Candidate{
			Release:    Release{Version: v, Artifacts: map[string]Artifact{"amd64": a, "arm64": a}},
			PreRelease: !stable, Deprecated: e.Deprecated != "", Timestamps: ts,
		})
	}
	slices.SortFunc(cands, func(a, b Candidate) int { return strings.Compare(a.Version, b.Version) })
	return cands, nil
}

type ghAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
}

// github reads the newest 100 releases whose tag starts with p.TagPrefix, which is stripped from the version. A stable release that lacks the asset of any
// architecture in p.Assets is dropped. Only when no stable release carries them all, so the pin names a wrong asset, is it an error. A release that lacks the
// bundle p.Signing.Bundles names gets an empty Bundle: the verifier refuses it if selected (B5), and the releases that carry one bump (P7).
func (g getter) github(p Pin) ([]Candidate, error) {
	if len(p.Assets) == 0 {
		return nil, errors.New("no assets named")
	}
	var rels []struct {
		Tag         string    `json:"tag_name"`
		Prerelease  bool      `json:"prerelease"`
		Draft       bool      `json:"draft"`
		CreatedAt   string    `json:"created_at"`
		PublishedAt string    `json:"published_at"`
		Assets      []ghAsset `json:"assets"`
	}
	if _, err := g.json(p.Locator+"?per_page=100", "application/vnd.github+json", &rels); err != nil {
		return nil, err
	}
	cands := []Candidate{}
	stable, complete := 0, 0 // the stable releases seen, and those with every asset
	for _, r := range rels {
		if r.Tag == "" {
			return nil, errors.New("a release has no tag_name")
		}
		version, ok := strings.CutPrefix(r.Tag, p.TagPrefix)
		if !ok {
			continue
		}
		ts, err := parseTimes(r.CreatedAt, r.PublishedAt)
		if err != nil {
			return nil, fmt.Errorf("release %s: %w", r.Tag, err)
		}
		c := Candidate{Release: Release{Version: version, Artifacts: map[string]Artifact{}}, PreRelease: r.Prerelease || r.Draft, Timestamps: ts}
		if !c.PreRelease {
			stable++
		}
		for arch, name := range p.Assets {
			i := slices.IndexFunc(r.Assets, func(a ghAsset) bool { return a.Name == name })
			if i < 0 {
				continue
			}
			a := r.Assets[i]
			if err := HTTPSURL(a.URL); err != nil {
				return nil, fmt.Errorf("release %s: %w", r.Tag, err)
			}
			sum, hasSum := strings.CutPrefix(a.Digest, "sha256:")
			if a.Digest != "" && (!hasSum || !IsSHA256(sum)) {
				return nil, fmt.Errorf("release %s: asset %q: bad digest %q", r.Tag, name, a.Digest)
			}
			art := Artifact{URL: a.URL, SHA256: sum}
			if bundle, ok := p.Signing.Bundles[arch]; ok {
				if j := slices.IndexFunc(r.Assets, func(a ghAsset) bool { return a.Name == bundle }); j >= 0 {
					if err := HTTPSURL(r.Assets[j].URL); err != nil {
						return nil, fmt.Errorf("release %s: %w", r.Tag, err)
					}
					art.Bundle = r.Assets[j].URL
				}
			}
			c.Artifacts[arch] = art
		}
		if !c.PreRelease {
			if len(c.Artifacts) < len(p.Assets) {
				continue // an old release with a renamed asset does not block the rest
			}
			complete++
		}
		cands = append(cands, c)
	}
	if stable > 0 && complete == 0 {
		return nil, errors.New("no stable release carries every asset named")
	}
	return cands, nil
}

// vendor reads the release the vendor's latest file names, the shape Claude
// Code publishes: <root>/latest, <root>/<version>/manifest.json and the file at
// <root>/<version>/<platform>/<binary>, the name the manifest gives the platform's file.
func (g getter) vendor(p Pin) ([]Candidate, error) {
	if len(p.Assets) == 0 {
		return nil, errors.New("no platforms named")
	}
	root := strings.TrimSuffix(p.Locator, "/")
	body, _, err := g.get(root+"/latest", "")
	if err != nil {
		return nil, err
	}
	v := strings.TrimSpace(string(body))
	if _, ok := ParseVersion(v); !ok {
		return nil, fmt.Errorf("latest is %q, not a version", v)
	}
	var m struct {
		Version   string `json:"version"`
		BuildDate string `json:"buildDate"`
		Platforms map[string]struct {
			Checksum string `json:"checksum"`
			Binary   string `json:"binary"`
		} `json:"platforms"`
	}
	if _, err := g.json(root+"/"+v+"/manifest.json", "", &m); err != nil {
		return nil, err
	}
	if m.Version != v {
		return nil, fmt.Errorf("manifest of %s reports version %q", v, m.Version)
	}
	ts, err := parseTimes(m.BuildDate)
	if err != nil {
		return nil, fmt.Errorf("manifest of %s: buildDate: %w", v, err)
	}
	arts := map[string]Artifact{}
	for arch, platform := range p.Assets {
		pl := m.Platforms[platform]
		if !IsSHA256(pl.Checksum) {
			return nil, fmt.Errorf("manifest of %s: no SHA-256 for platform %q", v, platform)
		}
		if pl.Binary == "" || strings.ContainsAny(pl.Binary, "/?#") {
			return nil, fmt.Errorf("manifest of %s: no binary name for platform %q", v, platform)
		}
		arts[arch] = Artifact{URL: root + "/" + v + "/" + platform + "/" + pl.Binary, SHA256: pl.Checksum}
	}
	return []Candidate{{Release: Release{Version: v, Artifacts: arts}, Timestamps: ts}}, nil
}

// oci reads the manifests of the newest maxOCITags tags that are plain
// versions. The artifact is the manifest by digest, the same for every
// architecture. A manifest without an org.opencontainers.image.created
// annotation has no timestamp, and so is never selected.
func (g getter) oci(p Pin) ([]Candidate, error) {
	var list struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	h, err := g.json(p.Locator+"/tags/list", "", &list)
	if err != nil {
		return nil, err
	}
	if h.Get("Link") != "" {
		return nil, errors.New("the tag list has more than one page")
	}
	if list.Name == "" {
		return nil, errors.New("the tag list has no name")
	}
	tags := slices.DeleteFunc(list.Tags, func(t string) bool { _, ok := ParseVersion(t); return !ok })
	slices.SortFunc(tags, func(a, b string) int {
		va, _ := ParseVersion(a)
		vb, _ := ParseVersion(b)
		return Compare(vb, va)
	})
	cands := []Candidate{}
	for _, tag := range tags[:min(len(tags), maxOCITags)] {
		body, h, err := g.get(p.Locator+"/manifests/"+tag, ociAccept)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		if d := h.Get("Docker-Content-Digest"); d != "" && d != "sha256:"+digest {
			return nil, fmt.Errorf("tag %s: Docker-Content-Digest %q is not the digest of the body", tag, d)
		}
		var m struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("tag %s: %w", tag, err)
		}
		var ts []time.Time
		if created := m.Annotations["org.opencontainers.image.created"]; created != "" {
			if ts, err = parseTimes(created); err != nil {
				return nil, fmt.Errorf("tag %s: created: %w", tag, err)
			}
		}
		a := Artifact{URL: p.Locator + "/manifests/sha256:" + digest, SHA256: digest}
		cands = append(cands, Candidate{Release: Release{Version: tag, Artifacts: map[string]Artifact{"amd64": a, "arm64": a}}, Timestamps: ts})
	}
	return cands, nil
}
