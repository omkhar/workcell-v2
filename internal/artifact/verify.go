// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package artifact downloads the artifacts of a candidate release on the host,
// computes their digests from the bytes as they stream, and checks everything
// upstream published about them: the published digest or npm SRI always, and a
// Sigstore signature or registry provenance where the pin says upstream signs
// (B5). Nothing is skipped silently: a check that cannot run is a refusal.
package artifact

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/sigstore"
)

const (
	// MaxArtifact bounds one download and one tarball's decompressed bytes. A
	// provider CLI is at most a few hundred MiB; an OCI manifest is a few KiB.
	MaxArtifact     = 512 << 20
	maxBundle       = 64 << 10
	maxAttestations = 1 << 20
	inTotoType      = "application/vnd.in-toto+json"
)

var (
	slsaTypes      = map[string]bool{"https://slsa.dev/provenance/v1": true, "https://slsa.dev/provenance/v0.2": true}
	statementTypes = map[string]bool{"https://in-toto.io/Statement/v1": true, "https://in-toto.io/Statement/v0.1": true}
)

// Verifier downloads with Client and checks Sigstore bundles against Root. A
// nil Client means http.DefaultClient; a nil Root means the embedded public
// Sigstore root.
type Verifier struct {
	Client *http.Client
	Root   *sigstore.Root
}

// Verify downloads every artifact of c, hashes it, checks each statement
// upstream makes about it, and returns the release with every SHA-256 taken
// from the downloaded bytes. Any failure names the architecture and the check,
// and echoes nothing upstream sent. The context bounds the whole step.
func (v Verifier) Verify(ctx context.Context, p pins.Pin, c pins.Candidate) (pins.Release, error) {
	s := p.Signing
	signed := s.Identity != "" || s.Issuer != "" || len(s.Bundles) > 0 || len(s.Members) > 0
	var id sigstore.Identity
	if signed {
		if p.Source != pins.GitHubReleases && p.Source != pins.NPM {
			return pins.Release{}, fmt.Errorf("pin %q: source %s has no signature mechanism", p.Name, p.Source)
		}
		if s.Identity == "" || s.Issuer == "" {
			return pins.Release{}, fmt.Errorf("pin %q: signing needs an identity and an issuer", p.Name)
		}
		if p.Source == pins.NPM && len(s.Bundles)+len(s.Members) > 0 {
			return pins.Release{}, fmt.Errorf("pin %q: npm provenance names no bundle asset or member", p.Name)
		}
		if !versionRE.MatchString(c.Version) {
			return pins.Release{}, fmt.Errorf("pin %q: the release version is not plain", p.Name)
		}
		for arch, m := range s.Members {
			if m == "" || path.Clean(m) != m || path.IsAbs(m) || m == "." || m == ".." || strings.HasPrefix(m, "../") {
				return pins.Release{}, fmt.Errorf("pin %q %s: the member path is not a clean relative path", p.Name, arch)
			}
		}
		id = sigstore.Identity{SAN: strings.ReplaceAll(s.Identity, "{version}", c.Version), Issuer: s.Issuer}
	}
	if len(c.Artifacts) == 0 {
		return pins.Release{}, fmt.Errorf("pin %q: the release has no artifact", p.Name)
	}
	rel := pins.Release{Version: c.Version, Artifacts: map[string]pins.Artifact{}}
	for _, arch := range slices.Sorted(maps.Keys(c.Artifacts)) {
		a, err := v.check(ctx, p, c.Version, arch, c.Artifacts[arch], id, signed)
		if err != nil {
			return pins.Release{}, fmt.Errorf("pin %q %s: %w", p.Name, arch, err)
		}
		rel.Artifacts[arch] = a
	}
	return rel, nil
}

// check downloads one architecture's artifact and checks what upstream says
// about it: the published digest first, then the signature or provenance.
func (v Verifier) check(ctx context.Context, p pins.Pin, version, arch string, a pins.Artifact, id sigstore.Identity, signed bool) (pins.Artifact, error) {
	sum256, sum512, member, err := v.download(ctx, a.URL, p.Signing.Members[arch])
	if err != nil {
		return pins.Artifact{}, err
	}
	hex256 := hex.EncodeToString(sum256)
	switch {
	case p.Source == pins.NPM && a.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum512):
		return pins.Artifact{}, errors.New("the published integrity is not the sha512 of the download")
	case p.Source != pins.NPM && a.SHA256 == "":
		return pins.Artifact{}, errors.New("upstream publishes no digest")
	case p.Source != pins.NPM && a.SHA256 != hex256:
		return pins.Artifact{}, errors.New("the published digest is not the sha256 of the download")
	case p.Source == pins.OCI && !strings.HasSuffix(a.URL, "/manifests/sha256:"+hex256):
		return pins.Artifact{}, errors.New("the URL digest is not the sha256 of the manifest")
	}
	if signed {
		switch p.Source {
		case pins.GitHubReleases:
			if member == nil {
				member = sum256
			}
			err = v.bundle(ctx, a.Bundle, id, member)
		case pins.NPM:
			err = v.provenance(ctx, p.Locator, version, id, hex.EncodeToString(sum512))
		}
		if err != nil {
			return pins.Artifact{}, err
		}
	}
	a.SHA256 = hex256
	return a, nil
}

// bundle checks a Sigstore message-signature bundle at rawURL over digest.
func (v Verifier) bundle(ctx context.Context, rawURL string, id sigstore.Identity, digest []byte) error {
	if rawURL == "" {
		return errors.New("the release has no bundle asset")
	}
	raw, err := v.readAll(ctx, rawURL, maxBundle)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	payload, _, err := sigstore.Verify(v.root(), raw, id, digest)
	if err != nil {
		return err
	}
	if payload != nil {
		return errors.New("bundle: a DSSE envelope where a message signature is expected")
	}
	return nil
}

// provenance checks the registry's SLSA provenance attestation for the package
// the npm locator names: a DSSE bundle whose in-toto statement has one subject,
// the package purl, with the tarball's sha512.
func (v Verifier) provenance(ctx context.Context, locator, version string, id sigstore.Identity, hex512 string) error {
	u, err := url.Parse(locator)
	if err != nil {
		return errors.New("provenance: the locator is not a URL")
	}
	name := strings.TrimPrefix(u.Path, "/") // "name" or "@scope/name"
	scope, base, scoped := strings.Cut(name, "/")
	if !scoped {
		scope, base = "@x", scope
	}
	if !nameRE.MatchString(base) || len(scope) < 2 || scope[0] != '@' || !nameRE.MatchString(scope[1:]) {
		return errors.New("provenance: the locator does not name a package")
	}
	att := u.Scheme + "://" + u.Host + "/-/npm/v1/attestations/" + strings.ReplaceAll(name, "/", "%2f") + "@" + version
	doc, err := v.readAll(ctx, att, maxAttestations)
	if err != nil {
		return fmt.Errorf("provenance: %w", err)
	}
	b, err := provenanceBundle(doc)
	if err != nil {
		return err
	}
	payload, payloadType, err := sigstore.Verify(v.root(), b, id, nil)
	if err != nil {
		return err
	}
	if payloadType != inTotoType {
		return errors.New("provenance: payload type is not in-toto")
	}
	return checkStatement(payload, "pkg:npm/"+strings.Replace(name, "@", "%40", 1)+"@"+version, hex512)
}

// provenanceBundle picks the one SLSA provenance attestation of a registry
// attestations document and returns its bundle.
func provenanceBundle(doc []byte) (json.RawMessage, error) {
	var d struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, errors.New("provenance: attestations are not valid JSON")
	}
	var b json.RawMessage
	for _, a := range d.Attestations {
		if slsaTypes[a.PredicateType] {
			if b != nil {
				return nil, errors.New("provenance: more than one provenance attestation")
			}
			b = a.Bundle
		}
	}
	if len(b) == 0 {
		return nil, errors.New("provenance: no provenance attestation")
	}
	return b, nil
}

// checkStatement checks that an in-toto statement is SLSA provenance of
// exactly one subject, purl, whose sha512 is hex512.
func checkStatement(payload []byte, purl, hex512 string) error {
	var s struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	switch {
	case json.Unmarshal(payload, &s) != nil:
		return errors.New("provenance: the statement is not valid JSON")
	case !statementTypes[s.Type]:
		return errors.New("provenance: not an in-toto statement")
	case !slsaTypes[s.PredicateType]:
		return errors.New("provenance: the statement is not SLSA provenance")
	case len(s.Subject) != 1:
		return errors.New("provenance: the statement needs exactly one subject")
	case s.Subject[0].Name != purl:
		return errors.New("provenance: the subject is another package or version")
	case s.Subject[0].Digest["sha512"] != hex512:
		return errors.New("provenance: the subject sha512 is not the tarball's")
	}
	return nil
}

func (v Verifier) root() *sigstore.Root {
	if v.Root == nil {
		return sigstore.PublicRoot()
	}
	return v.Root
}

// Fetch starts an https GET of rawURL with client, or http.DefaultClient when
// it is nil, and returns the body of a 200 that is within limit bytes, whether
// declared or streamed: the body fails past limit, and maps a transport fault to
// a fixed phrase. Redirects follow the pins policy: at most three, https only.
// It is the one bounded reader of upstream bytes on the host (B8).
func Fetch(ctx context.Context, client *http.Client, rawURL string, limit int64) (io.ReadCloser, error) {
	if err := pins.HTTPSURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("not a usable URL")
	}
	c := *cmp.Or(client, http.DefaultClient)
	c.CheckRedirect = pins.Redirect
	resp, err := c.Do(req)
	if err != nil {
		return nil, pins.Bare("download", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		resp.Body.Close()
		return nil, errCap
	}
	return &body{resp.Body, limit}, nil
}

// readAll fetches a small body, such as a bundle, into memory.
func (v Verifier) readAll(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	b, err := Fetch(ctx, v.Client, rawURL, limit)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return io.ReadAll(b)
}

// download streams one artifact through sha256 and sha512 once, and, when
// member is set, through the gzip tarball reader that digests that member.
// Nothing is written to disk, and the bytes hashed are the bytes parsed.
func (v Verifier) download(ctx context.Context, rawURL, member string) (sum256, sum512, memberSum []byte, err error) {
	b, err := Fetch(ctx, v.Client, rawURL, MaxArtifact)
	if err != nil {
		return nil, nil, nil, err
	}
	defer b.Close()
	h256, h512 := sha256.New(), sha512.New()
	r := io.TeeReader(b, io.MultiWriter(h256, h512))
	if member != "" {
		if memberSum, err = tarMember(r, member, MaxArtifact); err != nil {
			return nil, nil, nil, err
		}
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		return nil, nil, nil, err
	}
	return h256.Sum(nil), h512.Sum(nil), memberSum, nil
}

// tarMember reads a gzip tarball once and returns the sha256 of exactly one
// regular-file entry named name. A second entry of that name, whatever its
// kind, a member larger than limit, or more than limit decompressed bytes in
// all, is a refusal. Nothing is extracted.
func tarMember(r io.Reader, name string, limit int64) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, errors.New("tarball: not a gzip stream")
	}
	tr := tar.NewReader(&body{gz, limit})
	var sum []byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("tarball: unreadable")
		}
		if h.Name != name {
			continue
		}
		switch {
		case sum != nil:
			return nil, errors.New("tarball: the member appears twice")
		case h.Typeflag != tar.TypeReg:
			return nil, errors.New("tarball: the member is not a regular file")
		case h.Size > limit:
			return nil, errors.New("tarball: the member is over the size cap")
		}
		d := sha256.New()
		if _, err := io.Copy(d, tr); err != nil {
			return nil, errors.New("tarball: unreadable")
		}
		sum = d.Sum(nil)
	}
	if sum == nil {
		return nil, errors.New("tarball: the member is missing")
	}
	return sum, nil
}

var errCap = errors.New("over the size cap")

// body reads at most n bytes from a reader and then fails, unlike io.LimitReader,
// which ends quietly. Any other fault but the end is mapped to a fixed phrase.
type body struct {
	io.ReadCloser
	n int64
}

func (b *body) Read(p []byte) (int, error) {
	if int64(len(p)) > b.n+1 {
		p = p[:b.n+1]
	}
	n, err := b.ReadCloser.Read(p)
	if b.n -= int64(n); b.n < 0 {
		return 0, errCap
	}
	if err != nil && err != io.EOF {
		err = pins.Bare("download", err)
	}
	return n, err
}

// versionRE and nameRE are non-empty ASCII letters and digits plus ".-+" and ".-_".
var (
	versionRE = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)
