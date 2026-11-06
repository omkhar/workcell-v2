// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/pins"
)

const (
	maxManifest = 64 << 10 // one manifest or index; real ones are a few KiB
	maxBlob     = 512 << 20
	maxToken    = 64 << 10
	maxLayers   = 128
	// maxRaw bounds the bytes of tar stream, and of file data, that all layers of one
	// image may expand to. The tree lives in memory, so a gzip bomb ends here.
	maxRaw = 2 << 30

	acceptManifests = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
)

// Media types Pull accepts. Anything else, zstd layers and foreign layers included, is refused.
var (
	indexTypes = map[string]bool{
		"application/vnd.oci.image.index.v1+json":                   true,
		"application/vnd.docker.distribution.manifest.list.v2+json": true,
	}
	manifestTypes = map[string]bool{
		"application/vnd.oci.image.manifest.v1+json":           true,
		"application/vnd.docker.distribution.manifest.v2+json": true,
	}
	// layerTypes maps a layer media type to whether the blob is gzip.
	layerTypes = map[string]bool{
		"application/vnd.oci.image.layer.v1.tar+gzip":       true,
		"application/vnd.docker.image.rootfs.diff.tar.gzip": true,
		"application/vnd.oci.image.layer.v1.tar":            false,
	}
)

// Image names one image in a registry, by digest, and the platform to take from it.
type Image struct {
	Registry   string // https://host[:port], no path
	Repository string // for example library/debian
	Digest     string // sha256:<hex> of the image index or the image manifest
	OS, Arch   string // for example linux, arm64; used when Digest names an index
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  struct {
		OS   string `json:"os"`
		Arch string `json:"architecture"`
	} `json:"platform"`
}

type document struct {
	MediaType string       `json:"mediaType"`
	Manifests []descriptor `json:"manifests"`
	Layers    []descriptor `json:"layers"`
}

// Pull fetches img over https, resolves an index to the manifest for img.OS and
// img.Arch, and applies the manifest's layers to t in order. Every manifest and
// blob is checked against the digest it was requested by, and every size against a
// cap, before it is trusted.
// Registry content is data only (I8): nothing is run, and nothing is written to disk.
// On error t may be partly changed and must be dropped.
func Pull(ctx context.Context, client *http.Client, img Image, t *Tree) error {
	if err := img.check(); err != nil {
		return err
	}
	g := &registry{client: cmp.Or(client, http.DefaultClient), base: img.Registry, repo: img.Repository}
	digest := img.Digest
	doc, err := g.document(ctx, digest)
	if err != nil {
		return err
	}
	if indexTypes[doc.MediaType] {
		digest = ""
		for _, m := range doc.Manifests {
			if m.Platform.OS == img.OS && m.Platform.Arch == img.Arch {
				digest = m.Digest
				break
			}
		}
		if digest == "" {
			return fmt.Errorf("registry: the index has no manifest for %s/%s", img.OS, img.Arch)
		}
		if doc, err = g.document(ctx, digest); err != nil {
			return err
		}
		if !manifestTypes[doc.MediaType] {
			return errors.New("registry: the index entry is not an image manifest")
		}
	}
	if len(doc.Layers) > maxLayers {
		return errors.New("registry: too many layers")
	}
	budget := int64(maxRaw)
	for i, l := range doc.Layers {
		used, err := g.layer(ctx, l, t, budget)
		if err != nil {
			return fmt.Errorf("registry: layer %d: %w", i, err)
		}
		budget -= used
	}
	return nil
}

func (img Image) check() error {
	u, err := url.Parse(img.Registry)
	if err != nil || pins.HTTPSURL(img.Registry) != nil || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return errors.New("registry: the registry must be a bare https://host[:port]")
	}
	for c := range strings.SplitSeq(img.Repository, "/") {
		if c == "" || c == "." || c == ".." || strings.Trim(c, "abcdefghijklmnopqrstuvwxyz0123456789._-") != "" {
			return errors.New("registry: bad repository name")
		}
	}
	return checkDigest(img.Digest)
}

func checkDigest(d string) error {
	h, ok := strings.CutPrefix(d, "sha256:")
	if b, err := hex.DecodeString(h); !ok || err != nil || len(b) != sha256.Size || h != hex.EncodeToString(b) {
		return errors.New("registry: not a sha256 digest")
	}
	return nil
}

// document fetches a manifest or index by digest and checks the bytes against it.
func (g *registry) document(ctx context.Context, digest string) (*document, error) {
	body, err := g.get(ctx, "manifests", digest, acceptManifests, maxManifest)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, maxManifest+1))
	if err != nil {
		return nil, pins.Bare("registry", err)
	}
	if sum := sha256.Sum256(b); len(b) > maxManifest || "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("registry: the manifest does not match its digest")
	}
	var doc document
	if json.Unmarshal(b, &doc) != nil || !indexTypes[doc.MediaType] && !manifestTypes[doc.MediaType] {
		return nil, errors.New("registry: not an OCI or Docker image manifest or index")
	}
	for _, d := range slices.Concat(doc.Manifests, doc.Layers) {
		if err := checkDigest(d.Digest); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// layer fetches one blob and applies it to t. The compressed bytes are hashed as
// they stream, and the digest and size are checked once the tar has been read.
func (g *registry) layer(ctx context.Context, d descriptor, t *Tree, budget int64) (int64, error) {
	gz, ok := layerTypes[d.MediaType]
	if !ok {
		return 0, errors.New("unsupported layer media type")
	}
	if d.Size <= 0 || d.Size > maxBlob {
		return 0, errors.New("layer size outside the cap")
	}
	body, err := g.get(ctx, "blobs", d.Digest, "", d.Size)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	h := sha256.New()
	var n int64
	src := io.TeeReader(io.LimitReader(body, d.Size+1), io.MultiWriter(h, count{&n}))
	var tarIn io.Reader = src
	if gz {
		zr, err := gzip.NewReader(src)
		if err != nil {
			return 0, errors.New("layer is not a gzip stream")
		}
		tarIn = zr
	}
	used, err := applyLayer(t, tarIn, budget)
	if err == nil {
		_, err = io.Copy(io.Discard, src)
	}
	if err != nil {
		return 0, err
	}
	if n != d.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
		return 0, errors.New("the layer does not match its digest")
	}
	return used, nil
}

// registry is an anonymous client for one repository. Its token goes only to
// requests that this type builds for the registry host.
type registry struct {
	client     *http.Client
	base, repo string
	token      string
}

// get returns the body of a 200 for /v2/<repo>/<kind>/<digest> whose declared length is
// within limit. On a 401 with a Bearer challenge it takes an anonymous token from the
// https realm and retries once.
func (g *registry) get(ctx context.Context, kind, digest, accept string, limit int64) (io.ReadCloser, error) {
	u := g.base + "/v2/" + g.repo + "/" + kind + "/" + digest
	resp, err := g.do(ctx, u, accept, g.token)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && g.token == "" {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if g.token, err = g.fetchToken(ctx, challenge); err != nil {
			return nil, err
		}
		if resp, err = g.do(ctx, u, accept, g.token); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("registry: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		resp.Body.Close()
		return nil, errors.New("registry: over the size cap")
	}
	return resp.Body, nil
}

func (g *registry) fetchToken(ctx context.Context, challenge string) (string, error) {
	p := pins.BearerParams(challenge)
	realm, err := url.Parse(p["realm"])
	if err != nil || pins.HTTPSURL(p["realm"]) != nil {
		return "", errors.New("registry: HTTP 401 without an https Bearer challenge")
	}
	q := realm.Query()
	q.Set("service", p["service"])
	q.Set("scope", p["scope"])
	realm.RawQuery = q.Encode()
	resp, err := g.do(ctx, realm.String(), "", "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, maxToken)).Decode(&tok) != nil ||
		cmp.Or(tok.Token, tok.AccessToken) == "" {
		return "", errors.New("registry: no anonymous token")
	}
	return cmp.Or(tok.Token, tok.AccessToken), nil
}

// do sends one GET. Redirects follow the artifact policy: at most three, https
// only, and the credential dropped when the host changes.
func (g *registry) do(ctx context.Context, rawURL, accept, bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("registry: not a usable URL")
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	c := *g.client
	c.CheckRedirect = pins.Redirect
	resp, err := c.Do(req)
	if err != nil {
		return nil, pins.Bare("registry", err)
	}
	return resp, nil
}

var errCap = errors.New("over the size cap")

// limited reads at most n bytes from r and then fails, unlike io.LimitReader, which
// ends quietly.
type limited struct {
	r io.Reader
	n int64
}

func (l *limited) Read(p []byte) (int, error) {
	n, err := l.r.Read(p[:min(int64(len(p)), l.n+1)])
	if l.n -= int64(n); l.n < 0 {
		return 0, errCap
	}
	return n, err
}

type count struct{ n *int64 }

func (c count) Write(p []byte) (int, error) {
	*c.n += int64(len(p))
	return len(p), nil
}
