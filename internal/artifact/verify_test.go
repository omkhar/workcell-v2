// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package artifact

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/sigstore"
)

const (
	up      = "https://up.test"
	ghID    = "https://github.com/vendor/tool/.github/workflows/release.yml@refs/tags/{version}"
	npmID   = "https://github.com/vendor/tool/.github/workflows/publish.yml@refs/tags/{version}"
	issuer  = "https://token.actions.githubusercontent.com"
	slsaV1  = "https://slsa.dev/provenance/v1"
	publish = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
	purl    = "pkg:npm/%40vendor/tool@1.2.0"
)

var (
	arches    = []string{"amd64", "arm64"}
	signedAt  = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	oidSAN    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// signer is a synthetic Fulcio CA and Rekor log, and the trusted root that holds them.
type signer struct {
	root     *sigstore.Root
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	rekor    *ecdsa.PrivateKey
	keyID    []byte
}

func p256(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t testing.TB, tmpl, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sign(t testing.TB, k *ecdsa.PrivateKey, digest []byte) []byte {
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func newSigner(t testing.TB) *signer {
	ca := func(serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprint("ca", serial)},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	}
	s := &signer{interKey: p256(t), rekor: p256(t)}
	rootKey := p256(t)
	rootCert := issue(t, ca(1), nil, rootKey, nil)
	s.inter = issue(t, ca(2), rootCert, s.interKey, rootKey)
	spki, err := x509.MarshalPKIXPublicKey(s.rekor.Public())
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(spki)
	s.keyID = id[:]
	since := map[string]any{"start": "2000-01-01T00:00:00Z"}
	raw, _ := json.Marshal(map[string]any{
		"tlogs": []any{map[string]any{"logId": map[string]any{"keyId": s.keyID}, "publicKey": map[string]any{"rawBytes": spki, "validFor": since}}},
		"certificateAuthorities": []any{map[string]any{"validFor": since, "certChain": map[string]any{"certificates": []any{
			map[string]any{"rawBytes": s.inter.Raw}, map[string]any{"rawBytes": rootCert.Raw}}}}}})
	if s.root, err = sigstore.ParseRoot(raw); err != nil {
		t.Fatal(err)
	}
	return s
}

// bundle mints a Sigstore bundle whose leaf names san and issuer: a message
// signature over digest when payload is nil, else a DSSE envelope over payload.
func (s *signer) bundle(t testing.TB, san string, digest, payload []byte, payloadType string) []byte {
	k := p256(t)
	sanDER, _ := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(san)}})
	issDER, _ := asn1.MarshalWithParams(issuer, "utf8")
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: signedAt, NotAfter: signedAt.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidSAN, Value: sanDER}, {Id: oidIssuer, Value: issDER}}}, s.inter, k, s.interKey)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	b := map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}
	var sig, hash []byte
	var kind string
	var spec map[string]any
	if payload == nil {
		sig, hash, kind = sign(t, k, digest), digest, "hashedrekord"
		b["messageSignature"] = map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": digest}, "signature": sig}
		spec = map[string]any{"data": map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(hash)}},
			"signature": map[string]any{"content": sig, "publicKey": map[string]any{"content": cert}}}
	} else {
		pae := sha256.Sum256(append(fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload)), payload...))
		ph := sha256.Sum256(payload)
		sig, hash, kind = sign(t, k, pae[:]), ph[:], "dsse"
		b["dsseEnvelope"] = map[string]any{"payload": payload, "payloadType": payloadType, "signatures": []any{map[string]any{"sig": sig}}}
		spec = map[string]any{"payloadHash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(hash)},
			"signatures": []any{map[string]any{"signature": sig, "verifier": cert}}}
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": kind, "spec": spec})
	at := signedAt.Add(time.Minute).Unix()
	set := sha256.Sum256(fmt.Appendf(nil, `{"body":"%s","integratedTime":%d,"logID":"%x","logIndex":7}`, base64.StdEncoding.EncodeToString(body), at, s.keyID))
	b["verificationMaterial"] = map[string]any{"certificate": map[string]any{"rawBytes": leaf.Raw}, "tlogEntries": []any{map[string]any{
		"logIndex": 7, "logId": map[string]any{"keyId": s.keyID}, "kindVersion": map[string]any{"kind": kind, "version": "0.0.1"},
		"integratedTime": at, "inclusionPromise": map[string]any{"signedEntryTimestamp": sign(t, s.rekor, set[:])}, "canonicalizedBody": body}}}
	raw, _ := json.Marshal(b)
	return raw
}

// entry is one tarball member. A size withholds the body: the header claims it.
type entry struct {
	name string
	body []byte
	flag byte
	link string
	size int64
}

func tgz(t testing.TB, entries ...entry) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	whole := true
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: cmp.Or(e.flag, tar.TypeReg), Linkname: e.link}
		if e.size > 0 {
			h.Size, whole = e.size, false
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.body)
	}
	if whole {
		tw.Close()
	}
	gz.Close()
	return buf.Bytes()
}

// route is one recorded response.
type route struct {
	status  int
	body    []byte
	header  map[string]string
	chunked bool
	drip    bool // a byte every 50 ms until the client goes away
}

// serve runs one TLS server that answers for every host: the client dials it
// whatever the URL says. Routes are keyed by host and escaped path.
func serve(t *testing.T, routes map[string]route) (*http.Client, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rt, ok := routes[r.Host+r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rt.drip {
			for {
				w.Write([]byte{0})
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
		}
		if !rt.chunked {
			w.Header().Set("Content-Length", strconv.Itoa(len(rt.body)))
		}
		for k, v := range rt.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(cmp.Or(rt.status, 200))
		w.Write(rt.body)
	}))
	t.Cleanup(srv.Close)
	c := srv.Client()
	tr := c.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	tr.TLSClientConfig.ServerName = "example.com"
	return c, &hits
}

func key(u string) string { return strings.TrimPrefix(u, "https://") }

func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func statement(subjects ...map[string]any) map[string]any {
	return map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": slsaV1, "subject": subjects, "predicate": map[string]any{}}
}

func subject(name string, digest map[string]string) map[string]any {
	return map[string]any{"name": name, "digest": digest}
}

// setup is an honest upstream of one source type; a row tampers with it.
type setup struct {
	t       testing.TB
	sg      *signer
	pin     pins.Pin
	cand    pins.Candidate
	routes  map[string]route
	sums    map[string]string // the sha256 Verify must report per architecture
	san     string            // the rendered identity
	hex512  string            // the npm tarball's sha512
	timeout time.Duration
	noFetch bool // the refusal must come before any request
}

func (s *setup) art(arch string, f func(*pins.Artifact)) {
	a := s.cand.Artifacts[arch]
	f(&a)
	s.cand.Artifacts[arch] = a
}

func (s *setup) sign(digest []byte) []byte { return s.sg.bundle(s.t, s.san, digest, nil, "") }

// retar replaces one architecture's tarball, and the digest the listing publishes for it.
func (s *setup) retar(arch string, entries ...entry) {
	tb := tgz(s.t, entries...)
	s.routes[key(s.cand.Artifacts[arch].URL)] = route{body: tb}
	s.art(arch, func(a *pins.Artifact) { a.SHA256 = hexOf(tb) })
}

// attest serves the registry's attestations: a publish attestation and a
// provenance one of outer predicate type whose DSSE payload is stmt.
func (s *setup) attest(outer, payloadType string, stmt map[string]any) {
	raw, _ := json.Marshal(stmt)
	b := s.sg.bundle(s.t, s.san, nil, raw, payloadType)
	doc, _ := json.Marshal(map[string]any{"attestations": []any{
		map[string]any{"predicateType": publish, "bundle": map[string]any{}},
		map[string]any{"predicateType": outer, "bundle": json.RawMessage(b)}}})
	s.routes[key(up+"/-/npm/v1/attestations/@vendor%2ftool@1.2.0")] = route{body: doc}
}

type row struct {
	name   string
	src    pins.Source
	signed bool // GitHub: a bundle per architecture; npm: registry provenance
	member bool // GitHub: the bundle signs the tar member, not the asset
	mut    func(*setup)
	ok     bool
}

func build(t *testing.T, sg *signer, r row) *setup {
	s := &setup{t: t, sg: sg, routes: map[string]route{}, sums: map[string]string{}, timeout: 20 * time.Second}
	arts := map[string]pins.Artifact{}
	switch r.src {
	case pins.GitHubReleases:
		s.pin = pins.Pin{Name: "tool", Source: r.src, Locator: up + "/repos/vendor/tool/releases", Assets: map[string]string{}}
		s.cand.Version = "v1.2.0"
		s.san = strings.ReplaceAll(ghID, "{version}", s.cand.Version)
		if r.signed {
			s.pin.Signing = pins.Signing{Identity: ghID, Issuer: issuer, Bundles: map[string]string{}, Members: map[string]string{}}
		}
		for _, arch := range arches {
			bin := []byte("binary for " + arch)
			tb := tgz(t, entry{name: "tool-" + arch, body: bin})
			u := up + "/dl/v1.2.0/tool-linux-" + arch + ".tar.gz"
			s.pin.Assets[arch] = "tool-linux-" + arch + ".tar.gz"
			s.routes[key(u)] = route{body: tb}
			a := pins.Artifact{URL: u, SHA256: hexOf(tb)}
			if r.signed {
				s.pin.Signing.Bundles[arch] = "tool-linux-" + arch + ".sigstore"
				a.Bundle = strings.TrimSuffix(u, ".tar.gz") + ".sigstore"
				d := sha256.Sum256(tb)
				if r.member {
					s.pin.Signing.Members[arch] = "tool-" + arch
					d = sha256.Sum256(bin)
				}
				s.routes[key(a.Bundle)] = route{body: s.sign(d[:])}
			}
			arts[arch] = a
		}
	case pins.NPM:
		s.pin = pins.Pin{Name: "tool", Source: r.src, Locator: up + "/@vendor%2ftool"}
		s.cand.Version = "1.2.0"
		s.san = strings.ReplaceAll(npmID, "{version}", s.cand.Version)
		tb := tgz(t, entry{name: "package/bin/tool", body: []byte("npm binary")})
		u := up + "/@vendor/tool/-/tool-1.2.0.tgz"
		s.routes[key(u)] = route{body: tb}
		sum := sha512.Sum512(tb)
		s.hex512 = hex.EncodeToString(sum[:])
		a := pins.Artifact{URL: u, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}
		arts["amd64"], arts["arm64"] = a, a
		if r.signed {
			s.pin.Signing = pins.Signing{Identity: npmID, Issuer: issuer}
			s.attest(slsaV1, inTotoType, statement(subject(purl, map[string]string{"sha512": s.hex512})))
		}
	case pins.VendorManifest:
		s.pin = pins.Pin{Name: "claude", Source: r.src, Locator: up + "/root", Assets: map[string]string{"amd64": "linux-x64", "arm64": "linux-arm64"}}
		s.cand.Version = "1.2.0"
		for arch, platform := range s.pin.Assets {
			body := []byte("claude for " + arch)
			u := up + "/root/1.2.0/" + platform + "/claude"
			s.routes[key(u)] = route{body: body}
			arts[arch] = pins.Artifact{URL: u, SHA256: hexOf(body)}
		}
	case pins.OCI:
		s.pin = pins.Pin{Name: "tool", Source: r.src, Locator: up + "/v2/vendor/tool"}
		s.cand.Version = "1.2.0"
		body := []byte(`{"schemaVersion": 2, "annotations": {"org.opencontainers.image.created": "2026-10-20T09:30:00Z"}}`)
		u := up + "/v2/vendor/tool/manifests/sha256:" + hexOf(body)
		s.routes[key(u)] = route{body: body}
		a := pins.Artifact{URL: u, SHA256: hexOf(body)}
		arts["amd64"], arts["arm64"] = a, a
	}
	s.cand.Artifacts = arts
	for arch, a := range arts {
		s.sums[arch] = hexOf(s.routes[key(a.URL)].body)
	}
	return s
}

func TestVerify(t *testing.T) {
	sg := newSigner(t)
	gh, npm, vendor, oci := pins.GitHubReleases, pins.NPM, pins.VendorManifest, pins.OCI
	other := sha256.Sum256([]byte("other bytes"))
	// swap serves other bytes for amd64 and leaves the listing as it was.
	swap := func(s *setup) { s.routes[key(s.cand.Artifacts["amd64"].URL)] = route{body: []byte("other bytes")} }
	// relist serves other bytes for amd64 and makes the listing agree with them.
	relist := func(s *setup) {
		swap(s)
		s.art("amd64", func(a *pins.Artifact) { a.SHA256 = hex.EncodeToString(other[:]) })
	}
	redirect := func(to string) func(*setup) {
		return func(s *setup) {
			u := s.cand.Artifacts["amd64"].URL
			if to == "" {
				to = u
			}
			s.routes[key(to)] = s.routes[key(u)]
			s.routes[key(u)] = route{status: 302, header: map[string]string{"Location": to}}
		}
	}
	length := func(delta int) func(*setup) {
		return func(s *setup) {
			k := key(s.cand.Artifacts["amd64"].URL)
			rt := s.routes[k]
			rt.header = map[string]string{"Content-Length": strconv.Itoa(len(rt.body) + delta)}
			s.routes[k] = rt
		}
	}
	version := func(v string) func(*setup) {
		return func(s *setup) { s.cand.Version, s.noFetch = v, true }
	}
	sha := func(v string) func(*setup) {
		return func(s *setup) { s.art("amd64", func(a *pins.Artifact) { a.SHA256 = v }) }
	}
	bundle := func(f func(s *setup) []byte) func(*setup) {
		return func(s *setup) { s.routes[key(s.cand.Artifacts["amd64"].Bundle)] = route{body: f(s)} }
	}
	memberOf := func(s *setup) []byte { d := sha256.Sum256([]byte("binary for amd64")); return d[:] }
	assetOf := func(s *setup) []byte {
		d := sha256.Sum256(s.routes[key(s.cand.Artifacts["amd64"].URL)].body)
		return d[:]
	}
	members := func(m string) func(*setup) {
		return func(s *setup) { s.pin.Signing.Members["amd64"], s.noFetch = m, true }
	}
	integrity := func(v string) func(*setup) {
		return func(s *setup) {
			for _, arch := range arches {
				s.art(arch, func(a *pins.Artifact) { a.Integrity = v })
			}
		}
	}
	attRoute := key(up + "/-/npm/v1/attestations/@vendor%2ftool@1.2.0")
	att := func(rt route) func(*setup) { return func(s *setup) { s.routes[attRoute] = rt } }
	stmt := func(outer, payloadType string, st map[string]any) func(*setup) {
		return func(s *setup) { s.attest(outer, payloadType, st) }
	}
	signing := func(s *setup) {
		s.pin.Signing, s.noFetch = pins.Signing{Identity: ghID, Issuer: issuer}, true
	}
	b64 := base64.StdEncoding.EncodeToString

	rows := []row{
		{name: "good github signed member", src: gh, signed: true, member: true, ok: true},
		{name: "good github signed asset", src: gh, signed: true, ok: true},
		{name: "good github unsigned digest", src: gh, ok: true},
		{name: "good npm signed", src: npm, signed: true, ok: true},
		{name: "good npm unsigned sri", src: npm, ok: true},
		{name: "good vendor", src: vendor, ok: true},
		{name: "good oci", src: oci, ok: true},

		// common
		{name: "1E body-swapped-honest-meta github", src: gh, mut: swap},
		{name: "1E body-swapped-honest-meta npm", src: npm, mut: swap},
		{name: "1E body-swapped-honest-meta vendor", src: vendor, mut: swap},
		{name: "2E meta-matches-swapped-body github member", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "tool-amd64", body: []byte("trojan")})
		}},
		{name: "2E meta-matches-swapped-body github asset", src: gh, signed: true, mut: relist},
		{name: "2E meta-matches-swapped-body npm", src: npm, signed: true, mut: func(s *setup) {
			swap(s)
			sum := sha512.Sum512([]byte("other bytes"))
			integrity("sha512-" + b64(sum[:]))(s)
		}},
		{name: "3E redirect-to-http", src: gh, mut: redirect("http://up.test/x")},
		{name: "4E redirect-other-host followed", src: gh, mut: redirect("https://mirror.test/x"), ok: true},
		{name: "4V redirect-loop", src: gh, mut: redirect("")},
		{name: "5E over-size-cap declared", src: gh, mut: func(s *setup) {
			s.routes[key(s.cand.Artifacts["amd64"].URL)] = route{header: map[string]string{"Content-Length": strconv.Itoa(maxArtifact + 1)}}
		}},
		{name: "5E over-size-cap bundle", src: gh, signed: true, mut: bundle(func(*setup) []byte { return make([]byte, maxBundle+1) })},
		{name: "5E over-size-cap bundle chunked", src: gh, signed: true, mut: func(s *setup) {
			s.routes[key(s.cand.Artifacts["amd64"].Bundle)] = route{body: make([]byte, maxBundle+1), chunked: true}
		}},
		{name: "5E over-size-cap attestations", src: npm, signed: true, mut: att(route{body: make([]byte, maxAttestations+1)})},
		{name: "6E truncated-body", src: gh, mut: length(1)},
		{name: "7V content-length-lies-short", src: gh, mut: length(-1)},
		{name: "8V slow-drip", src: gh, mut: func(s *setup) {
			s.routes[key(s.cand.Artifacts["amd64"].URL)] = route{drip: true}
			s.timeout = 500 * time.Millisecond
		}},
		{name: "9E empty-sha256-no-signature github", src: gh, mut: sha("")},
		{name: "9E empty-sha256-no-signature npm", src: npm, mut: integrity("")},
		{name: "9E empty-sha256-no-signature vendor", src: vendor, mut: sha("")},
		{name: "10E version-template-injection path", src: gh, signed: true, mut: version("1.0/../x")},
		{name: "10E version-template-injection at", src: gh, signed: true, mut: version("1.0@evil")},
		{name: "10E version-template-injection ref", src: gh, signed: true, mut: version("v1.0/refs/tags/x")},
		{name: "10E version-template-injection npm", src: npm, signed: true, mut: version("1.0@evil")},
		{name: "10V version-empty", src: gh, signed: true, mut: version("")},
		{name: "11V wrong-arch-fixture", src: gh, mut: func(s *setup) {
			s.routes[key(s.cand.Artifacts["amd64"].URL)] = s.routes[key(s.cand.Artifacts["arm64"].URL)]
		}},
		{name: "no artifacts", src: gh, mut: func(s *setup) { s.cand.Artifacts = nil }},

		// GitHub releases
		{name: "12E digest-missing-bundle-present", src: gh, signed: true, mut: sha("")},
		{name: "13V bundle-url-missing", src: gh, signed: true, mut: func(s *setup) { s.art("amd64", func(a *pins.Artifact) { a.Bundle = "" }) }},
		{name: "14E bundle-other-asset", src: gh, signed: true, mut: bundle(func(s *setup) []byte { return s.sign(other[:]) })},
		{name: "15E bundle-other-arch", src: gh, signed: true, mut: bundle(func(s *setup) []byte { return s.routes[key(s.cand.Artifacts["arm64"].Bundle)].body })},
		{name: "16E bundle-wrong-identity", src: gh, signed: true, mut: func(s *setup) {
			s.pin.Signing.Identity = strings.Replace(ghID, "release.yml", "other.yml", 1)
		}},
		{name: "16E bundle-wrong-issuer", src: gh, signed: true, mut: func(s *setup) { s.pin.Signing.Issuer = "https://accounts.google.com" }},
		{name: "16V identity-without-issuer", src: gh, signed: true, mut: func(s *setup) { s.pin.Signing.Issuer, s.noFetch = "", true }},
		{name: "16V bundles-without-identity", src: gh, signed: true, mut: func(s *setup) { s.pin.Signing.Identity, s.noFetch = "", true }},
		{name: "17E bundle-signs-tarball-pin-says-member", src: gh, signed: true, member: true, mut: bundle(func(s *setup) []byte { return s.sign(assetOf(s)) })},
		{name: "18E bundle-signs-member-pin-says-tarball", src: gh, signed: true, mut: bundle(func(s *setup) []byte { return s.sign(memberOf(s)) })},
		{name: "19E member-missing", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "nope", body: []byte("binary for amd64")})
		}},
		{name: "19V member-is-directory", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "tool-amd64/", flag: tar.TypeDir})
		}},
		{name: "20E member-duplicated", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "tool-amd64", body: []byte("binary for amd64")}, entry{name: "tool-amd64", body: []byte("binary for amd64")})
		}},
		{name: "21E member-symlink", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "real", body: []byte("binary for amd64")}, entry{name: "tool-amd64", flag: tar.TypeSymlink, link: "real"})
		}},
		{name: "22V member-hardlink", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "real", body: []byte("binary for amd64")}, entry{name: "tool-amd64", flag: tar.TypeLink, link: "real"})
		}},
		{name: "23V member-dotdot in pin", src: gh, signed: true, member: true, mut: members("../tool-amd64")},
		{name: "23V member-absolute in pin", src: gh, signed: true, member: true, mut: members("/tool-amd64")},
		{name: "23V member-unclean in pin", src: gh, signed: true, member: true, mut: members("./tool-amd64")},
		{name: "23V member-absolute in tarball", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "/tool-amd64", body: []byte("binary for amd64")})
		}},
		{name: "25V member-oversized header", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.retar("amd64", entry{name: "tool-amd64", size: maxArtifact + 1})
		}},
		{name: "25V not-a-tarball", src: gh, signed: true, member: true, mut: func(s *setup) {
			s.routes[key(s.cand.Artifacts["amd64"].URL)] = route{body: []byte("binary for amd64")}
			sha(hexOf([]byte("binary for amd64")))(s)
		}},
		{name: "26V bundle-malformed-json", src: gh, signed: true, mut: bundle(func(*setup) []byte { return []byte("{") })},
		{name: "26V bundle-empty", src: gh, signed: true, mut: bundle(func(*setup) []byte { return nil })},
		{name: "26V dsse-where-messagesignature-expected", src: gh, signed: true, mut: bundle(func(s *setup) []byte {
			raw, _ := json.Marshal(statement(subject("x", nil)))
			return s.sg.bundle(t, s.san, nil, raw, inTotoType)
		})},
		{name: "27V digest-format uppercase", src: gh, mut: func(s *setup) { sha(strings.ToUpper(s.cand.Artifacts["amd64"].SHA256))(s) }},
		{name: "27V digest-format prefixed", src: gh, mut: func(s *setup) { sha("sha256:" + s.cand.Artifacts["amd64"].SHA256)(s) }},

		// npm
		{name: "28E sri-wrong-algo sha256", src: npm, mut: func(s *setup) {
			sum := sha256.Sum256(s.routes[key(s.cand.Artifacts["amd64"].URL)].body)
			integrity("sha256-" + b64(sum[:]))(s)
		}},
		{name: "28E sri-wrong-algo sha1", src: npm, mut: integrity("sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=")},
		{name: "29E sri-malformed-base64", src: npm, mut: integrity("sha512-!!!!")},
		{name: "29V sri-matches-but-unsigned-when-signing-named", src: npm, signed: true, mut: att(route{status: 404})},
		{name: "30E attestations-404", src: npm, signed: true, mut: func(s *setup) { delete(s.routes, attRoute) }},
		{name: "31E attestations-500", src: npm, signed: true, mut: att(route{status: 500, body: []byte("oops")})},
		{name: "32E attestations-empty", src: npm, signed: true, mut: att(route{body: []byte(`{"attestations": []}`)})},
		{name: "32V attestations-not-json", src: npm, signed: true, mut: att(route{body: []byte(`{`)})},
		{name: "33E publish-only", src: npm, signed: true, mut: att(route{body: []byte(`{"attestations": [{"predicateType": "` + publish + `", "bundle": {}}]}`)})},
		{name: "33V two-provenance", src: npm, signed: true, mut: func(s *setup) {
			raw, _ := json.Marshal(statement(subject(purl, map[string]string{"sha512": s.hex512})))
			b := json.RawMessage(s.sg.bundle(t, s.san, nil, raw, inTotoType))
			doc, _ := json.Marshal(map[string]any{"attestations": []any{
				map[string]any{"predicateType": slsaV1, "bundle": b}, map[string]any{"predicateType": slsaV1, "bundle": b}}})
			att(route{body: doc})(s)
		}},
		{name: "34E provenance-other-package", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject("pkg:npm/%40vendor/other@1.2.0", map[string]string{"sha512": s.hex512})))(s)
		}},
		{name: "34E provenance-other-version", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject("pkg:npm/%40vendor/tool@1.2.1", map[string]string{"sha512": s.hex512})))(s)
		}},
		{name: "34V provenance-unencoded-scope", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject("pkg:npm/@vendor/tool@1.2.0", map[string]string{"sha512": s.hex512})))(s)
		}},
		{name: "35E subject-sha256-only", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject(purl, map[string]string{"sha256": hexOf(s.routes[key(s.cand.Artifacts["amd64"].URL)].body)})))(s)
		}},
		{name: "35V subject-sha512-other", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject(purl, map[string]string{"sha512": strings.Repeat("00", 64)})))(s)
		}},
		{name: "35V subject-sha512-uppercase", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, inTotoType, statement(subject(purl, map[string]string{"sha512": strings.ToUpper(s.hex512)})))(s)
		}},
		{name: "36E two-subjects", src: npm, signed: true, mut: func(s *setup) {
			sub := subject(purl, map[string]string{"sha512": s.hex512})
			stmt(slsaV1, inTotoType, statement(sub, sub))(s)
		}},
		{name: "36V no-subject", src: npm, signed: true, mut: stmt(slsaV1, inTotoType, statement())},
		{name: "37V statement-type-wrong", src: npm, signed: true, mut: func(s *setup) {
			st := statement(subject(purl, map[string]string{"sha512": s.hex512}))
			st["_type"] = "https://in-toto.io/Statement/v2"
			stmt(slsaV1, inTotoType, st)(s)
		}},
		{name: "38V predicate-type-wrong outer", src: npm, signed: true, mut: func(s *setup) {
			stmt("https://slsa.dev/provenance/v3", inTotoType, statement(subject(purl, map[string]string{"sha512": s.hex512})))(s)
		}},
		{name: "38V predicate-type-wrong inner", src: npm, signed: true, mut: func(s *setup) {
			st := statement(subject(purl, map[string]string{"sha512": s.hex512}))
			st["predicateType"] = publish
			stmt(slsaV1, inTotoType, st)(s)
		}},
		{name: "39V dsse-payloadtype-wrong", src: npm, signed: true, mut: func(s *setup) {
			stmt(slsaV1, "application/json", statement(subject(purl, map[string]string{"sha512": s.hex512})))(s)
		}},
		{name: "39V message-signature-as-provenance", src: npm, signed: true, mut: func(s *setup) {
			doc, _ := json.Marshal(map[string]any{"attestations": []any{map[string]any{"predicateType": slsaV1, "bundle": json.RawMessage(s.sign(assetOf(s)))}}})
			att(route{body: doc})(s)
		}},
		{name: "39V npm-signing-names-bundle", src: npm, signed: true, mut: func(s *setup) {
			s.pin.Signing.Bundles, s.noFetch = map[string]string{"amd64": "x"}, true
		}},

		// vendor manifest and OCI
		{name: "40E identity-on-vendor", src: vendor, mut: signing},
		{name: "40E identity-on-oci", src: oci, mut: signing},
		{name: "40E oci-url-digest-mismatch", src: oci, mut: func(s *setup) {
			u := up + "/v2/vendor/tool/manifests/sha256:" + hex.EncodeToString(other[:])
			s.routes[key(u)] = s.routes[key(s.cand.Artifacts["amd64"].URL)]
			s.art("amd64", func(a *pins.Artifact) { a.URL = u })
		}},
		{name: "40E oci-body-mismatch", src: oci, mut: swap},
		{name: "40E vendor-checksum-mismatch", src: vendor, mut: sha(hex.EncodeToString(other[:]))},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := build(t, sg, r)
			if r.mut != nil {
				r.mut(s)
			}
			client, hits := serve(t, s.routes)
			ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
			defer cancel()
			start := time.Now()
			rel, err := Verifier{Client: client, Root: sg.root}.Verify(ctx, s.pin, s.cand)
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("took %v", d)
			}
			if !r.ok {
				if err == nil {
					t.Fatalf("verified %+v; want a refusal", rel)
				}
				if strings.Contains(err.Error(), "up.test") || strings.Contains(err.Error(), "other bytes") {
					t.Fatalf("the error echoes upstream bytes: %v", err)
				}
				if s.noFetch && hits.Load() != 0 {
					t.Fatalf("%d requests before the refusal: %v", hits.Load(), err)
				}
				t.Logf("refused: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rel.Version != s.cand.Version || len(rel.Artifacts) != len(arches) {
				t.Fatalf("got %+v", rel)
			}
			for arch, a := range rel.Artifacts {
				if a.SHA256 != s.sums[arch] || a.URL != s.cand.Artifacts[arch].URL {
					t.Errorf("%s: got %+v, want sha256 %s", arch, a, s.sums[arch])
				}
			}
		})
	}
}

// TestTarMember covers the limits that the Verify table cannot reach cheaply:
// the decompressed cap and a member of exactly the cap.
func TestTarMember(t *testing.T) {
	bin := []byte("binary")
	want := sha256.Sum256(bin)
	big := make([]byte, 600<<10)
	for _, tt := range []struct {
		name  string
		tgz   []byte
		limit int64
		ok    bool
	}{
		{"good", tgz(t, entry{name: "tool", body: bin}), 1 << 20, true},
		{"good among others", tgz(t, entry{name: "a", body: big}, entry{name: "tool", body: bin}, entry{name: "b/", flag: tar.TypeDir}), 1 << 20, true},
		{"archive at the cap", tgz(t, entry{name: "tool", body: bin}), 2048, true}, // header, body block, end marker
		{"archive one over the cap", tgz(t, entry{name: "tool", body: bin}), 2047, false},
		{"24E gzip-bomb", tgz(t, entry{name: "a", body: big}, entry{name: "b", body: big}, entry{name: "tool", body: bin}), 1 << 20, false},
		{"24V bomb-before-member", tgz(t, entry{name: "a", body: big}, entry{name: "b", body: big}), 1 << 20, false},
		{"25V oversized header", tgz(t, entry{name: "tool", size: 2 << 20}), 1 << 20, false},
		{"missing", tgz(t, entry{name: "other", body: bin}), 1 << 20, false},
		{"empty archive", tgz(t), 1 << 20, false},
		{"not gzip", []byte("plain"), 1 << 20, false},
		{"truncated gzip", tgz(t, entry{name: "tool", body: bin})[:20], 1 << 20, false},
		{"empty input", nil, 1 << 20, false},
	} {
		sum, err := tarMember(bytes.NewReader(tt.tgz), "tool", tt.limit)
		if (err == nil) != tt.ok || (tt.ok && !bytes.Equal(sum, want[:])) {
			t.Errorf("%s: got %x, %v; want ok=%v", tt.name, sum, err, tt.ok)
		}
	}
}

func FuzzTarMember(f *testing.F) {
	f.Add(tgz(f, entry{name: "tool", body: []byte("binary")}))
	f.Add(tgz(f, entry{name: "tool", body: []byte("binary")}, entry{name: "tool", flag: tar.TypeSymlink, link: "x"}))
	f.Add(tgz(f, entry{name: "tool", size: 1 << 30}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		sum, err := tarMember(bytes.NewReader(data), "tool", 1<<16)
		if (err == nil) != (len(sum) == sha256.Size) {
			t.Fatalf("sum %x with error %v", sum, err)
		}
	})
}

func FuzzProvenance(f *testing.F) {
	stmt, _ := json.Marshal(statement(subject(purl, map[string]string{"sha512": strings.Repeat("ab", 64)})))
	doc, _ := json.Marshal(map[string]any{"attestations": []any{map[string]any{"predicateType": slsaV1, "bundle": map[string]any{"mediaType": "x"}}}})
	for _, s := range [][]byte{stmt, doc, nil, []byte("{}"), []byte("null"), []byte(`{"attestations":[null]}`), []byte(`{"subject":[null]}`)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if b, err := provenanceBundle(data); (err == nil) != (len(b) > 0) || err == nil && !json.Valid(data) {
			t.Fatalf("bundle %q with error %v", b, err)
		}
		if err := checkStatement(data, purl, strings.Repeat("ab", 64)); err == nil && !json.Valid(data) {
			t.Fatalf("accepted a statement that is not JSON: %q", data)
		}
	})
}
