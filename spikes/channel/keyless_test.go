// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestTrustedRoot reads the committed upstream trusted_root.json and chains each
// Fulcio CA's first certificate to its last at the start of the CA's validFor.
func TestTrustedRoot(t *testing.T) {
	raw, err := os.ReadFile("testdata/trusted-root.json")
	var root TrustedRoot
	if err == nil {
		err = json.Unmarshal(raw, &root)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("channel trusted_root_bytes=%d trusted_root_sha256=%x fulcio=%d rekor=%d ctfe=%d tsa=%d",
		len(raw), sha256.Sum256(raw), len(root.CertificateAuthorities), len(root.Tlogs), len(root.Ctlogs), len(root.TimestampAuthorities))
	span := func(w window) string {
		if w.End == nil {
			return w.Start.Format(time.DateOnly) + "..open"
		}
		return w.Start.Format(time.DateOnly) + ".." + w.End.Format(time.DateOnly)
	}
	for _, ca := range root.CertificateAuthorities {
		certs, pool := ca.CertChain.Certificates, x509.NewCertPool()
		first, err1 := x509.ParseCertificate(certs[0].RawBytes)
		last, err2 := x509.ParseCertificate(certs[len(certs)-1].RawBytes)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		pool.AddCert(last)
		if _, err := first.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: ca.ValidFor.Start,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
			t.Fatalf("%s: %v", ca.URI, err)
		}
		t.Logf("channel fulcio uri=%s certs=%d valid=%s", ca.URI, len(certs), span(ca.ValidFor))
	}
	for _, a := range root.TimestampAuthorities {
		t.Logf("channel tsa uri=%s certs=%d valid=%s", a.URI, len(a.CertChain.Certificates), span(a.ValidFor))
	}
	for _, l := range append(root.Tlogs, root.Ctlogs...) {
		t.Logf("channel log url=%s key=%s valid=%s", l.BaseURL, l.PublicKey.KeyDetails, span(l.PublicKey.ValidFor))
	}
}

// TestKeyless runs VerifyKeyless on a Fulcio-shaped bundle the test makes,
// because the session's proxy refused the real codex bundle.
func TestKeyless(t *testing.T) {
	const identity = "https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.0.1"
	const issuer = "https://token.actions.githubusercontent.com"
	signed := now.Add(-time.Hour)
	issue := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		c, err2 := x509.ParseCertificate(der)
		if err != nil || err2 != nil {
			t.Fatal(err, err2)
		}
		return c, key
	}
	ca := func(n int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "test"}, IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: signed.AddDate(-1, 0, 0), NotAfter: signed.AddDate(5, 0, 0)}
	}
	rootCert, rootKey := issue(ca(1), nil, nil)
	interCert, interKey := issue(ca(2), rootCert, rootKey)
	ext, _ := asn1.MarshalWithParams(issuer, "utf8")
	uri, _ := url.Parse(identity)
	leaf, leafKey := issue(&x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: signed, NotAfter: signed.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, URIs: []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{{Id: oidIssuer, Value: ext}}}, interCert, interKey)
	root := func(start time.Time) *TrustedRoot {
		return &TrustedRoot{CertificateAuthorities: []authority{{"https://fulcio.test",
			chain{[]rawCert{{interCert.Raw}, {rootCert.Raw}}}, window{Start: start}}}}
	}
	sum, other := sha256.Sum256([]byte("artifact")), sha256.Sum256([]byte("other"))
	bundle := func(d, signedDigest []byte) []byte {
		sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, signedDigest)
		b, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
			"verificationMaterial": map[string]any{"certificate": rawCert{leaf.Raw}},
			"messageSignature":     map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": d}, "signature": sig}})
		return b
	}
	good, trusted := bundle(sum[:], sum[:]), root(signed.AddDate(-1, 0, 0))
	for _, tc := range []struct {
		name, identity, issuer string
		bundle                 []byte
		root                   *TrustedRoot
		ok                     bool
	}{
		{"good", identity, issuer, good, trusted, true},
		{"other identity", identity + "x", issuer, good, trusted, false},
		{"other issuer", identity, "https://accounts.google.com", good, trusted, false},
		{"digest not the pinned one", identity, issuer, bundle(other[:], other[:]), trusted, false},
		{"signature over another digest", identity, issuer, bundle(sum[:], other[:]), trusted, false},
		{"CA not yet valid at signing", identity, issuer, good, root(signed.Add(time.Second)), false},
		{"unknown CA", identity, issuer, good, &TrustedRoot{}, false},
		{"garbage", identity, issuer, []byte("{"), trusted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyKeyless(tc.bundle, tc.root, sum[:], tc.identity, tc.issuer); (err == nil) != tc.ok {
				t.Fatalf("got %v, want ok=%v", err, tc.ok)
			}
		})
	}
	us := p50(200, func() error { return VerifyKeyless(good, trusted, sum[:], identity, issuer) }).Microseconds()
	t.Logf("channel keyless_verify_us=%d samples=200 bundle_bytes=%d bundle=synthetic real_bundle=refused-by-session-proxy", us, len(good))
	t.Logf("channel keyless_missing=SCT,rekor-SET,inclusion-proof,rekor-v2-tiles,TUF-refresh,timestamp-authority")
}
