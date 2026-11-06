// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sigstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	maxBundle  = 64 << 10
	maxCerts   = 10
	maxEntries = 10
)

var (
	oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	// Fulcio's OIDC issuer extension, a DER UTF8String. The older .1.1 (raw bytes) is not read.
	oidIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

	mediaTypes = map[string]bool{
		"application/vnd.dev.sigstore.bundle+json;version=0.1": true,
		"application/vnd.dev.sigstore.bundle+json;version=0.2": true,
		"application/vnd.dev.sigstore.bundle+json;version=0.3": true,
		"application/vnd.dev.sigstore.bundle.v0.3+json":        true,
	}
)

// Identity is the expected URI SAN and OIDC issuer of the signing certificate,
// compared byte for byte.
type Identity struct {
	SAN, Issuer string
}

// int64s is a protobuf-JSON int64, which arrives as a number or a decimal string.
type int64s int64

func (i *int64s) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		b = []byte(s)
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	*i = int64s(v)
	return err
}

// bundle is the subset of a Sigstore bundle (protobuf JSON form) read here.
type bundle struct {
	MediaType            string      `json:"mediaType"`
	VerificationMaterial *material   `json:"verificationMaterial"`
	MessageSignature     *messageSig `json:"messageSignature"`
	DSSEEnvelope         *envelope   `json:"dsseEnvelope"`
}

type material struct {
	Certificate          *rawCert     `json:"certificate"`
	X509CertificateChain *certChain   `json:"x509CertificateChain"`
	PublicKey            *struct{}    `json:"publicKey"`
	TlogEntries          []*tlogEntry `json:"tlogEntries"`
}

type tlogEntry struct {
	LogIndex          int64s       `json:"logIndex"`
	LogID             *logRef      `json:"logId"`
	KindVersion       *kindVersion `json:"kindVersion"`
	IntegratedTime    int64s       `json:"integratedTime"`
	InclusionPromise  *promise     `json:"inclusionPromise"`
	CanonicalizedBody []byte       `json:"canonicalizedBody"`
}

type logRef struct {
	KeyID []byte `json:"keyId"`
}

type kindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

type promise struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
}

type messageSig struct {
	MessageDigest *digestRef `json:"messageDigest"`
	Signature     []byte     `json:"signature"`
}

type digestRef struct {
	Algorithm string `json:"algorithm"`
	Digest    []byte `json:"digest"`
}

type envelope struct {
	Payload     []byte   `json:"payload"`
	PayloadType string   `json:"payloadType"`
	Signatures  []envSig `json:"signatures"`
}

type envSig struct {
	Sig []byte `json:"sig"`
}

// Verify checks a Sigstore bundle against root: the leaf certificate chains to
// a Fulcio CA at every Rekor integrated time, every Rekor entry's signed entry
// timestamp verifies and its body binds the leaf, signature and digest, the
// leaf names id, and the signature covers digest (a SHA-256, required for a
// messageSignature bundle and checked against messageDigest when that is
// present) or the DSSE pre-authentication encoding. For a dsseEnvelope bundle
// it returns the payload and payload type, whose subject the caller checks,
// and ignores digest; for a messageSignature bundle it returns nil.
func Verify(root *Root, bundleJSON []byte, id Identity, digest []byte) (payload []byte, payloadType string, err error) {
	if root == nil || id.SAN == "" || id.Issuer == "" {
		return nil, "", errors.New("verify: root, identity and issuer are required")
	}
	if len(bundleJSON) > maxBundle {
		return nil, "", errors.New("bundle: too large")
	}
	var b bundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return nil, "", errors.New("bundle: not valid JSON")
	}
	if !mediaTypes[b.MediaType] {
		return nil, "", errors.New("bundle: unknown media type")
	}
	m := b.VerificationMaterial
	if m == nil || m.PublicKey != nil {
		return nil, "", errors.New("bundle: needs certificate verification material")
	}
	certs, err := parseCerts(m)
	if err != nil {
		return nil, "", err
	}
	leaf := certs[0]
	pub, err := checkLeaf(leaf, id)
	if err != nil {
		return nil, "", err
	}
	var sig, hash []byte
	var kind string
	switch {
	case b.MessageSignature != nil && b.DSSEEnvelope == nil:
		ms := b.MessageSignature
		if len(digest) != sha256.Size {
			return nil, "", errors.New("verify: digest is not a SHA-256")
		}
		if md := ms.MessageDigest; md != nil && (md.Algorithm != "SHA2_256" || !bytes.Equal(md.Digest, digest)) {
			return nil, "", errors.New("bundle: message digest is not the artifact digest")
		}
		if !ecdsa.VerifyASN1(pub, digest, ms.Signature) {
			return nil, "", errors.New("bundle: signature does not cover the digest")
		}
		sig, hash, kind = ms.Signature, digest, "hashedrekord"
	case b.DSSEEnvelope != nil && b.MessageSignature == nil:
		env := b.DSSEEnvelope
		if len(env.Payload) == 0 || env.PayloadType == "" || len(env.Signatures) != 1 {
			return nil, "", errors.New("bundle: DSSE envelope needs a payload, a payload type and one signature")
		}
		sum := sha256.Sum256(pae(env.PayloadType, env.Payload))
		if !ecdsa.VerifyASN1(pub, sum[:], env.Signatures[0].Sig) {
			return nil, "", errors.New("bundle: signature does not cover the DSSE payload")
		}
		ps := sha256.Sum256(env.Payload)
		sig, hash, kind = env.Signatures[0].Sig, ps[:], "dsse"
		payload, payloadType = env.Payload, env.PayloadType
	default:
		return nil, "", errors.New("bundle: needs exactly one of messageSignature and dsseEnvelope")
	}
	if len(m.TlogEntries) == 0 || len(m.TlogEntries) > maxEntries {
		return nil, "", fmt.Errorf("bundle: needs 1 to %d tlog entries", maxEntries)
	}
	for _, e := range m.TlogEntries {
		if err := verifyEntry(root, e, kind, certs, sig, hash); err != nil {
			return nil, "", err
		}
	}
	return payload, payloadType, nil
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return append(fmt.Appendf(nil, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload)), payload...)
}

// parseCerts returns the leaf first, then any extra certificates the bundle
// carries, which may serve as intermediates only.
func parseCerts(m *material) ([]*x509.Certificate, error) {
	var raw []rawCert
	switch {
	case m.Certificate != nil && m.X509CertificateChain == nil:
		raw = []rawCert{*m.Certificate}
	case m.X509CertificateChain != nil && m.Certificate == nil:
		raw = m.X509CertificateChain.Certificates
	}
	if len(raw) == 0 || len(raw) > maxCerts {
		return nil, fmt.Errorf("bundle: needs 1 to %d certificates", maxCerts)
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, c := range raw {
		cert, err := x509.ParseCertificate(c.RawBytes)
		if err != nil {
			return nil, errors.New("bundle: certificate is not DER")
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// checkLeaf checks the leaf's shape and that it names id, and returns its key.
func checkLeaf(leaf *x509.Certificate, id Identity) (*ecdsa.PublicKey, error) {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("leaf: key is not ECDSA P-256")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return nil, errors.New("leaf: not a code-signing end-entity certificate")
	}
	var san []byte
	var issuer string
	for _, e := range leaf.Extensions {
		switch {
		case e.Id.Equal(oidSAN):
			var names []asn1.RawValue
			rest, err := asn1.Unmarshal(e.Value, &names)
			if err != nil || len(rest) != 0 || len(names) != 1 || names[0].Class != asn1.ClassContextSpecific || names[0].Tag != 6 || names[0].IsCompound {
				return nil, errors.New("leaf: needs exactly one URI SAN and no other name")
			}
			san = names[0].Bytes
		case e.Id.Equal(oidIssuer):
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(e.Value, &v)
			if err != nil || len(rest) != 0 || v.Class != asn1.ClassUniversal || v.Tag != asn1.TagUTF8String || v.IsCompound || !utf8.Valid(v.Bytes) {
				return nil, errors.New("leaf: issuer extension is not one UTF8String")
			}
			issuer = string(v.Bytes)
		}
	}
	if san == nil || string(san) != id.SAN {
		return nil, errors.New("leaf: identity mismatch")
	}
	if issuer != id.Issuer {
		return nil, errors.New("leaf: issuer mismatch")
	}
	return pub, nil
}

// verifyEntry checks one Rekor entry: a signed entry timestamp by a known log
// key valid at the integrated time, a body of the bundle's kind that binds the
// leaf, signature and hash, and a leaf chain valid at that time.
func verifyEntry(root *Root, e *tlogEntry, kind string, certs []*x509.Certificate, sig, hash []byte) error {
	if e == nil || e.LogID == nil || e.KindVersion == nil || e.InclusionPromise == nil {
		return errors.New("tlog entry: needs a log id, a kind and an inclusion promise")
	}
	if e.IntegratedTime <= 0 {
		return errors.New("tlog entry: integrated time missing")
	}
	at := time.Unix(int64(e.IntegratedTime), 0)
	key := root.log(e.LogID.KeyID)
	if key == nil {
		return errors.New("tlog entry: unknown log key")
	}
	if !key.validFor.has(at) {
		return errors.New("tlog entry: integrated time outside the log key's window")
	}
	// Rekor signs the canonical JSON of these four fields, keys in this order.
	signed, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{base64.StdEncoding.EncodeToString(e.CanonicalizedBody), int64(e.IntegratedTime), key.logID, int64(e.LogIndex)})
	sum := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(key.pub, sum[:], e.InclusionPromise.SignedEntryTimestamp) {
		return errors.New("tlog entry: signed entry timestamp does not verify")
	}
	if e.KindVersion.Kind != kind || e.KindVersion.Version != "0.0.1" {
		return errors.New("tlog entry: kind does not match the bundle")
	}
	if err := bindBody(e.CanonicalizedBody, kind, certs[0], sig, hash); err != nil {
		return err
	}
	return chain(root, certs, at)
}

// bindBody checks that a hashedrekord or dsse body names exactly the leaf,
// the bundle signature and the signed hash. Bytes are compared as they are.
func bindBody(raw []byte, kind string, leaf *x509.Certificate, sig, hash []byte) error {
	var body struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Data struct {
				Hash struct{ Algorithm, Value string } `json:"hash"`
			} `json:"data"`
			Signature struct {
				Content   []byte `json:"content"`
				PublicKey struct {
					Content []byte `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
			PayloadHash struct{ Algorithm, Value string } `json:"payloadHash"`
			Signatures  []struct {
				Signature []byte `json:"signature"`
				Verifier  []byte `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Kind != kind || body.APIVersion != "0.0.1" {
		return errors.New("tlog entry: body kind does not match the bundle")
	}
	h, bodySig, cert := body.Spec.Data.Hash, body.Spec.Signature.Content, body.Spec.Signature.PublicKey.Content
	if kind == "dsse" {
		if len(body.Spec.Signatures) != 1 {
			return errors.New("tlog entry: body needs one signature")
		}
		h, bodySig, cert = body.Spec.PayloadHash, body.Spec.Signatures[0].Signature, body.Spec.Signatures[0].Verifier
	}
	if v, err := hex.DecodeString(h.Value); h.Algorithm != "sha256" || err != nil || !bytes.Equal(v, hash) {
		return errors.New("tlog entry: body hash is not the signed hash")
	}
	if !bytes.Equal(bodySig, sig) {
		return errors.New("tlog entry: body signature is not the bundle signature")
	}
	if block, _ := pem.Decode(cert); block == nil || !bytes.Equal(block.Bytes, leaf.Raw) {
		return errors.New("tlog entry: body certificate is not the leaf")
	}
	return nil
}

// chain verifies the leaf at time at against every CA whose window holds the
// leaf's NotBefore; the bundle's extra certificates may only be intermediates.
func chain(root *Root, certs []*x509.Certificate, at time.Time) error {
	leaf := certs[0]
	for _, ca := range root.cas {
		if !ca.validFor.has(leaf.NotBefore) {
			continue
		}
		inter := ca.intermediates.Clone()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{Roots: ca.roots, Intermediates: inter, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		if err == nil {
			return nil
		}
	}
	return errors.New("leaf: does not chain to a trusted CA at the integrated time")
}
