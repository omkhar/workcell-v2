// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"time"
)

// Fulcio's OIDC issuer extension, a DER UTF8String. The older .1.1 (raw bytes) is not read.
var oidIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

type window struct {
	Start time.Time  `json:"start"`
	End   *time.Time `json:"end"`
}

func (w window) has(t time.Time) bool {
	return !t.Before(w.Start) && (w.End == nil || !t.After(*w.End))
}

type rawCert struct {
	RawBytes []byte `json:"rawBytes"`
}

type chain struct {
	Certificates []rawCert `json:"certificates"`
}

type authority struct {
	URI       string `json:"uri"`
	CertChain chain  `json:"certChain"`
	ValidFor  window `json:"validFor"`
}

type logKey struct {
	BaseURL   string `json:"baseUrl"`
	PublicKey struct {
		KeyDetails string `json:"keyDetails"`
		ValidFor   window `json:"validFor"`
	} `json:"publicKey"`
}

// TrustedRoot is the subset of Sigstore's trusted_root.json the spike reads.
type TrustedRoot struct {
	MediaType              string      `json:"mediaType"`
	Tlogs                  []logKey    `json:"tlogs"`
	CertificateAuthorities []authority `json:"certificateAuthorities"`
	Ctlogs                 []logKey    `json:"ctlogs"`
	TimestampAuthorities   []authority `json:"timestampAuthorities"`
}

type sigBundle struct {
	VerificationMaterial struct {
		Certificate *rawCert `json:"certificate"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
}

// VerifyKeyless checks a Sigstore bundle for an artifact with SHA-256 digest:
// the leaf chains to a Fulcio CA in root at the leaf's NotBefore, the signature
// covers digest, and the leaf names identity (SAN URI) and issuer. It does NOT
// check the SCT, the Rekor entry, its SET or inclusion proof, or a timestamp,
// so it cannot tell when the short-lived leaf signed.
func VerifyKeyless(bundleJSON []byte, root *TrustedRoot, digest []byte, identity, issuer string) error {
	var b sigBundle
	if err := json.Unmarshal(bundleJSON, &b); err != nil || b.MessageSignature == nil {
		return errors.New("bundle: no message signature")
	}
	if b.VerificationMaterial.Certificate == nil { // v0.1 and v0.2 bundles carry a chain instead; not read
		return errors.New("bundle: no v0.3 certificate")
	}
	leaf, err := x509.ParseCertificate(b.VerificationMaterial.Certificate.RawBytes)
	if err != nil {
		return err
	}
	chained := false
	for _, ca := range root.CertificateAuthorities {
		certs := ca.CertChain.Certificates
		if len(certs) == 0 || !ca.ValidFor.has(leaf.NotBefore) {
			continue
		}
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		for i, c := range certs {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return err
			}
			if i == len(certs)-1 {
				roots.AddCert(cert)
			} else {
				inter.AddCert(cert)
			}
		}
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: leaf.NotBefore,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		chained = chained || err == nil
	}
	if !chained {
		return errors.New("leaf does not chain to a Fulcio CA")
	}
	md := b.MessageSignature.MessageDigest
	if md.Algorithm != "SHA2_256" || !bytes.Equal(md.Digest, digest) {
		return errors.New("bundle digest is not the pinned digest")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, digest, b.MessageSignature.Signature) {
		return errors.New("signature does not verify")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity {
		return errors.New("identity mismatch")
	}
	for _, e := range leaf.Extensions {
		var got string
		if rest, err := asn1.UnmarshalWithParams(e.Value, &got, "utf8"); e.Id.Equal(oidIssuer) && err == nil && len(rest) == 0 && got == issuer {
			return nil
		}
	}
	return errors.New("issuer mismatch")
}
