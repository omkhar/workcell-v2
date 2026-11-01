// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package sigstore verifies a Sigstore bundle against a trusted root with the
// standard library alone (B5, I14): the leaf chains to a Fulcio CA at the Rekor
// integrated time, the Rekor signed entry timestamp binds the entry to the
// bundle, the leaf names the expected identity and issuer, and the signature
// covers the artifact digest or the DSSE pre-authentication encoding. The
// verifier never consults the wall clock.
package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// maxRoot caps a trusted root before it is parsed.
const maxRoot = 256 << 10

//go:embed trusted-root.json
var publicRootJSON []byte

// window is a validFor range; a nil End is open.
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

type certChain struct {
	Certificates []rawCert `json:"certificates"`
}

// authority is one Fulcio CA: its self-signed root, its intermediates and the
// window in which it issued leaves.
type authority struct {
	roots, intermediates *x509.CertPool
	validFor             window
}

// logKey is one Rekor log key. logID is the hex SHA-256 of its SPKI DER, which
// Rekor writes into every signed entry timestamp.
type logKey struct {
	keyID    []byte
	logID    string
	pub      *ecdsa.PublicKey
	validFor window
}

// Root is a parsed trusted root: Fulcio CAs and Rekor log keys.
type Root struct {
	cas  []authority
	logs []logKey
}

// ParseRoot parses the JSON form of a Sigstore trusted root. Only tlogs and
// certificateAuthorities are read: ctlogs and timestamp authorities are
// ignored, and so is a log key that is not ECDSA P-256, because no entry it
// signed can verify here.
func ParseRoot(b []byte) (*Root, error) {
	if len(b) > maxRoot {
		return nil, errors.New("trusted root: too large")
	}
	var in struct {
		Tlogs []struct {
			PublicKey struct {
				RawBytes []byte `json:"rawBytes"`
				ValidFor window `json:"validFor"`
			} `json:"publicKey"`
			LogID struct {
				KeyID []byte `json:"keyId"`
			} `json:"logId"`
		} `json:"tlogs"`
		CertificateAuthorities []struct {
			CertChain certChain `json:"certChain"`
			ValidFor  window    `json:"validFor"`
		} `json:"certificateAuthorities"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, errors.New("trusted root: not valid JSON")
	}
	r := &Root{}
	for _, l := range in.Tlogs {
		pub, err := x509.ParsePKIXPublicKey(l.PublicKey.RawBytes)
		if err != nil {
			return nil, errors.New("trusted root: bad log key")
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			continue
		}
		sum := sha256.Sum256(l.PublicKey.RawBytes)
		r.logs = append(r.logs, logKey{l.LogID.KeyID, hex.EncodeToString(sum[:]), ec, l.PublicKey.ValidFor})
	}
	for _, ca := range in.CertificateAuthorities {
		certs := ca.CertChain.Certificates
		if len(certs) == 0 {
			return nil, errors.New("trusted root: empty CA chain")
		}
		a := authority{x509.NewCertPool(), x509.NewCertPool(), ca.ValidFor}
		for i, c := range certs {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return nil, errors.New("trusted root: bad CA certificate")
			}
			if i == len(certs)-1 {
				a.roots.AddCert(cert)
			} else {
				a.intermediates.AddCert(cert)
			}
		}
		r.cas = append(r.cas, a)
	}
	return r, nil
}

// log returns the Rekor key with keyID, or nil.
func (r *Root) log(keyID []byte) *logKey {
	for i := range r.logs {
		if len(keyID) > 0 && string(r.logs[i].keyID) == string(keyID) {
			return &r.logs[i]
		}
	}
	return nil
}

var publicRoot = sync.OnceValue(func() *Root {
	r, err := ParseRoot(publicRootJSON)
	if err != nil {
		panic("sigstore: embedded trusted root: " + err.Error())
	}
	return r
})

// PublicRoot returns the embedded snapshot of the public Sigstore trusted
// root, parsed once. It panics if the snapshot does not parse, which only a
// broken build can cause; TestPublicRoot proves the shipped one does.
func PublicRoot() *Root { return publicRoot() }
