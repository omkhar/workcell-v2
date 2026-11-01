// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package channel is the B-820 spike: a signed channel manifest, its
// verifier, a background daily check, and a minimal keyless verifier.
// Findings are in notes.md.
package channel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	payloadType      = "application/vnd.workcell.channel+json"
	maxManifestBytes = 64 << 10
	maxLifetime      = 14 * 24 * time.Hour // B7
	maxSkew          = 24 * time.Hour      // how far ahead of the client clock a serial may be
)

var (
	errFormat, errSignature = errors.New("malformed envelope or manifest"), errors.New("no valid signature by a trusted key")
	errExpired, errLifetime = errors.New("manifest expired"), errors.New("manifest expiry beyond serial plus 14 days")
	errRollback, errFuture  = errors.New("serial lower than the last one seen"), errors.New("serial too far in the future")
	errDigest               = errors.New("pin without a valid sha256 or https url")
)

// Key is a trusted channel key. A client holds a list of them; two overlap during rotation.
type Key struct {
	ID       string
	Public   ed25519.PublicKey
	NotAfter time.Time
}

// Signer holds a private key; only the publish job (and tests) have one.
type Signer struct {
	ID      string
	Private ed25519.PrivateKey
}

type Pin struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Manifest is the signed payload. Pins and Previous map name, then arch, to a pin.
type Manifest struct {
	Serial    uint64                    `json:"serial"` // publication time, unix seconds
	Expires   time.Time                 `json:"expires"`
	Pins      map[string]map[string]Pin `json:"pins"`
	Previous  map[string]map[string]Pin `json:"previous,omitempty"`
	Withdrawn []string                  `json:"withdrawn,omitempty"`
}

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// pae is DSSE's pre-authentication encoding: the signature covers the type and the payload.
func pae(typ string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "DSSEv1 %d %s %d ", len(typ), typ, len(body))
	b.Write(body)
	return b.Bytes()
}

// Sign marshals m and signs it with every signer, in order.
func Sign(m Manifest, signers []Signer) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	env := envelope{PayloadType: payloadType, Payload: body}
	for _, s := range signers {
		env.Signatures = append(env.Signatures, signature{s.ID, ed25519.Sign(s.Private, pae(payloadType, body))})
	}
	return json.Marshal(env)
}

func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil || d.More() {
		return errFormat
	}
	return nil
}

// Verify returns the manifest only if one signature by a key in keys that is
// valid at now covers it, it has not expired, and its serial is no lower than
// lastSerial (I14). Keys, clock and state are parameters.
func Verify(raw []byte, keys []Key, now time.Time, lastSerial uint64) (*Manifest, error) {
	var env envelope
	if len(raw) > maxManifestBytes || strict(raw, &env) != nil || env.PayloadType != payloadType {
		return nil, errFormat
	}
	msg, ok := pae(env.PayloadType, env.Payload), false
	for _, s := range env.Signatures {
		for _, k := range keys {
			if s.KeyID == k.ID && now.Before(k.NotAfter) && len(k.Public) == ed25519.PublicKeySize &&
				ed25519.Verify(k.Public, msg, s.Sig) {
				ok = true
			}
		}
	}
	if !ok {
		return nil, errSignature
	}
	var m Manifest
	if err := strict(env.Payload, &m); err != nil || m.Serial > 1<<40 {
		return nil, errFormat
	}
	published := time.Unix(int64(m.Serial), 0)
	switch {
	case m.Serial < lastSerial:
		return nil, errRollback
	case published.After(now.Add(maxSkew)):
		return nil, errFuture
	case m.Expires.After(published.Add(maxLifetime)):
		return nil, errLifetime
	case !now.Before(m.Expires):
		return nil, errExpired
	}
	for _, set := range []map[string]map[string]Pin{m.Pins, m.Previous} {
		for _, arches := range set {
			for _, p := range arches {
				if d, err := hex.DecodeString(p.SHA256); err != nil || len(d) != 32 || p.SHA256 != strings.ToLower(p.SHA256) ||
					!strings.HasPrefix(p.URL, "https://") {
					return nil, errDigest
				}
			}
		}
	}
	return &m, nil
}

// Select picks what to run for name and arch: the current pin unless it is
// withdrawn, else the kept previous one (B9, B10). Both come from the signed
// manifest, so a rollback stays inside I14. ok is false when neither is usable.
func Select(m *Manifest, name, arch string) (p Pin, ok bool) {
	withdrawn := map[string]bool{}
	for _, d := range m.Withdrawn {
		withdrawn[d] = true
	}
	for _, set := range []map[string]map[string]Pin{m.Pins, m.Previous} {
		if p, ok := set[name][arch]; ok && !withdrawn[p.SHA256] {
			return p, true
		}
	}
	return Pin{}, false
}
