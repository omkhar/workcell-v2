// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package channel is the client's side of ADR-004: the signed channel manifest,
// its verifier and selector, and its builder from the rows of pins/ (I14, B7).
package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

const (
	PayloadType = "application/vnd.workcell.channel+json" // a format old clients must not misread gets a new one
	MaxBytes    = 64 << 10                                // the most the client reads of channel.json
	lifetime    = 14 * 24 * 60 * 60                       // B7: expires is at most serial plus this, in seconds
	skew        = 24 * 60 * 60                            // how far ahead of the client clock a serial may be
)

var (
	errFormat, errSignature = errors.New("malformed channel manifest"), errors.New("no valid signature by a trusted key")
	errRollback, errFuture  = errors.New("serial lower than the last one seen"), errors.New("serial more than a day ahead")
	errLifetime, errExpired = errors.New("expiry beyond serial plus 14 days"), errors.New("manifest expired")
	errPin                  = errors.New("pin without a 64-hex sha256 or an https url")
)

// Key is one entry of the client's key table; two overlap during rotation.
type Key struct {
	Public   ed25519.PublicKey
	NotAfter time.Time
}

// Keys is the table built into the client: empty until H-905 hands over the project's key (B7),
// so until then a client installs from the channel only with a key its [update] table names.
var Keys []Key

// ID is the key ID, the hex SHA-256 of the public half, derived on both sides (W6).
func (k Key) ID() string { h := sha256.Sum256(k.Public); return hex.EncodeToString(h[:]) }

// Pin is one artifact; Released is when its version was selected (B10 counts from it).
type Pin struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Released int64  `json:"released,omitempty"`
}

// Manifest is the signed payload. Pins and Previous map name, then arch, to a pin.
type Manifest struct {
	Serial    int64                     `json:"serial"` // publication time, unix seconds
	Expires   int64                     `json:"expires"`
	Pins      map[string]map[string]Pin `json:"pins"`
	Previous  map[string]map[string]Pin `json:"previous,omitempty"`
	Withdrawn []string                  `json:"withdrawn,omitempty"`
}

// envelope is channel.json itself: a DSSE envelope over the manifest.
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
func pae(body []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(PayloadType), PayloadType, len(body), body)
}

// Sign signs the marshalled manifest with every key, in order, each under its own ID.
func Sign(body []byte, keys []ed25519.PrivateKey) ([]byte, error) {
	env := envelope{PayloadType: PayloadType, Payload: body}
	for _, k := range keys {
		env.Signatures = append(env.Signatures, signature{Key{Public: k.Public().(ed25519.PublicKey)}.ID(), ed25519.Sign(k, pae(body))})
	}
	return json.Marshal(env)
}

// decode parses exactly one JSON value, refusing unknown fields when strict.
func decode(b []byte, v any, strict bool) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if strict {
		d.DisallowUnknownFields()
	}
	if err := d.Decode(v); err != nil {
		return errFormat
	}
	if _, err := d.Token(); err != io.EOF { // nothing may follow the value
		return errFormat
	}
	return nil
}

// Verify returns the manifest in raw only if ADR-004's checks pass, in its order:
// size, strict envelope, a signature by a key trusted at now, serial and expiry
// against now and lastSerial, digests and URLs. Unknown payload fields are ignored.
func Verify(raw []byte, keys []Key, now time.Time, lastSerial int64) (*Manifest, error) {
	var env envelope
	if len(raw) > MaxBytes || decode(raw, &env, true) != nil || env.PayloadType != PayloadType {
		return nil, errFormat
	}
	msg := pae(env.Payload)
	if !slices.ContainsFunc(env.Signatures, func(s signature) bool {
		return slices.ContainsFunc(keys, func(k Key) bool {
			return s.KeyID == k.ID() && now.Before(k.NotAfter) && len(k.Public) == ed25519.PublicKeySize && ed25519.Verify(k.Public, msg, s.Sig)
		})
	}) {
		return nil, errSignature
	}
	var m Manifest
	if decode(env.Payload, &m, false) != nil {
		return nil, errFormat
	}
	switch {
	case m.Serial < lastSerial:
		return nil, errRollback
	case m.Serial > now.Unix()+skew:
		return nil, errFuture
	case m.Expires > m.Serial+lifetime:
		return nil, errLifetime
	case m.Expires <= now.Unix():
		return nil, errExpired
	}
	for _, set := range []map[string]map[string]Pin{m.Pins, m.Previous} {
		for _, arches := range set {
			for _, p := range arches {
				if !pins.IsSHA256(p.SHA256) || pins.HTTPSURL(p.URL) != nil {
					return nil, errPin
				}
			}
		}
	}
	if slices.ContainsFunc(m.Withdrawn, func(d string) bool { return !pins.IsSHA256(d) }) {
		return nil, errPin
	}
	return &m, nil
}

// Select is what name may install on arch: the current pin, then the kept previous one, each left
// out when withdrawn, so that a rollback stays inside I14 (B9, B10); the first is what to install.
func Select(m *Manifest, name, arch string) (out []Pin) {
	for _, set := range []map[string]map[string]Pin{m.Pins, m.Previous} {
		if p, ok := set[name][arch]; ok && !slices.Contains(m.Withdrawn, p.SHA256) {
			out = append(out, p)
		}
	}
	return out
}

// Build makes the manifest of rows as of now: each release under pins, each prior
// version under previous, and every withdrawn digest, sorted, so the same rows
// give the same bytes.
func Build(rows []pins.Pin, now time.Time) Manifest {
	m := Manifest{Serial: now.Unix(), Expires: now.Unix() + lifetime,
		Pins: map[string]map[string]Pin{}, Previous: map[string]map[string]Pin{}}
	for _, r := range rows {
		if r.Version == "" {
			continue // an unpinned row has nothing to deliver
		}
		m.Pins[r.Name] = entry(r.Release, r.Released.Unix())
		if r.Previous != nil {
			m.Previous[r.Name] = entry(*r.Previous, 0)
		}
		m.Withdrawn = append(m.Withdrawn, r.Withdrawn...)
	}
	slices.Sort(m.Withdrawn)
	m.Withdrawn = slices.Compact(m.Withdrawn)
	return m
}

func entry(r pins.Release, released int64) map[string]Pin {
	e := map[string]Pin{}
	for arch, a := range r.Artifacts {
		e[arch] = Pin{r.Version, a.URL, a.SHA256, released}
	}
	return e
}
