// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func signer(id string) (Signer, Key) {
	seed := sha256.Sum256([]byte(id))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return Signer{id, priv}, Key{id, priv.Public().(ed25519.PublicKey), now.Add(365 * 24 * time.Hour)}
}

func digest(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

// sample is n providers by two architectures, each with a kept previous version.
func sample(n int, published time.Time) Manifest {
	m := Manifest{Serial: uint64(published.Unix()), Expires: published.Add(maxLifetime),
		Pins: map[string]map[string]Pin{}, Previous: map[string]map[string]Pin{}}
	for i := range n {
		name := fmt.Sprintf("provider%d", i)
		m.Pins[name], m.Previous[name] = map[string]Pin{}, map[string]Pin{}
		for _, arch := range []string{"amd64", "arm64"} {
			for set, v := range map[*map[string]map[string]Pin]string{&m.Pins: "1.2.4", &m.Previous: "1.2.3"} {
				url := fmt.Sprintf("https://github.com/example/%s/releases/download/v%s/%s-%s-unknown-linux-musl.tar.gz", name, v, name, arch)
				(*set)[name][arch] = Pin{v, url, digest(url)}
			}
		}
	}
	return m
}

func TestVerify(t *testing.T) {
	s1, k1 := signer("2026-a")
	s2, k2 := signer("2026-b")
	keys := []Key{k1}
	published := now.Add(-time.Hour)
	good := sample(2, published)
	mut := func(f func(*Manifest)) Manifest {
		var m Manifest
		b, _ := json.Marshal(good)
		_ = json.Unmarshal(b, &m)
		f(&m)
		return m
	}
	sign := func(m Manifest, s ...Signer) []byte { b, _ := Sign(m, s); return b }
	var env envelope
	_ = json.Unmarshal(sign(good, s1), &env)
	env.Payload[len(env.Payload)/2] ^= 1
	tampered, _ := json.Marshal(env)
	installed := good.Pins["provider0"]["amd64"]
	for _, tc := range []struct {
		name string
		env  []byte
		keys []Key
		now  time.Time
		last uint64
		want error
		use  string // version Select must return for provider0/amd64
	}{
		{"good", sign(good, s1), keys, now, 0, nil, "1.2.4"},
		{"unknown key", sign(good, s2), keys, now, 0, errSignature, ""},
		{"tampered payload byte", tampered, keys, now, 0, errSignature, ""},
		{"expired", sign(good, s1), keys, published.Add(maxLifetime), 0, errExpired, ""},
		{"expiry beyond 14 days", sign(mut(func(m *Manifest) { m.Expires = m.Expires.Add(time.Second) }), s1), keys, now, 0, errLifetime, ""},
		{"serial lower", sign(good, s1), keys, now, good.Serial + 1, errRollback, ""},
		{"serial equal", sign(good, s1), keys, now, good.Serial, nil, "1.2.4"},
		{"serial over 24h ahead", sign(sample(2, now.Add(maxSkew+time.Second)), s1), keys, now, 0, errFuture, ""},
		{"digest absent", sign(mut(func(m *Manifest) {
			m.Pins["provider1"]["arm64"] = Pin{Version: "1.2.4", URL: "https://example.com/x"}
		}), s1), keys, now, 0, errDigest, ""},
		{"rotation overlap, second key trusted", sign(good, s1, s2), []Key{k2}, now, 0, nil, "1.2.4"},
		{"key past NotAfter", sign(good, s1), []Key{{k1.ID, k1.Public, now}}, now, 0, errSignature, ""},
		{"installed withdrawn, previous kept", sign(mut(func(m *Manifest) { m.Withdrawn = []string{installed.SHA256} }), s1), keys, now, 0, nil, "1.2.3"},
		{"empty", nil, keys, now, 0, errFormat, ""},
		{"garbage", []byte(`{"payloadType":"x"}{`), keys, now, 0, errFormat, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Verify(tc.env, tc.keys, tc.now, tc.last)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err != nil {
				return
			}
			p, ok := Select(m, "provider0", "amd64")
			if !ok || p.Version != tc.use {
				t.Fatalf("Select = %+v %v, want version %s", p, ok, tc.use)
			}
		})
	}
}

func TestSizeAndSpeed(t *testing.T) {
	s1, k1 := signer("2026-a")
	m := sample(8, now.Add(-time.Hour))
	body, _ := json.Marshal(m)
	env, _ := Sign(m, []Signer{s1})
	sign := p50(1000, func() error { _, err := Sign(m, []Signer{s1}); return err })
	verify := p50(1000, func() error { _, err := Verify(env, []Key{k1}, now, 0); return err })
	if sign < 0 || verify < 0 {
		t.Fatal("sign or verify failed")
	}
	t.Logf("channel manifest_bytes=%d envelope_bytes=%d max_manifest_bytes=%d pins=8x2+previous",
		len(body), len(env), maxManifestBytes)
	t.Logf("channel sign_us=%d verify_us=%d samples=1000", sign.Microseconds(), verify.Microseconds())
}

// p50 is the median duration of n calls of f, or -1 if a call failed.
func p50(n int, f func() error) time.Duration {
	d := make([]time.Duration, n)
	for i := range d {
		t0 := time.Now()
		if f() != nil {
			return -1
		}
		d[i] = time.Since(t0)
	}
	slices.Sort(d)
	return d[n/2]
}

func FuzzVerify(f *testing.F) {
	s1, k1 := signer("2026-a")
	good, _ := Sign(sample(1, now.Add(-time.Hour)), []Signer{s1})
	for _, seed := range [][]byte{good, nil, []byte("{}"), []byte(`{"payloadType":"` + payloadType + `","payload":"e30=","signatures":[]}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Verify(b, []Key{k1}, now, 0)
		if err == nil {
			Select(m, "provider0", "amd64")
		}
	})
}
