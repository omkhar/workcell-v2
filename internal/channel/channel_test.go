// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// signer derives a key pair from a label, trusted for a year from now.
func signer(label string) (ed25519.PrivateKey, Key) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, Key{priv.Public().(ed25519.PublicKey), now.Add(365 * 24 * time.Hour)}
}

func sum(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

// sample is n providers by two architectures, each with a kept previous version.
func sample(n int, published time.Time) Manifest {
	m := Manifest{Serial: published.Unix(), Expires: published.Unix() + lifetime,
		Pins: map[string]map[string]Pin{}, Previous: map[string]map[string]Pin{}}
	for i := range n {
		name := fmt.Sprintf("provider%d", i)
		m.Pins[name], m.Previous[name] = map[string]Pin{}, map[string]Pin{}
		for _, arch := range []string{"amd64", "arm64"} {
			for set, v := range map[*map[string]map[string]Pin]string{&m.Pins: "1.2.4", &m.Previous: "1.2.3"} {
				url := fmt.Sprintf("https://github.com/example/%s/releases/download/v%s/%s-%s.tar.gz", name, v, name, arch)
				(*set)[name][arch] = Pin{v, url, sum(url), published.Unix() - 3600}
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
	sign := func(m Manifest, s ...ed25519.PrivateKey) []byte {
		body, _ := json.Marshal(m)
		b, _ := Sign(body, s)
		return b
	}
	// mut signs a copy of good changed by f; edit signs a copy of the good envelope changed by f.
	mut := func(f func(*Manifest)) []byte {
		var m Manifest
		b, _ := json.Marshal(good)
		_ = json.Unmarshal(b, &m)
		f(&m)
		return sign(m, s1)
	}
	edit := func(f func(*envelope)) []byte {
		var e envelope
		_ = json.Unmarshal(sign(good, s1), &e)
		f(&e)
		b, _ := json.Marshal(e)
		return b
	}
	setPin := func(f func(*Pin)) func(*Manifest) {
		return func(m *Manifest) { p := m.Pins["provider1"]["arm64"]; f(&p); m.Pins["provider1"]["arm64"] = p }
	}
	body, _ := json.Marshal(good)
	extra, _ := Sign(bytes.Replace(body, []byte(`{"serial"`), []byte(`{"extra":{"x":1},"serial"`), 1), []ed25519.PrivateKey{s1})
	installed := good.Pins["provider0"]["amd64"]
	for _, tc := range []struct {
		name string
		env  []byte
		keys []Key
		now  time.Time
		last int64
		want error
		use  string // version Select must return for provider0/amd64; "" means none
	}{
		{"good", sign(good, s1), keys, now, 0, nil, "1.2.4"},
		{"wrong key", sign(good, s2), keys, now, 0, errSignature, ""},
		{"corrupted signature byte", edit(func(e *envelope) { e.Signatures[0].Sig[7] ^= 1 }), keys, now, 0, errSignature, ""},
		{"corrupted payload byte", edit(func(e *envelope) { e.Payload[len(e.Payload)/2] ^= 1 }), keys, now, 0, errSignature, ""},
		{"key past NotAfter", sign(good, s1), []Key{{k1.Public, now}}, now, 0, errSignature, ""},
		{"no signature", edit(func(e *envelope) { e.Signatures = nil }), keys, now, 0, errSignature, ""},
		{"expired", sign(good, s1), keys, time.Unix(good.Expires, 0), 0, errExpired, ""},
		{"expiry beyond 14 days", mut(func(m *Manifest) { m.Expires++ }), keys, now, 0, errLifetime, ""},
		{"serial below last seen", sign(good, s1), keys, now, good.Serial + 1, errRollback, ""},
		{"serial equal to last seen", sign(good, s1), keys, now, good.Serial, nil, "1.2.4"},
		{"serial a day ahead", sign(sample(2, now.Add(skew*time.Second+time.Second)), s1), keys, now, 0, errFuture, ""},
		{"negative serial", mut(func(m *Manifest) { m.Serial = -1 }), keys, now, 0, errRollback, ""},
		{"oversized", append(sign(good, s1), bytes.Repeat([]byte(" "), MaxBytes)...), keys, now, 0, errFormat, ""},
		{"other payloadType", edit(func(e *envelope) { e.PayloadType = PayloadType + ";v=2" }), keys, now, 0, errFormat, ""},
		{"unknown envelope field", bytes.Replace(sign(good, s1), []byte(`{"payloadType"`), []byte(`{"x":1,"payloadType"`), 1),
			keys, now, 0, errFormat, ""},
		{"unknown payload field ignored", extra, keys, now, 0, nil, "1.2.4"},
		{"trailing bytes", append(sign(good, s1), '{'), keys, now, 0, errFormat, ""},
		{"short digest", mut(setPin(func(p *Pin) { p.SHA256 = p.SHA256[:63] })), keys, now, 0, errPin, ""},
		{"uppercase digest", mut(setPin(func(p *Pin) { p.SHA256 = "A" + p.SHA256[1:] })), keys, now, 0, errPin, ""},
		{"http url", mut(setPin(func(p *Pin) { p.URL = "http://" + p.URL[8:] })), keys, now, 0, errPin, ""},
		{"short digest in previous", mut(func(m *Manifest) {
			m.Previous["provider1"]["arm64"] = Pin{Version: "1.2.3", URL: "https://example.com/x", SHA256: "abc"}
		}), keys, now, 0, errPin, ""},
		{"short digest in withdrawn", mut(func(m *Manifest) { m.Withdrawn = []string{"abc"} }), keys, now, 0, errPin, ""},
		{"two signatures, only the second key trusted", sign(good, s1, s2), []Key{k2}, now, 0, nil, "1.2.4"},
		{"installed withdrawn, previous selected", mut(func(m *Manifest) { m.Withdrawn = []string{installed.SHA256} }),
			keys, now, 0, nil, "1.2.3"},
		{"no current pin, previous selected", mut(func(m *Manifest) { delete(m.Pins, "provider0") }), keys, now, 0, nil, "1.2.3"},
		{"both withdrawn, nothing selected", mut(func(m *Manifest) {
			m.Withdrawn = []string{installed.SHA256, good.Previous["provider0"]["amd64"].SHA256}
		}), keys, now, 0, nil, ""},
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
			if p, ok := Select(m, "provider0", "amd64"); ok != (tc.use != "") || p.Version != tc.use {
				t.Fatalf("Select = %+v %v, want version %q", p, ok, tc.use)
			}
		})
	}
}

func TestBuild(t *testing.T) {
	release := func(v, name string) pins.Release {
		return pins.Release{Version: v, Artifacts: map[string]pins.Artifact{
			"arm64": {URL: "https://example.com/" + name + "/" + v + "/arm64", SHA256: sum(name + v + "arm64")},
			"amd64": {URL: "https://example.com/" + name + "/" + v + "/amd64", SHA256: sum(name + v + "amd64")},
		}}
	}
	rows := []pins.Pin{
		{Name: "b", Release: release("2.0", "b"), Released: now.Add(-48 * time.Hour), Previous: ptr(release("1.9", "b")),
			Withdrawn: []string{sum("b2.0arm64"), sum("b1.8amd64")}},
		{Name: "a", Release: release("5", "a"), Released: now.Add(-time.Hour), Withdrawn: []string{sum("b1.8amd64")}},
		{Name: "c", Released: now}, // unpinned: no entry
	}
	first, _ := json.Marshal(Build(rows, now))
	again, _ := json.Marshal(Build(rows, now))
	if !bytes.Equal(first, again) {
		t.Fatalf("the same rows built twice differ:\n%s\n%s", first, again)
	}
	m := Build(rows, now)
	wantPin := Pin{"2.0", "https://example.com/b/2.0/arm64", sum("b2.0arm64"), now.Add(-48 * time.Hour).Unix()}
	wantPrev := Pin{"1.9", "https://example.com/b/1.9/amd64", sum("b1.9amd64"), 0}
	wantGone := []string{sum("b1.8amd64"), sum("b2.0arm64")}
	slices.Sort(wantGone)
	switch {
	case m.Serial != now.Unix() || m.Expires != m.Serial+lifetime:
		t.Fatalf("serial %d expires %d, want %d and %d", m.Serial, m.Expires, now.Unix(), now.Unix()+lifetime)
	case m.Pins["b"]["arm64"] != wantPin:
		t.Fatalf("pins b/arm64 = %+v, want %+v", m.Pins["b"]["arm64"], wantPin)
	case m.Previous["b"]["amd64"] != wantPrev:
		t.Fatalf("previous b/amd64 = %+v, want %+v", m.Previous["b"]["amd64"], wantPrev)
	case len(m.Pins) != 2:
		t.Fatalf("pins %v, want a and b only", m.Pins)
	case len(m.Previous["a"]) != 0 || m.Pins["a"]["amd64"].Version != "5":
		t.Fatalf("row a: previous %+v pins %+v", m.Previous["a"], m.Pins["a"])
	case !slices.Equal(m.Withdrawn, wantGone):
		t.Fatalf("withdrawn %v, want %v sorted and deduplicated", m.Withdrawn, wantGone)
	}
	s1, k1 := signer("2026-a")
	body, _ := json.Marshal(m)
	env, err := Sign(body, []ed25519.PrivateKey{s1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, []Key{k1}, now.Add(time.Hour), 0); err != nil {
		t.Fatalf("a built manifest does not verify: %v", err)
	}
	if p, ok := Select(&m, "b", "arm64"); !ok || p.Version != "1.9" {
		t.Fatalf("Select b/arm64 = %+v %v, want the previous 1.9, as 2.0's digest is withdrawn", p, ok)
	}
}

func ptr[T any](v T) *T { return &v }

func FuzzVerify(f *testing.F) {
	s1, k1 := signer("2026-a")
	body, _ := json.Marshal(sample(1, now.Add(-time.Hour)))
	good, _ := Sign(body, []ed25519.PrivateKey{s1})
	for _, seed := range [][]byte{good, nil, []byte("{}"),
		[]byte(`{"payloadType":"` + PayloadType + `","payload":"e30=","signatures":[]}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Verify(b, []Key{k1}, now, 0)
		if err != nil {
			return
		}
		if _, ok := Select(m, "provider0", "amd64"); !ok {
			t.Fatalf("a verified manifest selects nothing for provider0/amd64: %+v", m)
		}
	})
}
