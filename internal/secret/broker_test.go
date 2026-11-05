// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: credbroker/credbroker_test.go

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/proxy"
)

var _ proxy.Broker = (*Broker)(nil)

// syncBuffer is a ledger the test reads back.
type syncBuffer struct{ bytes.Buffer }

func (*syncBuffer) Sync() error { return nil }

func (b *syncBuffer) results() string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if _, rest, ok := strings.Cut(line, `"result":"`); ok {
			out = append(out, strings.TrimSuffix(rest, `"}`))
		}
	}
	return strings.Join(out, " ")
}

// testGrants sends one secret in either of two headers and another secret to
// a second host, matching the ledger tests' known.
func testGrants(t *testing.T) []Grant {
	a := "file:" + writeFile(t, "a", []byte("sk-a\n"), 0o600)
	return []Grant{
		{Name: "anthropic", Source: a, Host: "api.anthropic.com", Header: "x-api-key"},
		{Name: "anthropic", Source: a, Host: "api.anthropic.com", Header: "authorization"},
		{Name: "gemini", Source: "file:" + writeFile(t, "g", []byte("g-key"), 0o600), Host: "generativelanguage.googleapis.com", Header: "x-goog-api-key"},
	}
}

func newTestBroker(t *testing.T, log Ledger) *Broker {
	t.Helper()
	b, err := NewBroker(testGrants(t), log)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLookupReleasesOnlyGrantedPairs(t *testing.T) {
	log := &syncBuffer{}
	b := newTestBroker(t, log)
	for _, tc := range []struct{ host, header, want string }{
		{"api.anthropic.com", "x-api-key", "sk-a"},
		{"api.anthropic.com", "authorization", "sk-a"},
		{"generativelanguage.googleapis.com", "x-goog-api-key", "g-key"},
		{"api.anthropic.com", "x-goog-api-key", ""},
		{"generativelanguage.googleapis.com", "x-api-key", ""},
		{"api.anthropic.com", "Authorization", ""},
		{"API.anthropic.com", "x-api-key", ""},
		{"evil.example", "x-api-key", ""},
		{"api.openai.com", "authorization", ""},
	} {
		got, err := b.Lookup(context.Background(), tc.host, tc.header)
		if string(got) != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("Lookup(%q, %q) = %q, %v; want %q", tc.host, tc.header, got, err, tc.want)
		}
	}
	want := "granted granted granted not_granted not_granted not_granted not_granted not_granted not_granted"
	if got := log.results(); got != want {
		t.Fatalf("ledger results = %q, want %q", got, want)
	}
	if strings.Contains(log.String(), "sk-a") || strings.Contains(log.String(), "g-key") {
		t.Fatalf("ledger leaks a value: %s", log.String())
	}
}

// TestSignInGrant: a grant whose source is a sign-in flow releases nothing
// before a sign-in, then the access token to Lookup and the refresh token
// to Refresh; a refresh that issues an access token alone keeps the refresh
// token; a replaced token is zeroed where it was held; Tokens hands out
// copies; and the ledger holds the sign-in, the refresh and each release,
// never a byte of a token.
func TestSignInGrant(t *testing.T) {
	log := &syncBuffer{}
	grants := append(testGrants(t), Grant{Name: "oauth", Source: "signin:login.example/oauth/token", Host: "api.example", Header: "authorization"})
	b, err := NewBroker(grants, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	lookup := func(refresh bool) string {
		f := b.Lookup
		if refresh {
			f = b.Refresh
		}
		v, err := f(ctx, "api.example", "authorization")
		if err != nil {
			return "refused"
		}
		return string(v)
	}
	first := []byte("sk-acc-1")
	steps := []struct {
		name string
		step func() string
		want string
	}{
		{"lookup before", func() string { return lookup(false) }, "refused"},
		{"refresh before", func() string { return lookup(true) }, "refused"},
		{"refresh of a static grant", func() string {
			_, err := b.Refresh(ctx, "api.anthropic.com", "x-api-key")
			return fmt.Sprint(err != nil)
		}, "true"},
		{"issue to a static grant", func() string {
			v := []byte("x")
			err := b.Issue("api.anthropic.com", "x-api-key", v, nil)
			return fmt.Sprintf("%t %q", err != nil, v)
		}, `true "\x00"`},
		{"sign in", func() string { return fmt.Sprint(b.Issue("api.example", "authorization", first, []byte("sk-ref-1"))) }, "<nil>"},
		{"lookup", func() string { return lookup(false) }, "sk-acc-1"},
		{"refresh", func() string { return lookup(true) }, "sk-ref-1"},
		{"tokens are copies", func() string {
			a, r := b.Tokens("api.example", "authorization")
			a[0], r[0] = 'X', 'X'
			return lookup(false) + " " + lookup(true)
		}, "sk-acc-1 sk-ref-1"},
		{"a refresh issues a new access token", func() string { return fmt.Sprint(b.Issue("api.example", "authorization", []byte("sk-acc-2"), nil)) }, "<nil>"},
		{"the old one is zeroed", func() string { return fmt.Sprint(bytes.Equal(first, make([]byte, len(first)))) }, "true"},
		{"lookup after", func() string { return lookup(false) + " " + lookup(true) }, "sk-acc-2 sk-ref-1"},
	}
	for _, s := range steps {
		if got := s.step(); got != s.want {
			t.Errorf("%s: got %q, want %q", s.name, got, s.want)
		}
	}
	want := "not_signed_in not_signed_in not_granted not_granted signed_in granted refresh_granted granted refresh_granted refreshed granted refresh_granted"
	if got := log.results(); got != want {
		t.Errorf("ledger results = %q, want %q", got, want)
	}
	if strings.Contains(log.String(), "sk-") {
		t.Fatalf("ledger leaks a token: %s", log.String())
	}
	if a, r := b.Tokens("api.anthropic.com", "x-api-key"); a != nil || r != nil {
		t.Errorf("Tokens of a static grant = (%q, %q), want none", a, r)
	}
	b = newTestBroker(t, failingLog{sync: errors.New("io error")})
	b.tokens[pair{"api.anthropic.com", "x-api-key"}] = &tokens{}
	if err := b.Issue("api.anthropic.com", "x-api-key", []byte("sk-acc-1"), nil); err == nil {
		t.Error("Issue succeeded with a ledger that does not sync")
	}
}

func TestLookupWithholdsAValueItCannotResolve(t *testing.T) {
	log := &syncBuffer{}
	b, err := NewBroker([]Grant{{Name: "x", Source: "file:/nonexistent/secret", Host: "h", Header: "k"}}, log)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := b.Lookup(context.Background(), "h", "k"); err == nil || v != nil {
		t.Fatalf("Lookup = %q, %v; want an error", v, err)
	}
	if log.Len() != 0 {
		t.Fatalf("ledger = %q, want no release recorded", log.String())
	}
}

func TestRateLimitIsAFixedWindow(t *testing.T) {
	b := newTestBroker(t, &syncBuffer{})
	clock := time.Unix(1000, 0)
	b.now = func() time.Time { return clock }
	lookup := func() ([]byte, error) { return b.Lookup(context.Background(), "api.anthropic.com", "x-api-key") }
	for i := 0; i < rateLimit; i++ {
		if _, err := lookup(); err != nil {
			t.Fatalf("lookup %d refused: %v", i, err)
		}
	}
	for _, step := range []time.Duration{0, rateWindow - time.Nanosecond} {
		clock = time.Unix(1000, 0).Add(step)
		if v, err := lookup(); err == nil || v != nil {
			t.Fatalf("lookup %v into the full window = %q, %v; want rate_limited", step, v, err)
		}
	}
	clock = time.Unix(1000, 0).Add(rateWindow)
	if v, err := lookup(); err != nil || string(v) != "sk-a" {
		t.Fatalf("lookup in the next window = %q, %v", v, err)
	}
}

// TestDenialsSpendTheirOwnBudget bounds the denial records per window; an
// over-long lookup, unlike a not_granted one, leaves the grant quota alone.
func TestDenialsSpendTheirOwnBudget(t *testing.T) {
	for _, tc := range []struct {
		host      string
		wantGrant bool
	}{
		{strings.Repeat("h", maxLineBytes+1), true},
		{"evil.example", false},
	} {
		log := &syncBuffer{}
		b := newTestBroker(t, log)
		for i := 0; i < rateLimit+5; i++ {
			_, _ = b.Lookup(context.Background(), tc.host, "x-api-key")
		}
		if n := strings.Count(log.String(), "\n"); n != rateLimit {
			t.Errorf("host of %d bytes: %d denials recorded, want %d", len(tc.host), n, rateLimit)
		}
		if _, err := b.Lookup(context.Background(), "api.anthropic.com", "x-api-key"); (err == nil) != tc.wantGrant {
			t.Errorf("host of %d bytes: grant after the flood = %v, want granted %v", len(tc.host), err, tc.wantGrant)
		}
	}
}

func TestNewBrokerRefusesBadRows(t *testing.T) {
	row := Grant{Name: "n", Source: "file:/s", Host: "h", Header: "k"}
	for _, tc := range []struct {
		name string
		rows []Grant
	}{
		{"no name", []Grant{{Source: "file:/s", Host: "h", Header: "k"}}},
		{"no source", []Grant{{Name: "n", Host: "h", Header: "k"}}},
		{"no host", []Grant{{Name: "n", Source: "file:/s", Header: "k"}}},
		{"no header", []Grant{{Name: "n", Source: "file:/s", Host: "h"}}},
		{"duplicate pair", []Grant{row, {Name: "m", Source: "file:/t", Host: "h", Header: "k"}}},
	} {
		if _, err := NewBroker(tc.rows, &syncBuffer{}); err == nil {
			t.Errorf("%s: NewBroker accepted %+v", tc.name, tc.rows)
		}
	}
	if _, err := NewBroker([]Grant{row}, nil); err == nil {
		t.Error("NewBroker accepted a nil ledger")
	}
}

// failingLog fails every write or every sync.
type failingLog struct{ write, sync error }

func (f failingLog) Write(p []byte) (int, error) {
	if f.write != nil {
		return 0, f.write
	}
	return len(p), nil
}

func (f failingLog) Sync() error { return f.sync }

// recoveringLog fails its first write half way and then accepts everything.
type recoveringLog struct{ writes int }

func (r *recoveringLog) Write(p []byte) (int, error) {
	r.writes++
	if r.writes == 1 {
		return len(p) / 2, errors.New("disk full")
	}
	return len(p), nil
}

func (*recoveringLog) Sync() error { return nil }

// TestGrantIsWithheldWhenTheRecordIsNotDurable also keeps the ledger failed
// after a partial write: no later grant is released.
func TestGrantIsWithheldWhenTheRecordIsNotDurable(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  Ledger
	}{
		{"write fails", failingLog{write: errors.New("disk full")}},
		{"sync fails", failingLog{sync: errors.New("io error")}},
		{"partial write", &recoveringLog{}},
	} {
		b := newTestBroker(t, tc.log)
		for i := 0; i < 2; i++ {
			if v, err := b.Lookup(context.Background(), "api.anthropic.com", "x-api-key"); err == nil || v != nil {
				t.Errorf("%s: lookup %d = %q, %v; want withheld", tc.name, i, v, err)
			}
		}
	}
}
