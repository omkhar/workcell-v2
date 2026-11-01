// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestStart shows B9 against a server the test starts: Start returns at once
// whatever the server does, and checks at most once a day.
func TestStart(t *testing.T) {
	s1, k1 := signer("2026-a")
	good, _ := Sign(sample(8, now.Add(-time.Hour)), []Signer{s1})
	expired, _ := Sign(sample(8, now.Add(-maxLifetime-time.Hour)), []Signer{s1})
	for _, tc := range []struct {
		name  string
		serve func(w http.ResponseWriter, r *http.Request)
		want  error // from the background check; nil means it stored the manifest
	}{
		{"hung", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, context.DeadlineExceeded},
		{"ok", func(w http.ResponseWriter, r *http.Request) { w.Write(good) }, nil},
		{"garbage", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }, errFormat},
		{"oversize", func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte{' '}, maxManifestBytes+1)) }, errTooBig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				tc.serve(w, r)
			}))
			defer srv.Close()
			c := &Checker{URL: srv.URL, Client: srv.Client(), Dir: t.TempDir(), Keys: []Key{k1}, Timeout: 300 * time.Millisecond}
			t0 := time.Now()
			m, done := c.Start(now)
			started := time.Since(t0)
			if m != nil || done == nil {
				t.Fatalf("first start: manifest %v, done %v", m, done)
			}
			err := <-done
			checked := time.Since(t0)
			if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("check: %v, want %v", err, tc.want)
			}
			t.Logf("channel start_%s_ms=%.3f check_%s_ms=%.3f", tc.name, ms(started), tc.name, ms(checked))
			before := requests.Load()
			m, done = c.Start(now.Add(23 * time.Hour))
			if done != nil || (m != nil) != (tc.want == nil) {
				t.Fatalf("second start the same day: manifest %v, done %v", m, done)
			}
			if tc.name == "ok" {
				t.Logf("channel check_requests_second_call_same_day=%d applied_serial=%d", requests.Load()-before, m.Serial)
			}
			if _, done = c.Start(now.Add(24 * time.Hour)); done == nil {
				t.Fatal("no check after 24 hours")
			}
			<-done
		})
	}
	t.Run("expired", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest"), expired, 0o600); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		c := &Checker{URL: srv.URL, Client: srv.Client(), Dir: dir, Keys: []Key{k1}, Timeout: time.Second}
		m, done := c.Start(now)
		<-done
		if m != nil {
			t.Fatalf("expired manifest applied: %+v", m)
		}
		t.Logf("channel expired_keeps_installed=%v", m == nil)
	})
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
