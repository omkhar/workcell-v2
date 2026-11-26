// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Regression test for C32 (I5, I6), fixed by S-F25. A guest request line "METHOD x:https://HOST/PATH HTTP/1.1" parses to URL{Scheme:"x", Opaque:"https://HOST/PATH", Path:""}, so the token-endpoint matcher (signin.go) and the host check (terminate.go) see no path, but the reverse proxy would send the absolute-form "https://HOST/PATH" that a net/http upstream serves by RFC 9112 3.2.2. The handler now refuses such a target with 400 before any judge runs.
package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// c32do sends "METHOD x:<abs> HTTP/1.1" with Host host (and X-Api-Key key when set) through c and returns the status and body.
func c32do(t *testing.T, c *http.Client, method, host, abs, ctype, body, key string) (int, string) {
	t.Helper()
	req := must(http.NewRequest(method, "https://"+host+"/", strings.NewReader(body)))
	req.URL.Opaque, req.URL.Path = "x:"+abs, ""
	req.Host = host
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	return do(t, c, req)
}

func TestC32OpaqueRequestTarget(t *testing.T) {
	t.Parallel()
	t.Run("token-answer-reaches-guest", func(t *testing.T) {
		c, _, _, _ := signinFixture(t, &provider{}, &tokenBroker{})
		code, got := c32do(t, c, "POST", "login.example.com", "https://login.example.com/oauth/token", "application/x-www-form-urlencoded", "grant_type=authorization_code&code=c0de", "")
		if code != http.StatusBadRequest || strings.Contains(got, "sk-acc") || strings.Contains(got, "sk-ref") {
			t.Fatalf("I5: the guest read a real token through an opaque target: (%d, %q), want 400 and no token", code, got)
		}
	})
	t.Run("secret-forwarded-to-another-authority", func(t *testing.T) {
		addr, ca, _, _ := terminateFixture(t, &fakeBroker{value: "real-secret"})
		code, got := c32do(t, clientVia(addr, caPool(t, ca)), "GET", "example.com", "https://other.example/collect", "", "", testPlaceholder)
		if code != http.StatusBadRequest || strings.Contains(got, "real-secret") && strings.Contains(got, "other.example") {
			t.Fatalf("I6: upstream got the real secret for authority other.example: (%d, %q), want 400 and no secret", code, got)
		}
	})
}
