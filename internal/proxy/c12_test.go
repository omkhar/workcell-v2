// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F7, finding C12 of S-1005 (I5). swapRefresh sends a refresh token to the endpoint as url.QueryEscape spells it in a form, so a token holding +, / or =
// (base64-shaped) goes out as a%2Bb%2Fc%3D, and as encoding/json spells it in an object, where & < > go out as \u0026 \u003c \u003e. hide must replace
// both spellings as well as the verbatim bytes: an error answer that echoes the parameter or the body as received, in text or inside a JSON string, would
// otherwise carry the proxy's own spelling to the guest, one decode away from the real refresh token. That an IdP echoes is a precondition the attacker
// does not control.
package proxy

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// TestLearnHidesTheEncodedSpelling: the proxy's own url-encoded and json-escaped spellings of the refresh token are hidden with the token itself. Pass → the
// guest decodes a%2Bb%2Fc%3D%26 or a+b/c=\u0026 to the real refresh token → FAIL (I5).
func TestLearnHidesTheEncodedSpelling(t *testing.T) {
	t.Parallel()
	const real = "a+b/c=&"
	wire := string(must(json.Marshal(map[string]string{"refresh_token": real}))) // the body swapRefresh sends to a JSON endpoint
	esc := string(must(json.Marshal(real)))
	p := &Proxy{broker: &tokenBroker{refresh: []byte(real)}}
	rule := TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}
	for _, body := range []string{"error=invalid_grant&refresh_token=" + url.QueryEscape(real), `{"error":"invalid_grant","error_description":"bad refresh_token=` + url.QueryEscape(real) + `"}`, "bad body: " + wire} {
		got, err := p.learn(rule, 400, []byte(body))
		if decoded, _ := url.QueryUnescape(string(got)); err != nil || strings.Contains(decoded, real) || strings.Contains(string(got), esc[1:len(esc)-1]) {
			t.Errorf("learn(%q) = %q, %v; decodes to the real refresh token", body, got, err)
		}
	}
}
