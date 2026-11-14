// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F7, finding C12 of S-1005 (I5). swapRefresh sends a refresh token to the endpoint as url.QueryEscape spells it, so a token holding +, / or =
// (base64-shaped) goes out as a%2Bb%2Fc%3D. hide must replace that spelling as well as the verbatim bytes: an error answer that echoes the parameter
// as received, in text or inside a JSON string, would otherwise carry the proxy's own spelling to the guest, one decode away from the real refresh
// token. That an IdP echoes the raw parameter is a precondition the attacker does not control.
package proxy

import (
	"net/url"
	"strings"
	"testing"
)

// TestLearnHidesTheEncodedSpelling: the proxy's own url-encoded spelling of the refresh token is hidden with the token itself. Pass → the guest
// decodes a%2Bb%2Fc%3D to the real refresh token → FAIL (I5).
func TestLearnHidesTheEncodedSpelling(t *testing.T) {
	t.Parallel()
	const real = "a+b/c="
	p := &Proxy{broker: &tokenBroker{refresh: []byte(real)}}
	rule := TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}
	for _, body := range []string{"error=invalid_grant&refresh_token=" + url.QueryEscape(real), `{"error":"invalid_grant","error_description":"bad refresh_token=` + url.QueryEscape(real) + `"}`} {
		got, err := p.learn(rule, 400, []byte(body))
		if decoded, _ := url.QueryUnescape(string(got)); err != nil || strings.Contains(decoded, real) {
			t.Errorf("learn(%q) = %q, %v; decodes to the real refresh token", body, got, err)
		}
	}
}
