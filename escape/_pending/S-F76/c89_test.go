// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C89 of S-1007 sweep 4 (I5, A4): the swap puts the real secret into any request to the bound host, and the answer of a host that is not a sign-in host passes to the guest unread. A provider that rotates a token for its holder (GitLab: POST /api/v4/personal_access_tokens/self/rotate) then mints a new real credential of the operator's account straight into the guest, which should never hold more than the placeholder.
// Parked under escape/_pending/S-F76 until the fix unit S-F76 moves it to internal/proxy/c89_test.go.
package proxy

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestC89MintedCredentialReachesTheGuest: real terminating Proxy, an unnarrowed private-token rule and a loopback upstream that models the provider: it answers 401 to any value but the real one, rotates at the rotate path and serves the account elsewhere. Controls: an honest GET /api/v4/user is served, so the upstream saw the real value; a rotate without the placeholder mints nothing. The minted token must not reach the guest; how a fix refuses is not judged.
func TestC89MintedCredentialReachesTheGuest(t *testing.T) {
	t.Parallel()
	const real, minted, rotate = "glpat-OLD-REAL", "glpat-NEW-REAL", "/api/v4/personal_access_tokens/self/rotate"
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Header.Get("Private-Token") != real:
			http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
		case r.Method == http.MethodPost && r.URL.Path == rotate:
			_, _ = w.Write([]byte(`{"id":42,"token":"` + minted + `"}`))
		default:
			_, _ = w.Write([]byte(`{"id":1,"username":"operator"}`))
		}
	}))
	t.Cleanup(up.Close)
	px, _, _ := testProxy(t, "gitlab.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
	px.upstreamRoots = x509.NewCertPool()
	px.upstreamRoots.AddCert(up.Certificate())
	ca := must(NewSessionCA([]string{"gitlab.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: real}, []TerminateRule{{Host: "gitlab.example.com", Header: "private-token", Placeholder: testPlaceholder}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	if code, body := send(t, c, "GET", "https://gitlab.example.com/api/v4/user", "", "", "Private-Token", testPlaceholder); code != http.StatusOK || !strings.Contains(body, "operator") {
		t.Errorf("control: GET /api/v4/user with the placeholder: got (%d, %q), want the account served with the real value seen upstream", code, body)
	}
	if code, body := send(t, c, "POST", "https://gitlab.example.com"+rotate, "", "", "Private-Token", "glpat-bogus"); code != http.StatusUnauthorized || strings.Contains(body, minted) {
		t.Errorf("control: POST rotate without the placeholder: got (%d, %q), want 401 and nothing minted", code, body)
	}
	if _, body := send(t, c, "POST", "https://gitlab.example.com"+rotate, "", "", "Private-Token", testPlaceholder); strings.Contains(body, minted) {
		t.Errorf("I5/A4: the guest read %q: the proxy signed a request that mints a credential and passed the answer unread", body)
	}
}
