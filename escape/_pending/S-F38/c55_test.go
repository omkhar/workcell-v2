// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C55 of S-1007 (I5): the token endpoint is claimed by the spelling of its path, so a spelling the provider's router also serves is relayed unread.
// Fix unit S-F38 moves this file to internal/proxy/c55_test.go.

package proxy

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestC55TokenEndpointFormatSuffix (I5): the token host's router serves the token action with a format suffix too, as a Rails `(.:format)` route does, so
// the same code grant sent to /oauth/token.json, .xml or .JSON is answered as /oauth/token. tokenEndpoint claims none of those spellings, tokenResponse
// relays an answer it did not claim unread, and the guest reads the real access and refresh tokens, where the honest spelling returns the placeholders.
// The second arm's provider answers in form encoding, as GitHub's does. The provider is a loopback server of the test (T8).
func TestC55TokenEndpointFormatSuffix(t *testing.T) {
	for _, form := range []bool{false, true} {
		t.Run(map[bool]string{false: "json answer", true: "form answer"}[form], func(t *testing.T) {
			var issued atomic.Int32
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Host != "login.example.com" || r.Method != http.MethodPost || strings.TrimSuffix(r.URL.Path, path.Ext(r.URL.Path)) != tokenEndpointPath || !strings.Contains(string(body), "grant_type=authorization_code") {
					http.NotFound(w, r)
				} else if n := issued.Add(1); form {
					w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
					fmt.Fprintf(w, "access_token=sk-acc-%d&scope=&token_type=bearer", n)
				} else {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"access_token":"sk-acc-%d","token_type":"Bearer","expires_in":3600,"refresh_token":"sk-ref-%d"}`, n, n)
				}
			}))
			t.Cleanup(up.Close)
			roots := x509.NewCertPool()
			roots.AddCert(up.Certificate())
			px, _, _ := testProxy(t, "api.example.com:443 login.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
			px.upstreamRoots = roots
			ca := must(NewSessionCA([]string{"api.example.com", "login.example.com"}, time.Now().Add(time.Hour)))
			must(0, px.Terminate(ca, &tokenBroker{}, []TerminateRule{{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}}))
			c := clientVia(listen(t, px, 443), caPool(t, ca))
			const login, grant, ctype = "https://login.example.com", "grant_type=authorization_code&code=c0de", "application/x-www-form-urlencoded"
			code, body := send(t, c, "POST", login+tokenEndpointPath, ctype, grant) // send fails the test on a real token in any answer (I5)
			if !form && (code != 200 || !strings.Contains(body, testPlaceholder) || !strings.Contains(body, testRefreshPlaceholder)) {
				t.Errorf("the honest spelling: got (%d, %q), want 200 with the two placeholders", code, body)
			}
			for _, ext := range []string{".json", ".xml", ".JSON"} {
				code, body := send(t, c, "POST", login+tokenEndpointPath+ext, ctype, grant)
				t.Logf("POST %s%s: %d %q", tokenEndpointPath, ext, code, body)
			}
		})
	}
}
