// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C55 of S-1007 (I5): the token endpoint is claimed by the spelling of its path, so a spelling the provider's router also serves is relayed unread.
// Fix unit S-F38 moved this file here from escape/_pending/S-F38/ and closes it on the response side.

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

// TestC55TokenEndpointFormatSuffix (I5): the token host's router serves the token action with a format suffix too, as a Rails `(.:format)` route does, so the same code grant sent to /oauth/token.json, .xml or .JSON is answered as /oauth/token. tokenEndpoint claims none of those spellings, tokenResponse relays an answer it did not claim unread, and the guest reads the real access and refresh tokens, where the honest spelling returns the placeholders. The second arm's provider answers in form encoding, as GitHub's does. The provider is a loopback server of the test (T8).
func TestC55TokenEndpointFormatSuffix(t *testing.T) {
	for _, form := range []bool{false, true} {
		t.Run(map[bool]string{false: "json answer", true: "form answer"}[form], func(t *testing.T) {
			const login, grant, ctype, pending = "https://login.example.com", "grant_type=authorization_code&code=c0de", "application/x-www-form-urlencoded", `{"error":"authorization_pending"}`
			var issued atomic.Int32
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Host != "login.example.com" || r.Method != http.MethodPost || strings.TrimSuffix(r.URL.Path, path.Ext(r.URL.Path)) != tokenEndpointPath || !strings.Contains(string(body), "grant_type=authorization_code") {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, pending) // every other request is answered as a device flow's poll is: a 2xx JSON object with no token in it
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
			px, log, _ := testProxy(t, "api.example.com:443 login.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
			px.upstreamRoots = roots
			ca := must(NewSessionCA([]string{"api.example.com", "login.example.com"}, time.Now().Add(time.Hour)))
			must(0, px.Terminate(ca, &tokenBroker{}, []TerminateRule{{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}}))
			c := clientVia(listen(t, px, 443), caPool(t, ca))
			code, body := send(t, c, "POST", login+tokenEndpointPath, ctype, grant) // send fails the test on a real token in any answer (I5)
			if !form && (code != 200 || !strings.Contains(body, testPlaceholder) || !strings.Contains(body, testRefreshPlaceholder)) {
				t.Errorf("the honest spelling: got (%d, %q), want 200 with the two placeholders", code, body)
			}
			before := len(denies(t, px, log)) // the form arm's honest answer is refused too: a 2xx that is not a JSON object
			for _, ext := range []string{".json", ".xml", ".JSON"} {
				if code, body := send(t, c, "POST", login+tokenEndpointPath+ext, ctype, grant); code != 502 || body != "" {
					t.Errorf("POST %s%s: got (%d, %q), want an empty 502", tokenEndpointPath, ext, code, body)
				}
			}
			if code, body := send(t, c, "POST", login+"/device/token", ctype, "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=d0de"); code != 200 || body != pending {
				t.Errorf("a 2xx with no token field on a path not claimed: got (%d, %q), want it through as (200, %q)", code, body, pending)
			}
			if d := denies(t, px, log)[before:]; len(d) != 3 || d[2].Reason != "token_answer_refused" || d[2].Host != "login.example.com" {
				t.Errorf("deny lines since the honest spelling = %+v, want three token_answer_refused for login.example.com and no more", d)
			}
		})
	}
}
