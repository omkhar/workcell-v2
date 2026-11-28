// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C88 of S-1005 sweep 4 (I5): a `path`-narrowed credential must not be released outside its rule's path. `/v1/%252e%252e/admin` is canonical to the proxy (`%25` is Go's own escaping of `%`) and goes upstream byte for byte with the real secret; a front end that decodes the path once and forwards it (Apache httpd, `RewriteRule ^/v1/(.*)$ http://backend/api/$1 [P,NE]`) hands a backend `%2e%2e`, which it decodes and cleans, and serves /admin with the secret.
// Reproduced under escape/_pending/S-F74 until the fix unit S-F74 moved it here. Its `repos` twin is the row "a doubled escape out of the repository" in TestTerminateNarrowedRule.
package proxy

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestC88DoubledEscapeLeavesTheBinding: real terminating Proxy + loopback upstream modelling the two readings; the upstream records the path it finally serves and the key it saw. The real secret must never be served outside /v1/. Controls: the plain `/v1/x` is served with it; `/v1/%2e%2e/admin` is refused by the proxy.
func TestC88DoubledEscapeLeavesTheBinding(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var served []string // "<path the backend serves> <key it saw>"
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		front, _ := url.PathUnescape(r.URL.EscapedPath()) // the front end decodes once and forwards the decoded form
		back, _ := url.PathUnescape(front)                // the backend decodes again and removes dot segments
		hit := path.Clean(back) + " " + r.Header.Get("X-Api-Key")
		mu.Lock()
		served = append(served, hit)
		mu.Unlock()
		_, _ = io.WriteString(w, hit)
	}))
	t.Cleanup(up.Close)
	px, _, _ := testProxy(t, "v.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
	px.upstreamRoots = x509.NewCertPool()
	px.upstreamRoots.AddCert(up.Certificate())
	ca := must(NewSessionCA([]string{"v.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "v.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	if code, body := send(t, c, "POST", "https://v.example.com/v1/x", "", "", "X-Api-Key", testPlaceholder); code != http.StatusOK || body != "/v1/x real-secret" {
		t.Errorf("control: POST /v1/x: got (%d, %q), want it served at /v1/x with the real secret", code, body)
	}
	if code, body := send(t, c, "POST", "https://v.example.com/v1/%2e%2e/admin", "", "", "X-Api-Key", testPlaceholder); code < 400 || strings.Contains(body, "real-secret") {
		t.Errorf("control: POST /v1/%%2e%%2e/admin: got (%d, %q), want it refused with the secret withheld", code, body)
	}
	send(t, c, "POST", "https://v.example.com/v1/%252e%252e/admin", "", "", "X-Api-Key", testPlaceholder) // how a fix answers is not judged, only where the secret goes
	mu.Lock()
	defer mu.Unlock()
	for _, hit := range served {
		if p, key, _ := strings.Cut(hit, " "); key == "real-secret" && !strings.HasPrefix(p, "/v1/") {
			t.Errorf("I5: the upstream served %q with the real secret: the credential bound to /v1/ was used outside its binding", p)
		}
	}
}
