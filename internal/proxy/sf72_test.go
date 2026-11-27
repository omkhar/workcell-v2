// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Unit S-F72 (I6, I5): the method-and-path rule of ADR-006, check two, which closes the class of C10, C33, C68, C71, C73 and C74. The request the proxy judges is the request it sends: a path a `path` rule admits reaches the upstream byte for byte as the rule judged it, under every method, with the real secret; a spelling that is not canonical, or that lies outside the rule's path as sent, is refused and the upstream never sees it.
package proxy

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSF72AdmittedPathReachesUpstreamAsJudged: the upstream records the request line it received; for each admitted spelling it must equal what the guest sent and carry the real secret, and every refused spelling gets a 4xx, no secret, and no request at the upstream. `//v1/x` and `/v1%00/x` lie outside the prefix as sent, whatever a router that drops a slash or a NUL would make of them.
func TestSF72AdmittedPathReachesUpstreamAsJudged(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen []string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.RequestURI)
		mu.Unlock()
		_, _ = io.WriteString(w, r.Method+" "+r.RequestURI+" "+r.Header.Get("X-Api-Key"))
	}))
	t.Cleanup(up.Close)
	px, _, _ := testProxy(t, "v.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
	px.upstreamRoots = x509.NewCertPool()
	px.upstreamRoots.AddCert(up.Certificate())
	ca := must(NewSessionCA([]string{"v.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "v.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	admitted := []string{"/v1/x", "/v1", "/v1/", "/v1/x/", "/v1/a%20b", "/v1/%E2%9C%93", "/v1/a:b@c=d,e+f~g", "/v1/x?_method%00=DELETE&q=a%2Fb"} // one reading each: Go's own escaping of the decoded path, path.Clean of itself but for one trailing slash, no `;` and no backslash; the query is not judged and not touched, C74's method override included, since the rule names no method
	var want []string
	for _, method := range []string{"GET", "POST", "DELETE"} {
		for _, target := range admitted {
			want = append(want, target)
			if code, body := send(t, c, method, "https://v.example.com"+target, "", "", "X-Api-Key", testPlaceholder); code != http.StatusOK || body != method+" "+target+" real-secret" {
				t.Errorf("%s %s: got (%d, %q), want it served with the real secret at the request line the rule judged", method, target, code, body)
			}
		}
	}
	for _, target := range []string{"//v1/x", "/v1%00/x", "/v1//x", "/v1/./x", "/v1/a/../x", "/v1/%2e%2e/admin", "/v1/a%2Fb", "/v1/%41", "/v1/a;b", "/v1/a%3Bb", "/v1/a%5Cb", "/v2/x", "/v1x"} {
		if code, body := send(t, c, "POST", "https://v.example.com"+target, "", "", "X-Api-Key", testPlaceholder); code < 400 || strings.Contains(body, "real-secret") {
			t.Errorf("POST %s: got (%d, %q), want it refused with the secret withheld", target, code, body)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, want) {
		t.Errorf("the upstream saw %q, want the admitted request lines alone: %q", seen, want)
	}
}
