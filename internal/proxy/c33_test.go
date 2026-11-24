// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C33 of S-1016b (I5): a `path`-narrowed credential must not be released outside its rule's path. fold decodes %2F before path.Clean, so `POST /v1/a%2Fb/../../admin` passes a rule with path `/v1/`, yet a router doing RFC 3986 5.2.4 dot-removal on the still-encoded path (%2F opaque, as
// path.Clean of EscapedPath) serves /admin. Real terminating Proxy + loopback upstream modelling that router: the %2F and %5C forms with a dot segment are refused 403 and the upstream never sees the real secret outside /v1/; /v1/a%2Fb/c is served as before with the real secret under /v1/.
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
	"testing"
	"time"
)

func TestC33PathBindingReleasesSecretOutsideBinding(t *testing.T) {
	t.Parallel()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served, _ := url.PathUnescape(path.Clean(r.URL.EscapedPath()))
		_, _ = io.WriteString(w, served+" "+r.Header.Get("X-Api-Key"))
	}))
	t.Cleanup(up.Close)
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	px, _, _ := testProxy(t, "v.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
	px.upstreamRoots = roots
	ca := must(NewSessionCA([]string{"v.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &tokenBroker{access: []byte("real-secret")}, []TerminateRule{
		{Host: "v.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"},
	}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	for _, tc := range []struct {
		target string
		code   int
	}{{"/v1/a%2Fb/../../admin", 403}, {"/v1/a%5Cb/../../admin", 403}, {"/v1/a%2Fb/c", 200}} {
		code, body := send(t, c, "POST", "https://v.example.com"+tc.target, "", "", "X-Api-Key", testPlaceholder)
		served, value, _ := strings.Cut(body, " ")
		if code != tc.code || (value == "real-secret") != (tc.code == 200) || value == "real-secret" && served != "/v1/a/b/c" {
			t.Errorf("I5: POST %s: got %d %q, want %d with the real secret only under the rule's path /v1/", tc.target, code, body, tc.code)
		}
	}
}
