// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C33 of S-1016b (I5), tool finding F9: a `path`-narrowed credential is released outside its rule's path. fold decodes %2F, so
// `POST /v1/a%2Fb/../../admin` passes a rule with path `/v1/`, but a router doing RFC 3986 5.2.4 dot-removal on the encoded path (%2F opaque, as
// path.Clean of EscapedPath) serves /admin. Real terminating Proxy + loopback upstream modelling that router. Fails until fix unit S-F26 lands, which
// moves it to internal/proxy/c33_test.go.
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
	_, body := send(t, c, "POST", "https://v.example.com/v1/a%2Fb/../../admin", "", "", "X-Api-Key", testPlaceholder)
	if served, value, _ := strings.Cut(body, " "); value == "real-secret" && !strings.HasPrefix(served, "/v1/") {
		t.Errorf("I5: upstream served %q with the real secret, outside the rule's path %q", served, "/v1/")
	}
}
