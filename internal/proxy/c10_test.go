// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F5, finding C10 of S-1005 (I5), rewritten by S-F72 as a test of the method-and-path rule of ADR-006 (check two). A router that drops ;params before it normalises (Tomcat's CoyoteAdapter: parsePathParameters, then normalize; Jetty and Undertow alike) or reads a backslash as a slash (HTTP.sys, IIS) serves
// /oauth/x/..;/token as the token endpoint and /v1/..;/admin as /admin. Under the rule a path is admitted only when it is canonical: one reading, the bytes Request.Write sends. A `;`, a backslash, a dot segment or an encoded separator is not canonical, so the request is refused under a rule and 400 on a sign-in host, and
// no spelling that folds elsewhere gets a token or a secret. That the operator's host sits behind such a router is a precondition the attacker does not control; the fake upstream below folds the path as those routers do.
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

// foldingFixture is signinFixture with the narrowed rules of terminateFixture, behind an upstream that folds the path as those routers do before it serves it (raw ;params cut up to the next raw slash, then decoded, a backslash taken for a slash, then dot segments resolved): the provider on login.example.com, elsewhere an echo of the folded path and the credential header. The broker holds "real-secret".
func foldingFixture(t *testing.T, prov *provider) *http.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segs := strings.Split(r.URL.EscapedPath(), "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		p, _ := url.PathUnescape(strings.Join(segs, "/"))
		r.URL.Path, r.URL.RawPath = path.Clean(strings.ReplaceAll(p, `\`, "/")), ""
		if r.Host == "login.example.com" {
			prov.ServeHTTP(w, r)
			return
		}
		_, _ = io.WriteString(w, r.URL.Path+" "+r.Header.Get("X-Api-Key")+r.Header.Get("Authorization"))
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	hosts := []string{"api.example.com", "login.example.com", "n.example.com", "r.example.com"}
	px, _, _ := testProxy(t, strings.Join(hosts, ":443 ")+":443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = roots
	ca := must(NewSessionCA(hosts, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &tokenBroker{access: []byte("real-secret")}, []TerminateRule{
		{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}},
		{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Path: "/v1/"},
		{Host: "r.example.com", Header: "authorization", Placeholder: testAuthPlaceholder, Repos: []string{"octo/allowed"}},
	}))
	return clientVia(listen(t, px, 443), caPool(t, ca))
}

// TestFoldedPathEscapesTheEndpointAndTheRule: (a) a code grant at a spelling the IdP's router folds to the token endpoint is not canonical, so the sign-in host refuses it with a 400 and the guest reads no token (send fails the test on one); (b) a placeholder on a request whose path is not canonical, or folds to one outside its rule, is refused with the secret withheld, as the unfolded /v1/../admin is.
func TestFoldedPathEscapesTheEndpointAndTheRule(t *testing.T) {
	t.Parallel()
	c := foldingFixture(t, &provider{})
	for _, target := range []string{"/oauth/x/..;/token", "/oauth%5Ctoken", "/oauth/./token;a/..;/token", "/oauth/token;%2Fx", "//oauth/token", "/oauth/./token", "/oauth/%74oken", "/oauth/x/../token"} {
		if code, _ := send(t, c, "POST", "https://login.example.com"+target, "application/x-www-form-urlencoded", "grant_type=authorization_code&code=c0de"); code != http.StatusBadRequest {
			t.Errorf("POST %s on the sign-in host: got %d, want 400 for a path that is not canonical", target, code)
		}
	}
	cases := []struct{ method, target, header, value string }{
		{"POST", "https://n.example.com/v1/..;/admin", "X-Api-Key", testPlaceholder}, {"POST", "https://n.example.com/v1/..%5Cadmin", "X-Api-Key", testPlaceholder},
		{"POST", "https://n.example.com/v1/x;%2Fa%2Fb/../../admin", "X-Api-Key", testPlaceholder}, {"POST", "https://n.example.com/v1/x;y", "X-Api-Key", testPlaceholder},
		{"GET", "https://n.example.com/v1/a%5Cb", "X-Api-Key", testPlaceholder}, {"GET", "https://n.example.com/v1/./x", "X-Api-Key", testPlaceholder}, {"GET", "https://n.example.com/v1/%78", "X-Api-Key", testPlaceholder},
		{"GET", "https://r.example.com/octo/allowed.git/..;/other.git/info/refs", "Authorization", "Bearer " + testAuthPlaceholder},
		{"GET", "https://r.example.com/octo/allowed.git/x;%2Fa%2Fb/../../../other.git/info/refs", "Authorization", "Bearer " + testAuthPlaceholder},
		{"POST", "https://r.example.com/octo/allowed/..;/..;/evil/repo.git/git-receive-pack", "Authorization", "Bearer " + testAuthPlaceholder},
		{"GET", "https://r.example.com/octo/allowed.git/info/refs;x", "Authorization", "Bearer " + testAuthPlaceholder}, {"GET", "https://r.example.com/octo/allowed.git/./info/refs", "Authorization", "Bearer " + testAuthPlaceholder},
	}
	for _, tc := range cases { // send fails the test on a body that carries a token the sign-in arms above may have issued
		if code, body := send(t, c, tc.method, tc.target, "", "", tc.header, tc.value); code < 400 || strings.Contains(body, "real-secret") {
			t.Errorf("%s %s: got (%d, %q), want it refused with the secret withheld", tc.method, tc.target, code, body)
		}
	}
}
