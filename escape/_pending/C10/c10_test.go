// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// C10 (I5). This file waits here, where Go does not compile it, until its fix lands; the fix unit moves it into internal/proxy/. tokenEndpoint and
// admits judge a path as sent and as decoded with its dot segments resolved, and sameEndpoint drops a ;param suffix from each segment, but neither
// resolves the dot segments that dropping a ;param or folding a backslash uncovers. A router that drops ;params before it normalises (Tomcat's
// CoyoteAdapter: parsePathParameters, then normalize; Jetty and Undertow alike) or reads a backslash as a slash (HTTP.sys, IIS) serves
// /oauth/x/..;/token as the token endpoint, so its answer carries real tokens to the guest unread (a), and serves /v1/..;/admin as /admin, so a
// placeholder bound to POST /v1/ or to one repository is swapped for the real secret on a request outside the rule (b). The fake upstream below
// folds the path as those routers do; that the operator's host sits behind one is a precondition the attacker does not control.
package proxy

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"strings"
	"testing"
	"time"
)

// foldingFixture is signinFixture with the narrowed rules of terminateFixture, behind an upstream that folds the path as those routers do before it
// serves it: the provider on login.example.com, elsewhere an echo of the folded path and the credential header. The broker holds "real-secret".
func foldingFixture(t *testing.T, prov *provider) *http.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segs := strings.Split(strings.ReplaceAll(r.URL.Path, `\`, "/"), "/")
		for i, s := range segs {
			segs[i], _, _ = strings.Cut(s, ";")
		}
		r.URL.Path, r.URL.RawPath = path.Clean(strings.Join(segs, "/")), ""
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
		{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"},
		{Host: "r.example.com", Header: "authorization", Placeholder: testAuthPlaceholder, Repos: []string{"octo/allowed"}},
	}))
	return clientVia(listen(t, px, 443), caPool(t, ca))
}

// TestFoldedPathEscapesTheEndpointAndTheRule: (a) a code grant at a spelling the IdP's router folds to the token endpoint must reach the guest with no
// real token in it (send fails the test on one); (b) a placeholder on a request whose path folds to one outside its rule must be refused, as the
// unfolded /v1/../admin is, with the secret withheld.
func TestFoldedPathEscapesTheEndpointAndTheRule(t *testing.T) {
	t.Parallel()
	c := foldingFixture(t, &provider{})
	for _, target := range []string{"/oauth/x/..;/token", "/oauth%5Ctoken", "/oauth/./token;a/..;/token"} {
		send(t, c, "POST", "https://login.example.com"+target, "application/x-www-form-urlencoded", "grant_type=authorization_code&code=c0de")
	}
	cases := []struct{ method, target, header, value string }{
		{"POST", "https://n.example.com/v1/..;/admin", "X-Api-Key", testPlaceholder}, {"POST", "https://n.example.com/v1/..%5Cadmin", "X-Api-Key", testPlaceholder},
		{"GET", "https://r.example.com/octo/allowed.git/..;/other.git/info/refs", "Authorization", "Bearer " + testAuthPlaceholder},
		{"POST", "https://r.example.com/octo/allowed/..;/..;/evil/repo.git/git-receive-pack", "Authorization", "Bearer " + testAuthPlaceholder},
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, tc.target, nil))
		req.Header.Set(tc.header, tc.value)
		if code, body := do(t, c, req); code < 400 || strings.Contains(body, "real-secret") {
			t.Errorf("%s %s: got (%d, %q), want it refused with the secret withheld", tc.method, tc.target, code, body)
		}
	}
}
