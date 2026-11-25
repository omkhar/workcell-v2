// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C68 of S-1005, sweep 3 (I5). Fix unit S-F51 moved this file here from escape/_pending/S-F51/ (SPEC S4) and closes it; its fix round added the last two rows. A placeholder bound to POST /v1/ or to one repository is swapped for the real secret on a request whose line
// sits inside the rule while a routing-override header moves it outside: the method from X-HTTP-Method-Override on a POST (Rack::MethodOverride, ASP.NET MVC, Google's API front end), the path from X-Original-URL or X-Rewrite-URL (IIS URL Rewrite, Symfony HttpFoundation). That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake upstream below honours those headers as they do, the underscore spelling as a CGI-style server reads it (RFC 3875 4.1.18 maps "-" to "_", so X_HTTP_Method_Override is the same variable), and a _method query parameter as Spring and Symfony do.
package proxy

import (
	"cmp"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestC68RoutingOverrideHeaders: a plain request inside the rule is served with the secret and a plain one outside is refused; no request that carries an override header gets the secret served for the method, path or repository the override reaches. Refusing it or forwarding it without the override both pass.
func TestC68RoutingOverrideHeaders(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path := r.Method, r.URL.Path
		if o := cmp.Or(r.Header.Get("X-HTTP-Method-Override"), r.Header.Get("X_HTTP_Method_Override"), r.URL.Query().Get("_method")); o != "" && method == http.MethodPost {
			method = o
		}
		if o := cmp.Or(r.Header.Get("X-Original-URL"), r.Header.Get("X-Rewrite-URL")); o != "" {
			path = o
		}
		_, password, _ := r.BasicAuth() // git sends the token as the Basic password
		_, _ = io.WriteString(w, method+" "+path+" "+cmp.Or(password, r.Header.Get("X-Api-Key")+r.Header.Get("Authorization")))
	}))
	t.Cleanup(server.Close)
	px, _, _ := testProxy(t, "n.example.com:443 r.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = x509.NewCertPool()
	px.upstreamRoots.AddCert(server.Certificate())
	ca := must(NewSessionCA([]string{"n.example.com", "r.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{
		{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"},
		{Host: "r.example.com", Header: "authorization", Placeholder: testAuthPlaceholder, Repos: []string{"octo/allowed"}},
	}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	n, r := "https://n.example.com", "https://r.example.com"
	key, bearer, git := []string{"X-Api-Key", testPlaceholder}, []string{"Authorization", "Bearer " + testAuthPlaceholder}, []string{"Authorization", basic(testAuthPlaceholder)}
	cases := []struct {
		method, target string
		header         []string // name, value pairs: the credential, then an override on all but a plain row
		served         string   // the whole answer a plain row inside the rule gets
		outside        string   // "METHOD PATH" the row reaches, which must never come back with the secret
	}{
		{"POST", n + "/v1/x", key, "POST /v1/x real-secret", ""},
		{"GET", r + "/octo/allowed.git/info/refs", bearer, "GET /octo/allowed.git/info/refs Bearer real-secret", ""},
		{"DELETE", n + "/v1/x", key, "", "DELETE /v1/x"},
		{"POST", n + "/v2/admin", key, "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X-HTTP-Method-Override", "DELETE"), "", "DELETE /v1/x"},
		{"POST", n + "/v1/x", append(key, "X-HTTP-Method-Override", "GET"), "", "GET /v1/x"},
		{"POST", n + "/v1/x", append(key, "X-Original-URL", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X-Rewrite-URL", "/v2/admin"), "", "POST /v2/admin"},
		{"GET", r + "/octo/allowed.git/info/refs", append(bearer, "X-Original-URL", "/octo/other.git/info/refs"), "", "GET /octo/other.git/info/refs"},
		{"POST", r + "/octo/allowed.git/git-receive-pack", append(git, "X-Original-URL", "/evil/repo.git/git-receive-pack"), "", "POST /evil/repo.git/git-receive-pack"},
		{"POST", n + "/v1/x", append(key, "X_HTTP_Method_Override", "DELETE"), "", "DELETE /v1/x"},
		{"POST", n + "/v1/x?_method=DELETE", key, "", "DELETE /v1/x"},
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, tc.target, nil))
		for i := 0; i < len(tc.header); i += 2 {
			req.Header.Set(tc.header[i], tc.header[i+1])
		}
		code, body := do(t, c, req)
		if tc.served != "" && body != tc.served || strings.HasPrefix(body, tc.outside+" ") && strings.Contains(body, "real-secret") {
			t.Errorf("%s %s %v: got (%d, %q), want it served as %q or the secret withheld from %q", tc.method, tc.target, tc.header[2:], code, body, tc.served, tc.outside)
		}
	}
}
