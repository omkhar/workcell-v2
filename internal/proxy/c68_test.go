// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C68 of S-1005, sweep 3 (I5), moved here from escape/_pending/S-F51/ by S-F51 (SPEC S4) and rewritten by S-F72 as a test of the method-and-path rule of ADR-006 (check two). A placeholder bound to /v1/ or to one repository is swapped for the real secret on a request whose line
// sits inside the rule while a routing-override header moves it outside: the method from X-HTTP-Method-Override on a POST (Rack::MethodOverride, ASP.NET MVC, Google's API front end), the path from X-Original-URL or X-Rewrite-URL (IIS URL Rewrite, Symfony HttpFoundation). The rule names no method, so a method override moves nothing the rule names and such a row is served inside the rule;
// the two path-override headers are refused under every spelling RFC 3875 4.1.18's one fold covers (a "-" read as "_", letter case dropped), as a CGI-style server reads them. That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake upstream below honours those headers as they do.
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

// TestC68RoutingOverrideHeaders: a plain request inside the rule is served with the secret, under any method, body or method override, and a plain one outside is refused; no request that carries a path-override header, in any spelling, gets the secret served for the path or repository the override reaches. Refusing it or forwarding it without the override both pass.
func TestC68RoutingOverrideHeaders(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path := r.Method, r.URL.Path
		if o := cmp.Or(r.Header.Get("X-HTTP-Method-Override"), r.Header.Get("X_HTTP_Method_Override"), r.URL.Query().Get("_method")); o != "" && method == http.MethodPost {
			method = o
		}
		for name, values := range r.Header {
			if cgi := strings.ToUpper(strings.ReplaceAll(name, "-", "_")); cgi == "X_ORIGINAL_URL" || cgi == "X_REWRITE_URL" { // the variable a CGI-style server folds the header into
				path = values[0]
			}
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
		{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Path: "/v1/"},
		{Host: "r.example.com", Header: "authorization", Placeholder: testAuthPlaceholder, Repos: []string{"octo/allowed"}},
	}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	n, r := "https://n.example.com", "https://r.example.com"
	key, bearer, git := []string{"X-Api-Key", testPlaceholder}, []string{"Authorization", "Bearer " + testAuthPlaceholder}, []string{"Authorization", basic(testAuthPlaceholder)}
	cases := []struct {
		method, target string
		header         []string // name, value pairs: the credential, then an override on all but a plain row
		served         string   // the whole answer a row inside the rule gets
		outside        string   // "METHOD PATH" the row reaches, which must never come back with the secret
	}{
		{"POST", n + "/v1/x", key, "POST /v1/x real-secret", ""}, {"DELETE", n + "/v1/x", key, "DELETE /v1/x real-secret", ""},
		{"GET", r + "/octo/allowed.git/info/refs", bearer, "GET /octo/allowed.git/info/refs Bearer real-secret", ""}, {"POST", n + "/v2/admin", key, "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X-HTTP-Method-Override", "DELETE"), "DELETE /v1/x real-secret", ""},
		{"POST", n + "/v1/x", append(key, "X_HTTP_Method_Override", "GET"), "GET /v1/x real-secret", ""}, {"POST", n + "/v1/x?_method=PUT", key, "PUT /v1/x real-secret", ""},
		{"POST", n + "/v1/x", append(key, "Content-Type", "application/json"), "POST /v1/x real-secret", ""},
		{"POST", n + "/v1/x", append(key, "X-Original-URL", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X-Rewrite-URL", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X_Original_URL", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "x_rewrite_url", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X-ORIGINAL_URL", "/v2/admin"), "", "POST /v2/admin"},
		{"POST", n + "/v1/x", append(key, "X_Rewrite-Url", "/v2/admin"), "", "POST /v2/admin"},
		{"GET", r + "/octo/allowed.git/info/refs", append(bearer, "X-Original-URL", "/octo/other.git/info/refs"), "", "GET /octo/other.git/info/refs"},
		{"POST", r + "/octo/allowed.git/git-receive-pack", append(git, "X_Original_URL", "/evil/repo.git/git-receive-pack"), "", "POST /evil/repo.git/git-receive-pack"},
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, tc.target, strings.NewReader(`{"_method":"DELETE"}`)))
		for i := 0; i < len(tc.header); i += 2 {
			req.Header.Set(tc.header[i], tc.header[i+1])
		}
		code, body := do(t, c, req)
		if tc.served != "" && body != tc.served || strings.HasPrefix(body, tc.outside+" ") && strings.Contains(body, "real-secret") {
			t.Errorf("%s %s %v: got (%d, %q), want it served as %q or the secret withheld from %q", tc.method, tc.target, tc.header[2:], code, body, tc.served, tc.outside)
		}
	}
}
