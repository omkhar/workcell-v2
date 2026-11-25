// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C74 of S-1020, sweep 3 (I5): a residue that S-F51 parked with no reproduction. A placeholder bound to POST /v1/ is swapped for the real secret on a POST whose query string moves the method outside the rule
// under a name the proxy does not judge: PHP reads "." in a parameter name as "_" when it fills $_GET (a documented rule of its variable names), so `?.method=DELETE` is `_method` to Symfony's HttpFoundation where the
// parameter override is enabled, as Laravel enables it, and C68 judged the `_method` spelling alone. That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake upstream
// below reads the query string as PHP and Symfony do. A plain POST is served with the secret, and the plain DELETE such a POST reaches and the `_method` spelling are refused; no row gets the secret served for the method
// its override reaches.
package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestC74DotMethodQuery(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		for name, values := range r.URL.Query() {
			if strings.ReplaceAll(name, ".", "_") == "_method" && r.Method == http.MethodPost { // the name as PHP stores it in $_GET, the override as Symfony applies it: on a POST, upper-cased
				method = strings.ToUpper(values[0])
			}
		}
		_, _ = w.Write([]byte(method + " " + r.URL.Path + " " + r.Header.Get("X-Api-Key")))
	}))
	t.Cleanup(server.Close)
	px, _, _ := testProxy(t, "n.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ca := must(NewSessionCA([]string{"n.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	cases := []struct{ method, query, served, outside string }{ // served: the whole answer a plain row inside the rule gets; outside: "METHOD PATH" the row reaches, which must never come back with the secret
		{"POST", "", "POST /v1/x real-secret", ""},
		{"DELETE", "", "", "DELETE /v1/x"},
		{"POST", "?_method=DELETE", "", "DELETE /v1/x"},
		{"POST", "?.method=DELETE", "", "DELETE /v1/x"},
		{"POST", "?a=b&.method=put", "", "PUT /v1/x"},
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, "https://n.example.com/v1/x"+tc.query, nil))
		req.Header.Set("X-Api-Key", testPlaceholder)
		if code, body := do(t, c, req); tc.served != "" && body != tc.served || strings.HasPrefix(body, tc.outside+" ") && strings.Contains(body, "real-secret") {
			t.Errorf("%s %s: got (%d, %q), want it served as %q or the secret withheld from %q", tc.method, tc.query, code, body, tc.served, tc.outside)
		}
	}
}
