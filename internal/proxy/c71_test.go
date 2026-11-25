// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C71 of S-1007, sweep 3 (I5), fixed by S-F55, which moved this file here from escape/_pending/S-F55/ (SPEC S4). A placeholder bound to POST /v1/ is swapped for the real secret on a POST whose form body moves the method outside the rule: a _method field (Rack::MethodOverride, Laravel) or an X-HTTP-Method-Override field (ASP.NET MVC),
// urlencoded or multipart, where C68 judged the override only as a header or a query parameter. That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake upstream below honours the fields as those frameworks do, the value upper-cased as Rack does. A POST with a text/plain body is served with the secret (C73 judges a JSON body) and the plain DELETE such a POST reaches is refused; no row carrying an override gets the secret served for the method the override reaches.
package proxy

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestC71FormMethodOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := cmp.Or(strings.ToUpper(cmp.Or(r.PostFormValue("_method"), r.PostFormValue("X-HTTP-Method-Override"))), r.Method) // the field of the POST body, urlencoded or multipart, as Rack's req.POST reads it
		_, _ = w.Write([]byte(method + " " + r.URL.Path + " " + r.Header.Get("X-Api-Key")))
	}))
	t.Cleanup(server.Close)
	px, _, _ := testProxy(t, "n.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ca := must(NewSessionCA([]string{"n.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	cases := []struct{ method, ctype, body, served, outside string }{ // served: the whole answer a plain row inside the rule gets; outside: "METHOD PATH" the row reaches, which must never come back with the secret
		{"POST", "text/plain", "_method=DELETE", "POST /v1/x real-secret", ""}, // a body that is neither a form nor JSON, which Rack's req.POST does not read; S-F57 turned this row from a JSON body, which C73 refuses
		{"DELETE", "application/json", "", "", "DELETE /v1/x"},
		{"POST", "application/x-www-form-urlencoded", "_method=DELETE&a=b", "", "DELETE /v1/x"},
		{"POST", "APPLICATION/X-WWW-FORM-URLENCODED; charset=utf-8", "a=b&_method=put", "", "PUT /v1/x"}, // the media type in capitals with a parameter, as Rack and mime.ParseMediaType both read it
		{"POST", "application/x-www-form-urlencoded", "X-HTTP-Method-Override=PATCH", "", "PATCH /v1/x"},
		{"POST", "multipart/form-data; boundary=b", "--b\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE\r\n--b--\r\n", "", "DELETE /v1/x"},
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, "https://n.example.com/v1/x", strings.NewReader(tc.body)))
		req.Header = http.Header{"X-Api-Key": {testPlaceholder}, "Content-Type": {tc.ctype}}
		if code, body := do(t, c, req); tc.served != "" && body != tc.served || strings.HasPrefix(body, tc.outside+" ") && strings.Contains(body, "real-secret") {
			t.Errorf("%s %s %q: got (%d, %q), want it served as %q or the secret withheld from %q", tc.method, tc.ctype, tc.body, code, body, tc.served, tc.outside)
		}
	}
}
