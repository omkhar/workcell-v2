// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C73 of S-1020, sweep 3 (I5), the residue of C71 as C71 was of C68; S-F57 moved this file here from escape/_pending/S-F57/ (SPEC S4). A placeholder bound to POST /v1/ is swapped for the real secret on a POST whose JSON body moves the method outside the rule: a top-level _method name, which
// Laravel reads from a JSON body as from a form (Illuminate\Http\Request::createFromBase takes the decoded JSON as the request parameters where the Content-Type holds "/json" or "+json", case-sensitively, and Symfony's HttpFoundation reads _method from them, upper-cased, where the parameter override is enabled, as
// Laravel enables it). That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake upstream below honours the name as Laravel does. A rule that names a method refuses a JSON body as it refuses a form body (C71): a bare POST, a JSON type with no body and a body of
// another type are served with the secret; every JSON body gets the 403 the plain DELETE gets, sent with a Content-Length or chunked, and no row carrying an override gets the secret served for the method the override reaches. The fix round added the last row, a Content_Type header beside the Content-Type (the reviewer's finding): the upstream reads it in place of Content-Type, as PHP's built-in server does, where both fold onto CONTENT_TYPE and the later line wins.
package proxy

import (
	"cmp"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestC73JSONMethodOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]string{} // the top-level names of a JSON body, as Laravel's input source reads them; a value of another type is skipped and the rest still read
		if ctype := cmp.Or(r.Header.Get("Content_type"), r.Header.Get("Content-Type")); r.Method == http.MethodPost && (strings.Contains(ctype, "/json") || strings.Contains(ctype, "+json")) {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		_, _ = w.Write([]byte(cmp.Or(strings.ToUpper(body["_method"]), r.Method) + " " + r.URL.Path + " " + r.Header.Get("X-Api-Key")))
	}))
	t.Cleanup(server.Close)
	px, _, _ := testProxy(t, "n.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ca := must(NewSessionCA([]string{"n.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "n.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	cases := []struct{ method, ctype, body, served, outside, transfer string }{ // served: the whole answer a row inside the rule gets, or "" for a row that must get a 403; outside: "METHOD PATH" the row reaches, which must never come back with the secret; transfer: "chunked" sends the body with no Content-Length, as a guest may
		{"POST", "", "", "POST /v1/x real-secret", "", ""},                               // a bare POST, with no body and no media type
		{"POST", "application/json", "", "POST /v1/x real-secret", "", ""},               // a JSON type with no body
		{"POST", "text/plain", `{"_method":"DELETE"}`, "POST /v1/x real-secret", "", ""}, // a body that is neither a form nor JSON, which Laravel does not read as JSON
		{"DELETE", "application/json", "", "", "DELETE /v1/x", ""},
		{"POST", "application/json", `{"a":1}`, "", "POST /v1/x", ""}, // a JSON body with no override, refused all the same: the proxy does not read it
		{"POST", "application/json", `{"_method":"DELETE"}`, "", "DELETE /v1/x", ""},
		{"POST", "application/vnd.api+json", `{"_method":"PUT"}`, "", "PUT /v1/x", ""},
		{"POST", "text/json; charset=utf-8", `{"a":1,"_method":"delete"}`, "", "DELETE /v1/x", ""}, // another type that is JSON to Laravel, with a parameter; the value in lower case as Symfony upper-cases it
		{"POST", "application/json", `{"_method":"DELETE"}`, "", "DELETE /v1/x", "chunked"},
		{"POST", "text/plain\napplication/json", `{"_method":"DELETE"}`, "", "DELETE /v1/x", ""}, // the fix round's row: Content-Type: text/plain beside Content_Type: application/json, which Go keeps as a second header and PHP's built-in server reads in place of the first
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, "https://n.example.com/v1/x", strings.NewReader(tc.body)))
		req.Header, req.TransferEncoding = http.Header{"X-Api-Key": {testPlaceholder}}, strings.Fields(tc.transfer)
		ctype, folded, ok := strings.Cut(tc.ctype, "\n") // "a\nb" sends Content-Type: a beside Content_Type: b
		if ok {
			req.Header.Set("Content_Type", folded)
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if code, body := do(t, c, req); tc.served != "" && body != tc.served || tc.served == "" && code != http.StatusForbidden {
			t.Errorf("%s %s %q %s: got (%d, %q), want it served as %q or a 403 withholding the secret from %q", tc.method, tc.ctype, tc.body, tc.transfer, code, body, tc.served, tc.outside)
		}
	}
}
