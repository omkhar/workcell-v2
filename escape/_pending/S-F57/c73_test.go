// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C73 of S-1020, sweep 3 (I5): the residue of C71, as C71 was of C68. A placeholder bound to POST /v1/ is swapped for the real secret on a POST whose JSON body moves the method outside the rule: a top-level _method
// name, which Laravel reads from a JSON body as it does from a form (Illuminate\Http\Request::createFromBase takes the decoded JSON as the request parameters, and Symfony's HttpFoundation reads _method from them, upper-cased,
// where the parameter override is enabled, as Laravel enables it). C71 judged the override in a form body alone. That the operator's host sits behind such a framework is a precondition the attacker does not control; the fake
// upstream below honours the name as Laravel does, on a body whose media type holds "/json" or "+json" in any case (RFC 2045 5.1: the type is case-insensitive). A bare POST and a plain JSON POST are served with the secret and
// the plain DELETE such a POST reaches is refused; no row carrying an override gets the secret served for the method the override reaches.
package proxy

import (
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
		method, body, ctype := r.Method, map[string]any{}, strings.ToLower(r.Header.Get("Content-Type"))
		if r.Method == http.MethodPost && (strings.Contains(ctype, "/json") || strings.Contains(ctype, "+json")) && json.NewDecoder(r.Body).Decode(&body) == nil {
			if o, ok := body["_method"].(string); ok { // the top-level name of the JSON body, as Laravel's input source reads it
				method = strings.ToUpper(o)
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
	cases := []struct{ method, ctype, body, served, outside string }{ // served: the whole answer a plain row inside the rule gets; outside: "METHOD PATH" the row reaches, which must never come back with the secret
		{"POST", "", "", "POST /v1/x real-secret", ""}, // a bare POST, with no body and no media type
		{"POST", "application/json", `{"a":1}`, "POST /v1/x real-secret", ""},
		{"DELETE", "application/json", "", "", "DELETE /v1/x"},
		{"POST", "application/json", `{"_method":"DELETE"}`, "", "DELETE /v1/x"},
		{"POST", "application/vnd.api+json", `{"_method":"PUT"}`, "", "PUT /v1/x"},
		{"POST", "APPLICATION/JSON; charset=utf-8", `{"a":1,"_method":"delete"}`, "", "DELETE /v1/x"}, // the media type in capitals with a parameter, the value in lower case as Symfony upper-cases it
	}
	for _, tc := range cases {
		req := must(http.NewRequest(tc.method, "https://n.example.com/v1/x", strings.NewReader(tc.body)))
		req.Header = http.Header{"X-Api-Key": {testPlaceholder}}
		if tc.ctype != "" {
			req.Header.Set("Content-Type", tc.ctype)
		}
		if code, body := do(t, c, req); tc.served != "" && body != tc.served || strings.HasPrefix(body, tc.outside+" ") && strings.Contains(body, "real-secret") {
			t.Errorf("%s %s %q: got (%d, %q), want it served as %q or the secret withheld from %q", tc.method, tc.ctype, tc.body, code, body, tc.served, tc.outside)
		}
	}
}
