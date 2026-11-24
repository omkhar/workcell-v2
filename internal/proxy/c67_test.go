// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C67 of S-1005, sweep 3 (I5): a token answer in a media type other than JSON or a form, to a spelling of the token endpoint the match
// does not claim, reaches the guest unread. Fix unit S-F50 moved this file here from escape/_pending/S-F50/ unchanged (SPEC S4) and closes it.

package proxy

import (
	"cmp"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestC67TokenAnswerInAnotherMediaType (I5): the token host's router serves the token action with a format suffix too, as C55's does, and answers the
// code grant in the media type the guest's Accept header names. Whatever the type, no byte of a real token the provider issued may reach the guest:
// refused or swapped for the placeholders, either is fine. The control row, the honest spelling with a JSON answer, gets the two placeholders today. The provider is a loopback server of the test (T8).
func TestC67TokenAnswerInAnotherMediaType(t *testing.T) {
	const login, grant, form, acc, ref = "https://login.example.com", "grant_type=authorization_code&code=c0de", "application/x-www-form-urlencoded", "sk-acc-REAL", "sk-ref-REAL"
	js := `{"access_token":"` + acc + `","token_type":"bearer","scope":"repo","refresh_token":"` + ref + `"}`
	rows := []struct{ name, path, ctype, body string }{
		{"control: honest spelling, json", tokenEndpointPath, "application/json", js},
		{"xml", tokenEndpointPath + ".xml", "application/xml; charset=utf-8", "<OAuth><token_type>bearer</token_type><scope>repo</scope><access_token>" + acc + "</access_token><refresh_token>" + ref + "</refresh_token></OAuth>"},
		{"text/json", tokenEndpointPath + ".json", "text/json", js},
		{"vnd.api+json", tokenEndpointPath + ".json", "application/vnd.api+json", js},
		{"text/plain form", tokenEndpointPath + ".json", "text/plain", "access_token=" + acc + "&refresh_token=" + ref + "&scope=repo&token_type=bearer"},
		{"no content-type", tokenEndpointPath + ".json", "", js},
		{"form label over json", tokenEndpointPath + ".json", form, js},
		{"text/json utf-16le", tokenEndpointPath + ".json", "text/json; charset=utf-16", "\xff\xfe" + strings.Join(strings.Split(js, ""), "\x00") + "\x00"}, // js is ASCII: a NUL after each byte is UTF-16LE
		{"vnd.api+json utf-16be", tokenEndpointPath + ".json", "application/vnd.api+json; charset=utf-16", "\xfe\xff\x00" + strings.Join(strings.Split(js, ""), "\x00")},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Host != "login.example.com" || r.Method != http.MethodPost || strings.TrimSuffix(r.URL.Path, path.Ext(r.URL.Path)) != tokenEndpointPath || !strings.Contains(string(body), "grant_type=authorization_code") {
					http.Error(w, "not the token action", http.StatusNotFound)
					return
				}
				w.Header()["Content-Type"] = slices.DeleteFunc([]string{row.ctype}, func(s string) bool { return s == "" }) // the row's type or none at all, never a sniffed one
				fmt.Fprint(w, row.body)
			}))
			t.Cleanup(up.Close)
			px, _, _ := testProxy(t, "api.example.com:443 login.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
			px.upstreamRoots = x509.NewCertPool()
			px.upstreamRoots.AddCert(up.Certificate())
			ca := must(NewSessionCA([]string{"api.example.com", "login.example.com"}, time.Now().Add(time.Hour)))
			must(0, px.Terminate(ca, &tokenBroker{}, []TerminateRule{{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}}))
			req := must(http.NewRequest(http.MethodPost, login+row.path, strings.NewReader(grant)))
			req.Header = http.Header{"Content-Type": {form}, "Accept": {cmp.Or(row.ctype, "*/*")}}
			resp := must(clientVia(listen(t, px, 443), caPool(t, ca)).Do(req))
			got := strings.ReplaceAll(string(must(httputil.DumpResponse(resp, true))), "\x00", "") // the status line, every header and the body, as the guest reads them; NULs dropped so a UTF-16 spelling of a token is read too
			if strings.Contains(got, acc) || strings.Contains(got, ref) {
				t.Errorf("POST %s answered in %q: the guest read a real token:\n%s", row.path, row.ctype, got)
			}
			if row.path == tokenEndpointPath && (resp.StatusCode != 200 || !strings.Contains(got, testPlaceholder) || !strings.Contains(got, testRefreshPlaceholder)) {
				t.Errorf("the honest spelling: got %d, want 200 with the two placeholders:\n%s", resp.StatusCode, got)
			}
		})
	}
}
