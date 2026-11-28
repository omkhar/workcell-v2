// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C90 of S-1007 sweep 4 (I5): a `path`-narrowed credential must not be released outside its rule's path, and a judged path must have one reading. `canonical` takes `/v1/x%0D%0A%0D%0AGET%20/admin` for such a path, since upper-case hex is Go's own escaping of CR, LF, TAB, 0x01 and DEL, and the request goes upstream byte for byte with the real secret; a front end that decodes the path once and re-reads the bytes meets a blank line and then a second request line, GET /admin, outside the binding, with the real secret beside it.
// Reproduced under escape/_pending/S-F75 until the fix unit S-F75 moved it here. Its `repos` twin is the row "a control byte in the repository path" in TestTerminateNarrowedRule.
package proxy

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestC90ControlBytesInACanonicalPath: first what canonical says of each spelling, then through the real terminating Proxy what a loopback upstream receives. The upstream is a model of a front end that decodes the path once and re-reads the bytes: a CR LF CR LF inside them ends the first request, and the request line after it is the one served; any other path it serves as decoded. Controls: the plain `/v1/x` is served with the secret; the lower-case `/v1/x%0d%0a` is refused.
func TestC90ControlBytesInACanonicalPath(t *testing.T) {
	t.Parallel()
	spellings := []string{"/v1/x%0D%0A%0D%0AGET%20/admin", "/v1/x%20HTTP/1.1%0D%0AHost:%20b%0D%0AContent-Length:%200%0D%0A%0D%0AGET%20/admin", "/v1/x%0A", "/v1/x%0D", "/v1/x%7F", "/v1/x%01y", "/v1/x%09y"}
	for _, p := range spellings {
		if canonical(must(url.Parse(p))) {
			t.Errorf("canonical(%q) = true: a path holding a control byte has more than one reading", p)
		}
	}
	served := make(chan string, 16) // "<path the front end serves> <key it saw>", one per request; the test sends nine
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		front, _ := url.PathUnescape(r.URL.EscapedPath()) // the front end decodes once and re-reads the bytes: a blank line ends the request, and the next line is a request of its own
		if _, second, ok := strings.Cut(front, "\r\n\r\n"); ok && len(strings.Fields(second)) > 1 {
			front = strings.Fields(second)[1]
		}
		served <- front + " " + r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte(front))
	}))
	t.Cleanup(up.Close)
	px, _, _ := testProxy(t, "v.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, up.Listener.Addr().String())
	px.upstreamRoots = x509.NewCertPool()
	px.upstreamRoots.AddCert(up.Certificate())
	ca := must(NewSessionCA([]string{"v.example.com"}, time.Now().Add(time.Hour)))
	must(0, px.Terminate(ca, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "v.example.com", Header: "x-api-key", Placeholder: testPlaceholder, Path: "/v1/"}}))
	c := clientVia(listen(t, px, 443), caPool(t, ca))
	if code, body := send(t, c, "POST", "https://v.example.com/v1/x", "", "", "X-Api-Key", testPlaceholder); code != http.StatusOK || body != "/v1/x" || <-served != "/v1/x real-secret" {
		t.Errorf("control: POST /v1/x: got (%d, %q), want it served at /v1/x with the real secret seen upstream", code, body)
	}
	if code, body := send(t, c, "POST", "https://v.example.com/v1/x%0d%0a", "", "", "X-Api-Key", testPlaceholder); code < 400 || len(served) > 0 {
		t.Errorf("control: POST /v1/x%%0d%%0a: got (%d, %q), want it refused before the upstream sees it", code, body)
	}
	for _, p := range spellings {
		send(t, c, "POST", "https://v.example.com"+p, "", "", "X-Api-Key", testPlaceholder) // how a fix answers is not judged, only where the secret goes
	}
	close(served)
	for hit := range served {
		if p, key, _ := strings.Cut(hit, " "); key == "real-secret" && (!strings.HasPrefix(p, "/v1/") || strings.ContainsFunc(p, func(c rune) bool { return c < ' ' || c == 0x7F })) {
			t.Errorf("I5: the upstream received %q with the real secret: a path with a control byte, or a second request line outside /v1/, passed as canonical", p)
		}
	}
}
