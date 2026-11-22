// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C30 of S-1013 (I6, through it I5; medium). upstreamRoots in internal/proxy/terminate.go reads the file SSL_CERT_FILE names with no IsAbs check: a relative value in the operator's
// environment (SSL_CERT_FILE=ca.pem, or ~/ca.pem left literal; a precondition the attacker does not control) is read against the working directory, so the repository ships ca.pem, a leaf
// that CA signed from the network attacker as DNS for an allowed name verifies, and the real secret is sent to it.
// Fix unit S-F22 first moves this file to internal/proxy/c30_test.go, package proxy, no build tag, as this comment says.

package proxy

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRelativeSSLCertFileIsRefused: upstreamRoots must refuse each relative spelling of ca.pem in the working directory, and Terminate under SSL_CERT_FILE=ca.pem must refuse or withhold the secret.
func TestRelativeSSLCertFileIsRefused(t *testing.T) {
	dir, repoCA, sessionCA := t.TempDir(), must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour))), must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour)))
	must(0, os.WriteFile(dir+"/ca.pem", repoCA.CertPEM(), 0o600)) // the attacker made repoCA and keeps the key of the leaf below
	t.Chdir(dir)
	t.Setenv("SSL_CERT_FILE", "ca.pem")
	for _, name := range []string{"ca.pem", "./ca.pem", ".." + dir[strings.LastIndex(dir, "/"):] + "/ca.pem"} {
		if _, err := upstreamRoots(name, ""); err == nil {
			t.Errorf("upstreamRoots(%q) read the repository's file against the working directory without error; want a refusal", name)
		}
	}
	ln := must(tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*must(repoCA.leaf("api.example.com"))}})) // the attacker's upstream, where its DNS answer sends the proxy
	t.Cleanup(func() { _ = ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.Header.Get("X-Api-Key"))) })) // echoes the credential header it got
	p, _, _ := testProxy(t, "api.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, ln.Addr().String())
	if p.Terminate(sessionCA, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "api.example.com", Header: "X-Api-Key", Placeholder: testPlaceholder}}) == nil { // an error here is the fix
		if code, body := get(t, clientVia(listen(t, p, 443), caPool(t, sessionCA)), "https://api.example.com/v1/x", testPlaceholder); code < 400 || strings.Contains(body, "real-secret") {
			t.Errorf("through a relative SSL_CERT_FILE the attacker's upstream answered (%d, %q); want the secret withheld", code, body)
		}
	}
}
