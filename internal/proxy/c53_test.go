// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C53 of S-1005 (I6, through it I5; medium), the sibling of C30: upstreamRoots refuses a relative SSL_CERT_FILE, yet x509.SystemCertPool also reads each entry of
// SSL_CERT_DIR (certs, ".", or one of a list; a precondition the attacker does not control) against the working directory, so the repository ships certs/ca.pem and a leaf
// that CA signed, from the network attacker as DNS for an allowed name, verifies, and the real secret is sent to it. This file waited under escape/_pending/S-F36/
// until fix unit S-F36 moved it here (SPEC S4): it failed before the fix, passes after, and stays in the suite.

package proxy

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestRelativeSSLCertDirIsRefused re-runs this test binary once per relative spelling of SSL_CERT_DIR, since Go loads the system pool once per process. The child, in
// a working directory holding ca.pem and certs/ca.pem, must have Terminate refuse, or withhold the secret from the attacker's upstream.
func TestRelativeSSLCertDirIsRefused(t *testing.T) {
	if os.Getenv("C53_CHILD") == "" {
		for _, dir := range []string{"certs", ".", "/etc/ssl/certs:certs"} {
			cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
			cmd.Dir, cmd.Env = t.TempDir(), append(os.Environ(), "C53_CHILD=1", "SSL_CERT_DIR="+dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("under SSL_CERT_DIR=%q: %v\n%s", dir, err, out)
			}
		}
		return
	}
	repoCA, sessionCA := must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour))), must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour)))
	must(0, os.Mkdir("certs", 0o700)) // the attacker made repoCA and keeps the key of the leaf below
	must(0, os.WriteFile("certs/ca.pem", repoCA.CertPEM(), 0o600))
	must(0, os.WriteFile("ca.pem", repoCA.CertPEM(), 0o600))
	ln := must(tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*must(repoCA.leaf("api.example.com"))}}))       // the attacker's upstream, where its DNS answer sends the proxy
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.Header.Get("X-Api-Key"))) })) // echoes the credential header it got
	p, _, _ := testProxy(t, "api.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, ln.Addr().String())
	if p.Terminate(sessionCA, &fakeBroker{value: "real-secret"}, []TerminateRule{{Host: "api.example.com", Header: "X-Api-Key", Placeholder: testPlaceholder}}) == nil { // an error here is the fix
		if code, body := get(t, clientVia(listen(t, p, 443), caPool(t, sessionCA)), "https://api.example.com/v1/x", testPlaceholder); code < 400 || body == "real-secret" {
			t.Errorf("through a relative SSL_CERT_DIR the attacker's upstream answered (%d, %q); want the secret withheld", code, body)
		}
	}
}
