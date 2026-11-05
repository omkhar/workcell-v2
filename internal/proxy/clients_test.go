// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
)

// TestClientsValidateSessionLeaf is the accept clause of TLS termination for the clients: a
// TLS server with a session leaf for localhost, the CA in the trust stores guest.WriteTrust
// writes, the same files and variables the guest gets, and curl, Node, Python, Java and
// the Go standard library each validating it under that environment alone. The guest image
// has none of these tools, so this runs here with go test, and each tool that is not on
// PATH is skipped. When the host has Debian's bundle the test starts from a copy of it, so
// the keystore and the bundle hold the public roots too, as they do in the guest.
func TestClientsValidateSessionLeaf(t *testing.T) {
	ca, err := NewSessionCA([]string{"localhost"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "certs")
	if bundle, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); err == nil {
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "ca-certificates.crt"), bundle, 0o644)
	}
	if err := guest.WriteTrust(dir, ca.CertPEM(), time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", ":0", &tls.Config{MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return ca.leaf("localhost") }})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	url := "https://localhost:" + port + "/"
	env := append(guest.TrustEnv(dir), "PATH="+os.Getenv("PATH"), "HOME="+t.TempDir())
	// Java's source-file mode compiles and runs one file; the store comes from JAVA_TOOL_OPTIONS.
	java := filepath.Join(t.TempDir(), "Get.java")
	os.WriteFile(java, []byte("public class Get { public static void main(String[] a) throws Exception {\n"+
		"var c = (java.net.HttpURLConnection) java.net.URI.create(a[0]).toURL().openConnection(); System.out.println(c.getResponseCode()); } }\n"), 0o644)
	node := "require('https').get(process.argv[1], r => { console.log(r.statusCode); process.exit(0) }).on('error', e => { console.error(e.message); process.exit(1) })"
	clients := map[string][]string{
		"curl":   {"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", url},
		"node":   {"node", "-e", node, url},
		"python": {"python3", "-I", "-c", "import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1]).status)", url},
		"java":   {"java", java, url},
	}
	for name, argv := range clients {
		t.Run(name, func(t *testing.T) {
			if _, err := exec.LookPath(argv[0]); err != nil {
				t.Skipf("%s is not on PATH", argv[0])
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			cmd.Env = env
			out, err := cmd.Output()
			if err != nil || strings.TrimSpace(string(out)) != "200" {
				t.Errorf("%v: %v, output %q, want 200", argv, err, out)
			}
		})
	}
	t.Run("go", func(t *testing.T) {
		// Go reads SSL_CERT_FILE once per process, and on macOS the first TLS handshake in the test binary
		// fixes the roots, so nil roots would depend on test order: use the file the variable names, as a guest program does.
		i := slices.IndexFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "SSL_CERT_FILE=") })
		pem, err := os.ReadFile(strings.TrimPrefix(env[max(i, 0)], "SSL_CERT_FILE=")) // no entry: env[0] is no certificate file either
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			t.Fatalf("SSL_CERT_FILE is missing from env or names no certificate file: %v", err)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}).Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	})
}
