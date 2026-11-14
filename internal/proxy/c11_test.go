// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F6, finding C11 of S-1005 (I10, with I12's hang). A client needs a few KiB of headers, and ADR-003 budgets 69 KiB for an idle terminated keep-alive, so a
// header block of 100 KiB is answered 431 before any handler runs and the connection closed. Otherwise a guest holding the 1024-connection cap with 1 MiB blocks
// and a declared, withheld body pins about 1 GiB of the proxy's heap for as long as it likes. Every connection is the test's own, on loopback (T8, S12).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestOversizedHeaderBlockRefused: a 100 KiB header block on a raw TLS connection to the token endpoint of a sign-in row, body declared and withheld, and to a
// plain terminated host, is answered "HTTP/1.1 431" and the connection then closed. Unfixed, the token endpoint answers 100 Continue and holds the block live
// while it waits for the body; the terminated host forwards the block upstream.
func TestOversizedHeaderBlockRefused(t *testing.T) {
	c, _, _, _ := signinFixture(t, &provider{}, &tokenBroker{})
	tr := c.Transport.(*http.Transport)
	addr, ca, _, _ := terminateFixture(t, &fakeBroker{})
	pad := "\r\n"
	for i := 0; i < 25; i++ {
		pad += fmt.Sprintf("X-Pad-%02d: %s\r\n", i, strings.Repeat("x", 4000))
	}
	rows := []struct {
		host, request string
		dial          func() (net.Conn, error)
		roots         *x509.CertPool
	}{
		{"login.example.com", "POST " + tokenEndpointPath + " HTTP/1.1\r\nHost: login.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue" + pad + "\r\n",
			func() (net.Conn, error) { return tr.DialContext(context.Background(), "tcp", "") }, tr.TLSClientConfig.RootCAs},
		{"example.com", "GET / HTTP/1.1\r\nHost: example.com" + pad + "\r\n", func() (net.Conn, error) { return net.Dial("tcp", addr) }, caPool(t, ca)},
	}
	for _, row := range rows {
		raw, err := row.dial()
		if err != nil {
			t.Fatal(err)
		}
		conn := tls.Client(raw, &tls.Config{ServerName: row.host, RootCAs: row.roots})
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, werr := conn.Write([]byte(row.request))
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if !strings.HasPrefix(line, "HTTP/1.1 431 ") {
			t.Errorf("%s: a %d KiB header block was answered %q (write %v, read %v), want HTTP/1.1 431", row.host, len(row.request)>>10, line, werr, err)
			continue
		}
		if _, err := io.Copy(io.Discard, r); errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s: the connection is still open five seconds after the 431, want it closed", row.host)
		}
	}
}
