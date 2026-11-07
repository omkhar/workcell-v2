// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestForwardStaysSplicedBesideTermination: a bare entry is terminated at 443 and a
// name:port entry is spliced to the upstream byte for byte, the ClientHello included, even
// for one host allowed both ways; the other port of each is refused.
func TestForwardStaysSplicedBesideTermination(t *testing.T) {
	t.Parallel()
	cases := []struct {
		allow, tls, forward, denied string // tls and forward: what each port does for example.com
	}{
		{"example.com:443 example.com:8443", "terminated", "spliced", ""},
		{"example.com:8443", "sni_not_allowed", "spliced", "sni_not_allowed"},
		{"example.com:443", "terminated", "port_not_allowed", "port_not_allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.allow, func(t *testing.T) {
			https := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host) }))
			defer https.Close()
			echo := must(net.Listen("tcp", "127.0.0.1:0"))
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { _, _ = io.Copy(c, c); c.Close() }()
				}
			}()
			p, log, _ := testProxy(t, tc.allow, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, https.Listener.Addr().String())
			p.upstreamRoots = x509.NewCertPool()
			p.upstreamRoots.AddCert(https.Certificate())
			dial := p.dial
			p.dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
				if addr.Port() == 8443 {
					return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
				}
				return dial(ctx, addr)
			}
			ca := must(NewSessionCA([]string{"example.com"}, time.Now().Add(time.Hour)))
			must(0, p.Terminate(ca, nil, nil))
			tlsAddr, fwdAddr := listen(t, p, 443), listen(t, p, 8443)
			resp, err := clientVia(tlsAddr, caPool(t, ca)).Get("https://example.com/")
			body := ""
			if err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				body = string(b)
			}
			if served := err == nil && body == "example.com"; served != (tc.tls == "terminated") {
				t.Errorf("443: got (%q, %v), want %s", body, err, tc.tls)
			}
			hello := clientHello(t, "example.com")
			c := must(net.Dial("tcp", fwdAddr))
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write(hello)
			back := make([]byte, len(hello))
			if _, err := io.ReadFull(c, back); (err == nil) != (tc.forward == "spliced") || err == nil && !bytes.Equal(back, hello) {
				t.Errorf("8443: echoed %d bytes, %v; want %s of %d bytes", len(back), err, tc.forward, len(hello))
			}
			var reasons []string
			for _, d := range denies(t, p, log) {
				reasons = append(reasons, d.Reason)
			}
			if got := strings.Join(reasons, ","); got != tc.denied {
				t.Errorf("deny reasons %q, want %q", got, tc.denied)
			}
		})
	}
}
