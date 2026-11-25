// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// T6 regression test for finding C13 of S-1006 (I10, on the I4 rebind path), fixed in S-F8. Before the fix the transport Terminate built gave the upstream TLS handshake no timeout, and Go's transport dials on a context cut off from the request's (context.WithoutCancel), so once the host resolver
// answered an allowed name with an address the network attacker runs, one guest request to the terminated host started a dial the guest's close did not end: the relay slot and the proxy slot were released, but the upstream socket, its goroutines and its handshake buffers stayed for as long as the attacker's server accepted and then stayed silent. One request, one host fd, outside the 1024-slot bound.
package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestUpstreamHandshakeEndsWithTheGuest: guests each send one request to a terminated host whose upstream accepts and never answers the ClientHello, then close. Pass → once no slot is held, every upstream connection ends within the dial timeout and a little. Still held → FAIL (I10).
func TestUpstreamHandshakeEndsWithTheGuest(t *testing.T) {
	t.Parallel()
	tarpit := must(net.Listen("tcp", "127.0.0.1:0")).(*net.TCPListener)
	t.Cleanup(func() { _ = tarpit.Close() })
	_ = tarpit.SetDeadline(time.Now().Add(5 * time.Second))
	p, _, _ := testProxy(t, "api.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, tarpit.Addr().String())
	ca := must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour)))
	must(0, p.Terminate(ca, &fakeBroker{}, nil))
	addr, roots := listen(t, p, 443), caPool(t, ca)
	var held []net.Conn
	for range 8 {
		guest := must(tls.Dial("tcp", addr, &tls.Config{ServerName: "api.example.com", RootCAs: roots}))
		must(io.WriteString(guest, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
		up := must(tarpit.Accept()) // the proxy's dial for this request, whose ClientHello the attacker never answers
		t.Cleanup(func() { _ = up.Close() })
		held = append(held, up)
		_ = guest.Close() // the guest is gone, about 100 ms after it asked
	}
	for wait := time.Now().Add(5 * time.Second); len(p.slots) > 0 && time.Now().Before(wait); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(p.slots); n > 0 {
		t.Fatalf("%d slots still held after every guest closed", n)
	}
	deadline := time.Now().Add(dialTimeout + 2*time.Second)
	for i, up := range held {
		_ = up.SetReadDeadline(deadline)
		if _, err := io.Copy(io.Discard, up); err != nil {
			t.Errorf("upstream connection %d is still held with no slot held, %v after its guest closed: %v", i, dialTimeout+2*time.Second, err)
		}
	}
}
