// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/proxy.go

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

const (
	extECH        = 0xfe0d // the encrypted_client_hello extension type
	peekTimeout   = 10 * time.Second
	dialTimeout   = 10 * time.Second // per resolve and per dial attempt
	connectBudget = 3 * dialTimeout  // all dial attempts for one connection
	maxHelloBytes = 16 << 10         // a real hello, post-quantum key share included, is under 2 KiB; bounds what each slot holds while peeking (I10)
	maxConns      = 1024             // concurrent connections across all ports
)

var publicIPv6 = netip.MustParsePrefix("2000::/3") // the only global unicast IPv6 block; IPv4-embedding forms, site-local and SRv6 lie outside

// blockedPrefixes adds what netip does not classify: shared, reserved or documentation IPv4 space, special blocks inside 2000::/3 and a cloud metadata address on public space.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),        // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),    // CGNAT; holds the 100.100.100.200 metadata address
	netip.MustParsePrefix("192.0.0.0/24"),     // IETF assignments; holds the 192.0.0.192 metadata address
	netip.MustParsePrefix("168.63.129.16/32"), // Azure platform virtual IP (WireServer) metadata address
	netip.MustParsePrefix("192.80.8.124/32"),  // Equinix Metal (formerly Packet) metadata address
	netip.MustParsePrefix("2001::/23"),        // IETF protocol assignments: Teredo, benchmarking, ORCHID
	netip.MustParsePrefix("2002::/16"),        // 6to4
	netip.MustParsePrefix("192.0.2.0/24"),     // documentation (TEST-NET-1)
	netip.MustParsePrefix("192.88.99.0/24"),   // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),    // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),  // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),   // documentation (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),      // reserved
	netip.MustParsePrefix("2001:db8::/32"),    // documentation
	netip.MustParsePrefix("3fff::/20"),        // documentation
}

// blockedAddr reports whether the proxy must refuse to connect to a, given the networks of the host's own interfaces.
func blockedAddr(a netip.Addr, host []netip.Prefix) bool {
	a = a.Unmap()
	in := func(p netip.Prefix) bool { return p.Contains(a) }
	return !a.IsGlobalUnicast() || a.IsPrivate() || a.Is6() && !publicIPv6.Contains(a) ||
		slices.ContainsFunc(blockedPrefixes, in) || slices.ContainsFunc(host, in)
}

// Proxy admits allowlisted connections and logs each denial as one JSONL line.
type Proxy struct {
	allow  *Allowlist
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	nets   func() ([]netip.Prefix, error) // the host's own networks (hostNets), read at each connect (I4)

	// TLS termination; set by Terminate, upstreamRoots from the system roots and SSL_CERT_FILE, after SSL_CERT_DIR passed the same check.
	terminate     map[string][]TerminateRule
	signin        map[string][]TerminateRule // by token host: the rules whose endpoint it serves
	ca            *SessionCA
	broker        Broker
	transport     *http.Transport
	upstreamRoots *x509.CertPool

	slots chan struct{} // one token per live connection

	rec Recorder
}

// Recorder takes one record of a connection attempt, allowed or refused (I9). It need not wait for the disk. A *audit.Log is one, and the one nil *audit.Log takes nothing.
type Recorder interface{ Note(audit.Record) error }

// New returns a proxy for allow that records every attempt it decides to rec.
func New(allow *Allowlist, rec Recorder) *Proxy {
	return &Proxy{
		allow: allow,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", addr.String())
		},
		nets: hostNets, slots: make(chan struct{}, maxConns), rec: rec}
}

// hostNets returns the host's own networks (I4): the prefixes of its interfaces and, on Linux, the local and on-link rows of its route tables (hostRoutes), so a neighbour on a link whose interface prefix is host-length (a /32; a /128 beside the router's on-link /64) and an address held by a route alone are known too. A list or table that cannot be read refuses.
func hostNets() ([]netip.Prefix, error) {
	nets, err := hostRoutes()
	addrs, err2 := net.InterfaceAddrs()
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		nets, err2 = append(nets, p), errors.Join(err2, err)
	}
	return nets, errors.Join(err, err2)
}

// Serve handles connections from ln, which receives traffic for port, until ln is closed.
func (p *Proxy) Serve(ln net.Listener, port uint16) error {
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil {
			time.Sleep(50 * time.Millisecond) // e.g. EMFILE; retry instead of exiting
			continue
		}
		select {
		case p.slots <- struct{}{}:
			go func() { defer func() { <-p.slots }(); p.handle(conn, port) }()
		default:
			_ = conn.Close() // at the limit: shed load and record nothing; the relay adapter, the only listener, holds an equal cap and closes first
		}
	}
}

func (p *Proxy) handle(client net.Conn, port uint16) {
	defer client.Close()
	host, replay, reason := p.route(client, port)
	if reason != "" {
		p.Deny(host, port, reason)
		return
	}
	if p.Deny(host, port, audit.Allowed) != nil { // no record, no connection (I9): nothing is dialled, and the guest reads EOF
		closeWrite(client) // FIN first, then what the guest sent is read until it closes, so that no unread byte turns the close into a reset
		_ = client.SetReadDeadline(time.Now().Add(peekTimeout))
		_, _ = io.Copy(io.Discard, client)
		return
	}
	if _, ok := p.terminate[host]; ok && port == tlsPort {
		p.serveTerminated(client, host, replay)
		return
	}
	upstream, reason := p.connect(host, port)
	if reason != "" {
		p.Deny(host, port, reason)
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(replay); err == nil {
		splice(client, upstream)
	}
}

// route picks the upstream host for a connection. On port 443 it reads the ClientHello and returns the bytes it read, which the caller must replay.
func (p *Proxy) route(client net.Conn, port uint16) (host string, replay []byte, reason string) {
	if port != tlsPort {
		host, ok := p.allow.forward[port]
		if !ok {
			return "", nil, "port_not_allowed"
		}
		return host, nil, ""
	}
	if client.SetReadDeadline(time.Now().Add(peekTimeout)) != nil {
		return "", nil, "no_sni"
	}
	sni, replay, ok := peekSNI(client)
	if !ok || client.SetReadDeadline(time.Time{}) != nil {
		return "", nil, "no_sni"
	}
	// ToLower maps the Kelvin sign (U+212A) to "k"; a length change marks a non-ASCII fold.
	lower := strings.ToLower(sni)
	if len(lower) != len(sni) || !p.allow.sni[lower] {
		return sni, nil, "sni_not_allowed"
	}
	return lower, replay, ""
}

// connect resolves host itself, as a rooted name so no search suffix is appended, and dials a resolved address, so a later DNS answer cannot change the target. One blocked address, or host networks it cannot read, refuses the host.
func (p *Proxy) connect(host string, port uint16) (net.Conn, string) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	addrs, err := p.lookup(ctx, host+".")
	if err != nil || len(addrs) == 0 {
		return nil, "resolve_failed"
	}
	nets, err := p.nets()
	if err != nil || slices.ContainsFunc(addrs, func(a netip.Addr) bool { return blockedAddr(a, nets) }) {
		return nil, "blocked_address"
	}
	deadline := time.Now().Add(connectBudget)
	for i, a := range addrs {
		// Share the remaining budget with the addresses still to try, so silent early answers cannot starve a later one.
		share := min(dialTimeout, time.Until(deadline)/time.Duration(len(addrs)-i))
		if share <= 0 {
			break
		}
		dctx, stop := context.WithTimeout(context.Background(), share)
		conn, err := p.dial(dctx, netip.AddrPortFrom(a.Unmap(), port))
		stop()
		if err == nil {
			return conn, ""
		}
	}
	return nil, "dial_failed"
}

// recordingConn records what the TLS stack reads and drops what it writes, so the client never sees a response from the proxy itself.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (r *recordingConn) Read(b []byte) (int, error) {
	room := maxHelloBytes - r.buf.Len()
	if room <= 0 {
		return 0, errors.New("client hello too large")
	}
	n, err := r.Conn.Read(b[:min(len(b), room)])
	r.buf.Write(b[:n])
	return n, err
}

func (r *recordingConn) Write(b []byte) (int, error) { return len(b), nil }

// peekSNI parses the ClientHello with crypto/tls and aborts the handshake as soon as the SNI is known. It returns the bytes read from conn.
func peekSNI(conn net.Conn) (sni string, read []byte, ok bool) {
	rec := &recordingConn{Conn: conn}
	abort := errors.New("sni peeked")
	_ = tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if ok = !slices.Contains(hello.Extensions, extECH); ok { // the outer name of an ECH hello is not the name the upstream serves
				sni = hello.ServerName
			}
			return nil, abort
		},
	}).Handshake()
	return sni, rec.buf.Bytes(), ok && sni != ""
}

func splice(client, upstream net.Conn) {
	var wg sync.WaitGroup
	pipe := func(dst, src net.Conn) { _, _ = io.Copy(dst, src); closeWrite(dst) }
	// ponytail: no idle timeout; a peer that never closes holds its goroutines.
	wg.Go(func() { pipe(upstream, client) })
	wg.Go(func() { pipe(client, upstream) })
	wg.Wait()
}

// closeWrite tells the peer of c that nothing more comes: c's own half-close where it has one, else a close.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

// Deny records one connection attempt, admitted or refused, the proxy's own or one from outside it (the resolver's, the relay's), through the same writer, so that the log keeps one order. An admitting caller acts only on nil (I9).
func (p *Proxy) Deny(host string, port uint16, reason string) error {
	return p.rec.Note(audit.Record{Event: audit.Connect, Host: host, Port: port, Result: reason})
}
