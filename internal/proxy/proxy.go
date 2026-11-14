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
	"sync/atomic"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

// extECH is the encrypted_client_hello extension type.
const extECH = 0xfe0d

const (
	peekTimeout   = 10 * time.Second
	dialTimeout   = 10 * time.Second // per resolve and per dial attempt
	connectBudget = 3 * dialTimeout  // all dial attempts for one connection
	maxHelloBytes = 16 << 10         // a real hello, post-quantum key share included, is under 2 KiB; bounds what each slot holds while peeking (I10)
	maxConns      = 1024             // concurrent connections across all ports
)

var publicIPv6 = netip.MustParsePrefix("2000::/3") // the only global unicast IPv6 block; IPv4-embedding forms, site-local and SRv6 lie outside

// blockedPrefixes adds the ranges that netip does not classify: shared,
// reserved or documentation IPv4 space and special blocks inside 2000::/3.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT; holds the 100.100.100.200 metadata address
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF assignments; holds the 192.0.0.192 metadata address
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments: Teredo, benchmarking, ORCHID
	netip.MustParsePrefix("2002::/16"),       // 6to4
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (TEST-NET-1)
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("3fff::/20"),       // documentation
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
	nets   func() ([]netip.Prefix, error) // the networks of the host's own interfaces, read at each connect (I4)

	// TLS termination; set by Terminate, upstreamRoots from the system roots and SSL_CERT_FILE.
	terminate     map[string][]TerminateRule
	signin        map[string][]TerminateRule // by token host: the rules whose endpoint it serves
	ca            *SessionCA
	broker        Broker
	transport     *http.Transport
	upstreamRoots *x509.CertPool

	slots chan struct{} // one token per live connection
	shed  chan uint16   // ports of shed connections awaiting a deny line
	lost  atomic.Uint64 // shed connections the full queue could not take, awaiting one count line

	rec Recorder
}

// Recorder takes one record of a connection attempt, allowed or refused (I9). It need not wait for
// the disk. A *audit.Log is one, and the one nil *audit.Log takes nothing.
type Recorder interface{ Note(audit.Record) error }

// New returns a proxy for allow that records every attempt it decides to rec.
func New(allow *Allowlist, rec Recorder) *Proxy {
	p := &Proxy{
		allow: allow,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "tcp", addr.String())
		},
		nets: func() ([]netip.Prefix, error) {
			addrs, err := net.InterfaceAddrs()
			nets := make([]netip.Prefix, len(addrs))
			for i := 0; err == nil && i < len(addrs); i++ {
				nets[i], err = netip.ParsePrefix(addrs[i].String())
			}
			return nets, err
		},
		slots: make(chan struct{}, maxConns),
		shed:  make(chan uint16, 64),
		rec:   rec,
	}
	go func() { // each queued refusal's line, then one line counting those the full queue could not take
		for port := range p.shed {
			p.Deny("", port, "overloaded")
			if n := p.lost.Swap(0); n > 0 {
				_ = p.rec.Note(audit.Record{Event: audit.Connect, Result: "overloaded", Count: n})
			}
		}
	}()
	return p
}

// Serve handles connections from ln, which receives traffic for port, until
// ln is closed.
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
			go func() {
				defer func() { <-p.slots }()
				p.handle(conn, port)
			}()
		default:
			_ = conn.Close() // at the limit: shed load, its refusal queued or counted so a stalled log cannot stall accept
			select {
			case p.shed <- port:
			default:
				p.lost.Add(1)
			}
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
	if _, ok := p.terminate[host]; ok && port == tlsPort {
		p.Deny(host, port, audit.Allowed)
		p.serveTerminated(client, host, replay)
		return
	}
	upstream, reason := p.connect(host, port)
	if reason != "" {
		p.Deny(host, port, reason)
		return
	}
	defer upstream.Close()
	p.Deny(host, port, audit.Allowed)
	if _, err := upstream.Write(replay); err != nil {
		return
	}
	splice(client, upstream)
}

// route picks the upstream host for a connection. On port 443 it reads the
// ClientHello and returns the bytes it read, which the caller must replay.
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

// connect resolves host itself, as a rooted name so no search suffix is appended, and dials a resolved address, so a
// later DNS answer cannot change the target. One blocked address, or host networks it cannot read, refuses the host.
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

// recordingConn records what the TLS stack reads and drops what it writes, so
// the client never sees a response from the proxy itself.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

var errHelloTooLarge = errors.New("client hello too large")

func (r *recordingConn) Read(b []byte) (int, error) {
	room := maxHelloBytes - r.buf.Len()
	if room <= 0 {
		return 0, errHelloTooLarge
	}
	n, err := r.Conn.Read(b[:min(len(b), room)])
	r.buf.Write(b[:n])
	return n, err
}

func (r *recordingConn) Write(b []byte) (int, error) { return len(b), nil }

// peekSNI parses the ClientHello with crypto/tls and aborts the handshake as
// soon as the SNI is known. It returns the bytes read from conn.
func peekSNI(conn net.Conn) (sni string, read []byte, ok bool) {
	rec := &recordingConn{Conn: conn}
	abort := errors.New("sni peeked")
	_ = tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// The outer name of an ECH hello is not the name the upstream serves.
			for _, ext := range hello.Extensions {
				if ext == extECH {
					return nil, abort
				}
			}
			sni, ok = hello.ServerName, true
			return nil, abort
		},
	}).Handshake()
	return sni, rec.buf.Bytes(), ok && sni != ""
}

func splice(client, upstream net.Conn) {
	var wg sync.WaitGroup
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	// ponytail: no idle timeout; a peer that never closes holds its goroutines.
	wg.Go(func() { pipe(upstream, client) })
	wg.Go(func() { pipe(client, upstream) })
	wg.Wait()
}

// Deny records one connection attempt, admitted or refused, the proxy's own or one from outside
// it (the resolver's, the relay's), through the same writer, so that the log keeps one order.
func (p *Proxy) Deny(host string, port uint16, reason string) {
	_ = p.rec.Note(audit.Record{Event: audit.Connect, Host: host, Port: port, Result: reason})
}
