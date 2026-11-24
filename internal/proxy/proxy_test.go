// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/proxy_test.go

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

func TestBlockedAddr(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"127.0.0.1": true, "::1": true, // loopback
		"10.1.2.3": true, "172.16.0.1": true, "192.168.1.1": true, // private
		"fd00:ec2::254": true, "fc00::1": true, // AWS IPv6 metadata (ULA)
		"169.254.169.254": true, "fe80::1": true, // metadata (link-local)
		"0.0.0.0": true, "::": true, "0.1.2.3": true, // unspecified, "this network"
		"224.0.0.1": true, "ff02::1": true, "255.255.255.255": true, // multicast, broadcast
		"100.64.0.1": true, "100.100.100.200": true, "192.0.0.192": true, // CGNAT, Alibaba metadata, Oracle metadata
		"168.63.129.16": true, "::ffff:168.63.129.16": true, // Azure platform virtual IP (WireServer), plain and IPv4-mapped
		"::ffff:127.0.0.1": true, "::ffff:169.254.169.254": true, "::ffff:10.0.0.1": true, // IPv4-mapped
		"::127.0.0.1": true, "64:ff9b::a9fe:a9fe": true, "64:ff9b:1::1": true, // IPv4-compatible, NAT64 of 169.254.169.254
		"2002:a9fe:a9fe::1": true, "2001:0:4136:e378::1": true, // 6to4, Teredo
		"192.0.2.1": true, "198.51.100.1": true, "203.0.113.10": true, // documentation
		"198.18.0.1": true, "198.19.255.255": true, // benchmarking
		"192.88.99.1": true, "240.0.0.1": true, "100::1": true, "2001:2::1": true, // reserved, discard-only
		"::ffff:0:a9fe:a9fe": true, "::ffff:0:8.8.8.8": true, // IPv4-translatable of 169.254.169.254
		"4000::1": true, "fec0::1": true, // outside 2000::/3, site-local
		"2001:10::1": true, "2001:20::1": true, "2001:200::1": false, // ORCHID, ORCHIDv2, just above 2001::/23
		"2001:db8::1": true, "3fff::1": true, "5f00::1": true, // documentation
		"198.17.255.255": false, "198.20.0.0": false, // just below and above benchmarking
		"8.8.8.8": false, "100.63.255.255": false, "100.128.0.0": false, // public; just below and above CGNAT
		"2606:4700:4700::1111": false, "::ffff:8.8.8.8": false, "2001:4860:4860::8888": false, "2a00:1450:4001:80b::200e": false,
	}
	for text, want := range cases {
		if got := blockedAddr(netip.MustParseAddr(text), nil); got != want {
			t.Errorf("blockedAddr(%s) = %v, want %v", text, got, want)
		}
	}
	if !blockedAddr(netip.Addr{}, nil) {
		t.Error("blockedAddr(zero Addr) = false, want true")
	}
}

// clientHello returns the bytes a TLS client sends first for serverName.
func clientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	rec := &recordingConn{Conn: server}
	_ = tls.Server(rec, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, errors.New("stop")
	}}).Handshake()
	_ = server.Close()
	_ = client.Close()
	return bytes.Clone(rec.buf.Bytes())
}

// feed returns a conn whose reads yield data then EOF.
func feed(data []byte) net.Conn {
	client, server := net.Pipe()
	go func() { _, _ = client.Write(data); _ = client.Close() }()
	return server
}

func TestPeekSNI(t *testing.T) {
	t.Parallel()
	hello := clientHello(t, "api.example.com")
	conn := feed(hello)
	defer conn.Close()
	if sni, read, ok := peekSNI(conn); !ok || sni != "api.example.com" || !bytes.Equal(read, hello) {
		t.Fatalf("peekSNI = (%q, ok=%v) after %d bytes, want api.example.com after the %d-byte ClientHello", sni, ok, len(read), len(hello))
	}

	record := append([]byte{0x16, 3, 3, 0x40, 0, 1, 1, 0, 0}, make([]byte, 16380)...) // a full-size record opening a 64 KiB hello
	for name, data := range map[string][]byte{
		"empty":                   nil,
		"plaintext":               []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		"truncated":               hello[:len(hello)/2],
		"no sni":                  clientHello(t, ""),
		"unfinished 64 KiB hello": bytes.Repeat(record, 4), // stops 4 bytes short of the hello; the peek must give up within 16 KiB (I10)
	} {
		conn := feed(data)
		if sni, read, ok := peekSNI(conn); ok || len(read) > 16<<10 {
			t.Errorf("%s: peekSNI = (%q, ok=%v) after %d bytes, want failure within 16 KiB", name, sni, ok, len(read))
		}
		_ = conn.Close()
	}
}

func FuzzPeekSNI(f *testing.F) {
	f.Add(clientHello(f, "api.example.com"))
	f.Add(clientHello(f, ""))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := feed(data)
		defer conn.Close()
		sni, read, ok := peekSNI(conn)
		if ok && sni == "" {
			t.Fatal("peekSNI ok with empty SNI")
		}
		if !bytes.HasPrefix(data, read) {
			t.Fatal("peekSNI returned bytes that are not a prefix of the input")
		}
	})
}

// testProxy returns a proxy whose resolver maps every host to addrs and whose dialer sends every dial to target, recording the address it was asked for.
func testProxy(t *testing.T, allow string, addrs []netip.Addr, target string) (*Proxy, *recorder, *[]netip.AddrPort) {
	t.Helper()
	a := must(ParseAllowlist(allow, "allowlist"))
	log := &recorder{}
	p := New(a, log)
	var dialed []netip.AddrPort
	p.lookup = func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }
	p.dial = func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		log.mu.Lock()
		dialed = append(dialed, addr)
		log.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}
	return p, log, &dialed
}

// testLedger is a real session log in a new directory, for a broker to write to.
func testLedger(t *testing.T) *audit.Log {
	t.Helper()
	l := must(audit.Create(t.TempDir(), ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), time.Now))
	t.Cleanup(func() { l.Close() })
	return l
}

// listen serves p on a loopback listener for port and returns its address.
func listen(t *testing.T, p *Proxy, port uint16) string {
	t.Helper()
	ln := must(net.Listen("tcp", "127.0.0.1:0"))
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = p.Serve(ln, port) }()
	return ln.Addr().String()
}

// recorder collects what the proxy notes. Its mutex also guards the dials the tests record.
type recorder struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (r *recorder) Note(rec audit.Record) error {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
	return nil
}

// denyLine is a refusal as the tests compare it: the count of its (host, port, reason) so far and its number among the refusals.
type denyLine struct {
	Host   string
	Port   uint16
	Reason string
	Count  uint64
	Seq    uint64
}

// denies are the refusals noted so far; a connection that went through is not one.
func denies(t *testing.T, p *Proxy, log *recorder) []denyLine {
	t.Helper()
	log.mu.Lock()
	defer log.mu.Unlock()
	var out []denyLine
	counts := map[denyLine]uint64{}
	for _, r := range log.recs {
		if r.Event != audit.Connect || r.Result == audit.Allowed {
			continue
		}
		d := denyLine{Host: r.Host, Port: r.Port, Reason: r.Result}
		counts[d]++
		d.Count, d.Seq = counts[d], uint64(len(out)+1)
		out = append(out, d)
	}
	return out
}

func TestConnectSharesBudgetAcrossAddresses(t *testing.T) {
	t.Parallel()
	p := New(&Allowlist{}, &recorder{})
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		a := netip.MustParseAddr
		return []netip.Addr{a("8.8.8.8"), a("8.8.4.4"), a("1.1.1.1"), a("1.0.0.1")}, nil
	}
	var timeouts []time.Duration
	p.dial = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		d, _ := ctx.Deadline()
		timeouts = append(timeouts, time.Until(d))
		return nil, errors.New("unreachable")
	}
	// Four addresses split the 30 s budget: the first attempt gets a quarter of it, not the full 10 s, so the fourth address is still reachable.
	if _, reason := p.connect("example.com", 443); reason != "dial_failed" || len(timeouts) != 4 || timeouts[0] > connectBudget/4 || timeouts[0] < connectBudget/4-time.Second {
		t.Fatalf("reason = %q, dial timeouts = %v; want dial_failed after 4 attempts with a first share near %v", reason, timeouts, connectBudget/4)
	}
}

// withExtension returns a ClientHello record with one more empty extension.
func withExtension(t *testing.T, hello []byte, typ uint16) []byte {
	t.Helper()
	off := 5 + 4 + 2 + 32
	off += 1 + int(hello[off])                           // session id
	off += 2 + int(binary.BigEndian.Uint16(hello[off:])) // cipher suites
	off += 1 + int(hello[off])                           // compression
	out := append(bytes.Clone(hello), byte(typ>>8), byte(typ), 0, 0)
	binary.BigEndian.PutUint16(out[off:], binary.BigEndian.Uint16(out[off:])+4)
	binary.BigEndian.PutUint16(out[3:], binary.BigEndian.Uint16(out[3:])+4)
	hs := uint32(out[6])<<16 | uint32(out[7])<<8 | uint32(out[8])
	hs += 4
	out[6], out[7], out[8] = byte(hs>>16), byte(hs>>8), byte(hs)
	return out
}

func TestPeekSNIRefusesECH(t *testing.T) {
	t.Parallel()
	hello := clientHello(t, "example.com")
	_, _, plain := peekSNI(feed(withExtension(t, hello, 0x0a0a))) // the control: an unknown extension is accepted
	if _, _, ech := peekSNI(feed(withExtension(t, hello, extECH))); !plain || ech {
		t.Fatalf("hello with an unknown extension accepted %t, with ECH accepted %t; want true then false", plain, ech)
	}
}

func TestRouteRefusesUnicodeFoldedSNI(t *testing.T) {
	p := New(&Allowlist{sni: map[string]bool{"k.example": true}}, &recorder{})
	c, srv := net.Pipe()
	go func() { _, _ = srv.Write(clientHello(t, "\u212a.example")) }()
	if _, _, got := p.route(c, 443); got != "sni_not_allowed" {
		t.Fatalf("route reason = %q, want sni_not_allowed", got)
	}
}

func TestConnectVetsEveryAnswerOnEveryConnection(t *testing.T) {
	t.Parallel()
	a, home := netip.MustParseAddr, []netip.Prefix{netip.MustParsePrefix("192.175.48.0/25")}
	cases := []struct {
		name    string
		answers [][]netip.Addr // one answer set per lookup; a nil set is a lookup error
		nets    []netip.Prefix // the host's own networks
		netsErr error          // the error reading them
		reasons []string
	}{
		{"public and private mixed", [][]netip.Addr{{a("8.8.8.8"), a("10.255.255.254")}}, nil, nil, []string{"blocked_address"}},
		{"private listed first", [][]netip.Addr{{a("10.255.255.254"), a("8.8.8.8")}}, nil, nil, []string{"blocked_address"}},
		{"mapped loopback", [][]netip.Addr{{a("::ffff:127.0.0.1")}}, nil, nil, []string{"blocked_address"}},
		{"unspecified", [][]netip.Addr{{a("0.0.0.0")}}, nil, nil, []string{"blocked_address"}},
		{"metadata", [][]netip.Addr{{a("169.254.169.254")}}, nil, nil, []string{"blocked_address"}},
		{"lookup error", [][]netip.Addr{nil}, nil, nil, []string{"resolve_failed"}},
		{"empty answer", [][]netip.Addr{{}}, nil, nil, []string{"resolve_failed"}},
		{"answer changes to loopback", [][]netip.Addr{{a("8.8.8.8")}, {a("127.0.0.1")}}, nil, nil, []string{"", "blocked_address"}},
		{"answer changes to public", [][]netip.Addr{{a("127.0.0.1")}, {a("8.8.8.8")}}, nil, nil, []string{"blocked_address", ""}},
		{"public inside a host network", [][]netip.Addr{{a("::ffff:192.175.48.1")}}, home, nil, []string{"blocked_address"}},
		{"public outside the host networks", [][]netip.Addr{{a("192.175.48.129")}}, home, nil, []string{""}},
		{"host networks unreadable", [][]netip.Addr{{a("8.8.8.8")}}, nil, errors.New("netlink"), []string{"blocked_address"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			upstream := must(net.Listen("tcp", "127.0.0.1:0"))
			defer upstream.Close()
			p, log, dialed := testProxy(t, "example.com:443", nil, upstream.Addr().String())
			var lookups int
			p.nets = func() ([]netip.Prefix, error) { return tc.nets, tc.netsErr }
			p.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
				answer := tc.answers[lookups]
				lookups++
				if answer == nil || host != "example.com." { // a rooted name: no DNS search suffix
					return nil, errors.New("lookup failed or name not rooted")
				}
				return answer, nil
			}
			wantDials := 0
			for i, want := range tc.reasons {
				conn, reason := p.connect("example.com", 443)
				if reason != want {
					t.Fatalf("connection %d: reason = %q, want %q", i+1, reason, want)
				}
				if conn != nil {
					_ = conn.Close()
					wantDials++
				}
			}
			if lookups != len(tc.reasons) {
				t.Fatalf("lookups = %d, want one per connection (%d)", lookups, len(tc.reasons))
			}
			log.mu.Lock()
			defer log.mu.Unlock()
			if len(*dialed) != wantDials {
				t.Fatalf("dialed %v, want %d dials", *dialed, wantDials)
			}
		})
	}
}
