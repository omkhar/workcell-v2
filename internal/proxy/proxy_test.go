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
	"encoding/json"
	"errors"
	"io"
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
		if got := blockedAddr(netip.MustParseAddr(text)); got != want {
			t.Errorf("blockedAddr(%s) = %v, want %v", text, got, want)
		}
	}
	if !blockedAddr(netip.Addr{}) {
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
	go func() {
		_, _ = client.Write(data)
		_ = client.Close()
	}()
	return server
}

func TestPeekSNI(t *testing.T) {
	t.Parallel()
	hello := clientHello(t, "api.example.com")
	conn := feed(hello)
	defer conn.Close()
	sni, read, ok := peekSNI(conn)
	if !ok || sni != "api.example.com" {
		t.Fatalf("peekSNI = (%q, ok=%v), want api.example.com", sni, ok)
	}
	if !bytes.Equal(read, hello) {
		t.Fatalf("peekSNI read %d bytes, want the %d-byte ClientHello", len(read), len(hello))
	}

	for name, data := range map[string][]byte{
		"empty":     nil,
		"plaintext": []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		"truncated": hello[:len(hello)/2],
		"no sni":    clientHello(t, ""),
	} {
		conn := feed(data)
		if sni, _, ok := peekSNI(conn); ok {
			t.Errorf("%s: peekSNI ok with sni %q, want failure", name, sni)
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

// testProxy returns a proxy whose resolver maps every host to addrs and whose
// dialer sends every dial to target, recording the address it was asked for.
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

// denyLine is a refusal as the tests compare it: the count of its (host, port, reason) so far and
// its number among the refusals.
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
	if _, reason := p.connect("example.com", 443); reason != "dial_failed" {
		t.Fatalf("reason = %q, want dial_failed", reason)
	}
	// Four addresses split the 30 s budget: the first attempt gets a quarter
	// of it, not the full 10 s, so the fourth address is still reachable.
	if len(timeouts) != 4 || timeouts[0] > connectBudget/4 || timeouts[0] < connectBudget/4-time.Second {
		t.Fatalf("dial timeouts = %v, want 4 attempts and a first share near %v", timeouts, connectBudget/4)
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
	if _, _, ok := peekSNI(feed(withExtension(t, hello, 0x0a0a))); !ok {
		t.Fatal("control hello with an unknown extension refused, want accepted")
	}
	if _, _, ok := peekSNI(feed(withExtension(t, hello, extECH))); ok {
		t.Fatal("ECH hello accepted, want refused")
	}
}

func TestConnectLooksUpRootedName(t *testing.T) {
	t.Parallel()
	p := New(&Allowlist{}, &recorder{})
	var looked string
	p.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		looked = host
		return nil, errors.New("stop")
	}
	p.connect("db", 5432)
	if looked != "db." {
		t.Fatalf("lookup host = %q, want %q", looked, "db.")
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
	a := netip.MustParseAddr
	cases := []struct {
		name    string
		answers [][]netip.Addr // one answer set per lookup; a nil set is a lookup error
		reasons []string
	}{
		{"public and private mixed", [][]netip.Addr{{a("8.8.8.8"), a("10.255.255.254")}}, []string{"blocked_address"}},
		{"private listed first", [][]netip.Addr{{a("10.255.255.254"), a("8.8.8.8")}}, []string{"blocked_address"}},
		{"mapped loopback", [][]netip.Addr{{a("::ffff:127.0.0.1")}}, []string{"blocked_address"}},
		{"unspecified", [][]netip.Addr{{a("0.0.0.0")}}, []string{"blocked_address"}},
		{"metadata", [][]netip.Addr{{a("169.254.169.254")}}, []string{"blocked_address"}},
		{"lookup error", [][]netip.Addr{nil}, []string{"resolve_failed"}},
		{"empty answer", [][]netip.Addr{{}}, []string{"resolve_failed"}},
		{"answer changes to loopback", [][]netip.Addr{{a("8.8.8.8")}, {a("127.0.0.1")}}, []string{"", "blocked_address"}},
		{"answer changes to public", [][]netip.Addr{{a("127.0.0.1")}, {a("8.8.8.8")}}, []string{"blocked_address", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			upstream := must(net.Listen("tcp", "127.0.0.1:0"))
			defer upstream.Close()
			p, log, dialed := testProxy(t, "example.com:443", nil, upstream.Addr().String())
			var lookups int
			p.lookup = func(context.Context, string) ([]netip.Addr, error) {
				answer := tc.answers[lookups]
				lookups++
				if answer == nil {
					return nil, errors.New("lookup failed")
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

// stalledLog is a Recorder that takes nothing until release is closed, as a log on a slow disk would, and then keeps each record in the wire
// form the audit log stores and `workcell verify` and the escape suite read: the JSON fields, port omitted when it is 0.
type stalledLog struct {
	release chan struct{}
	mu      sync.Mutex
	lines   []map[string]any
}

func (l *stalledLog) Note(r audit.Record) error {
	<-l.release
	var line map[string]any
	must(0, json.Unmarshal(must(json.Marshal(r)), &line))
	l.mu.Lock()
	l.lines = append(l.lines, line)
	l.mu.Unlock()
	return nil
}

// countingListener tells accepts of each call to Accept, which Serve makes only after it has queued or counted the connection before.
type countingListener struct {
	net.Listener
	accepts chan struct{}
}

func (l *countingListener) Accept() (net.Conn, error) {
	l.accepts <- struct{}{}
	return l.Listener.Accept()
}

// TestServeCountsRefusalsTheQueueDropped: at the connection limit every connection is shed and its
// refusal queued for the log, so that accept never waits for the disk; a refusal the full queue
// cannot take is counted, and the queue's reader writes the count as one overloaded line with
// port 0, so that the listed and the counted refusals together are every connection shed (I9).
func TestServeCountsRefusalsTheQueueDropped(t *testing.T) {
	t.Parallel()
	log := &stalledLog{release: make(chan struct{})}
	p := New(&Allowlist{}, log)
	for range cap(p.slots) {
		p.slots <- struct{}{} // the limit, without a thousand connections
	}
	shed := cap(p.shed) + 36 // more than the queue holds while the log is stalled
	ln := &countingListener{must(net.Listen("tcp", "127.0.0.1:0")), make(chan struct{}, shed+1)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = p.Serve(ln, 443) }()
	for i := range shed {
		c := must(net.Dial("tcp", ln.Addr().String()))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("connection %d at the limit: read = %v, want EOF without waiting for the log", i+1, err)
		}
		_ = c.Close()
	}
	for range shed + 1 {
		select {
		case <-ln.accepts:
		case <-time.After(5 * time.Second):
			t.Fatal("Serve did not come back to Accept after the shed connections")
		}
	}
	close(log.release)
	var listed, counted, counts int
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		log.mu.Lock()
		listed, counted, counts = 0, 0, 0
		for _, line := range log.lines {
			switch count, _ := line["count"].(float64); {
			case line["result"] != "overloaded":
				t.Fatalf("line %v, want only overloaded refusals", line)
			case line["port"] != nil:
				listed++
			case count == 0:
				t.Fatalf("line %v, want a count on a line with no port", line)
			default:
				counted, counts = counted+int(count), counts+1
			}
		}
		log.mu.Unlock()
		if listed+counted >= shed || time.Now().After(deadline) {
			break
		}
	}
	if listed+counted != shed || counts > listed {
		t.Fatalf("refusals logged: %d listed + %d counted on %d lines = %d, want the %d connections shed, with at most one count per listed refusal", listed, counted, counts, listed+counted, shed)
	}
}
