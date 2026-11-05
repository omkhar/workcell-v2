// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// The rebinding rows (I4). The policy allows one name, and the judge is the
// resolver the host side of the session asks about it (sandbox.Config
// .Resolver, at judgeResolver port 53 on the test host): it answers the
// allowed name with an address the host must never dial, the host's own
// loopback, a LAN address, the metadata address, in one spelling or
// another, with TTL 0, and refuses every other name. The guest connects to
// the allowed name as a program would, through its own resolver, by the
// forward port or by SNI at 443, and once more after the first attempt. A
// canary listens at the answer. The host must resolve the name itself (the
// judge sees the question; a host that never asked vetted nothing, which is
// an error, never a pass) and the canary must see nothing. What the guest
// says is detail. On control the guest resolves and dials for itself, with
// the judge as its resolver, so the canary sees it on every row.
//
// Missing, and said so in the report: the row where the first answer is an
// address the host may dial and the second is not, and the row where one
// answer set holds both. Each needs a global unicast address the test host
// owns, and every range set aside for that (RFC 5737, 2001:db8::/32,
// 3fff::/20) is one the host refuses; every other address is someone's.

// judgeResolver is where the judge's resolver listens, at port 53.
const judgeResolver = "127.5.3.53"

var (
	rebinding      = Want{Allow: []string{"allowed.escape.test:" + forwardPort}, Resolver: judgeResolver}
	rebindingSNI   = Want{Allow: []string{"allowed.escape.test"}, Resolver: judgeResolver}
	rebindingCNAME = Want{Allow: []string{"allowed.escape.test:" + forwardPort}, Deny: []string{"denied.escape.test"}, Resolver: judgeResolver}
)

// rebind is one row's answer and canary: the A and AAAA records the allowed
// name gets, owned by cname when that is set (the allowed name is then an
// alias of it), the address the canary listens at, and whether the guest
// offers TLS with the allowed name as SNI at 443 rather than a line at the
// forward port.
type rebind struct {
	a, aaaa []string
	cname   string
	canary  string
	sni     bool
	// names are the names answered with the records, as the resolver hears
	// them, with the trailing dot; allowedName alone when empty. A denied
	// name among them lets a session whose policy the guest widened reach
	// a canary under it (sandbox.Config.Deny).
	names []string
}

// answers says what the resolver tells about the allowed name.
func (r rebind) answers() string {
	var out []string
	if r.cname != "" {
		out = append(out, "CNAME "+r.cname)
	}
	for _, a := range r.a {
		out = append(out, "A "+a)
	}
	for _, a := range r.aaaa {
		out = append(out, "AAAA "+a)
	}
	return strings.Join(out, ", ")
}

// rebindProbe connects to the allowed name args[0] (name:port) as a program
// would, through the guest's own resolver, and sends the token args[1] on
// one line; with args[2] "sni" it offers a TLS ClientHello naming the host
// instead and, if the handshake completes, sends the token inside TLS as the
// path of a request for the host, since a host that terminates the
// connection resolves the name only to forward a request. It tries twice,
// the second time after a pause, and reports both.
func rebindProbe(args []string) Result {
	if len(args) != 3 {
		return Result{Status: "error", Detail: "want name:port, token and line|sni"}
	}
	first := connectName(args[0], args[1], args[2] == "sni")
	time.Sleep(300 * time.Millisecond)
	again := connectName(args[0], args[1], args[2] == "sni")
	again.Detail = fmt.Sprintf("first %s: %s; then %s", first.Status, first.Detail, again.Detail)
	return again
}

func connectName(addr, token string, sni bool) Result {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return dialFailed(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	line := token + "\n"
	if sni {
		tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // the probe is the attacker
		if err := tc.Handshake(); err != nil {
			return Result{Status: "handshake-failed", Detail: "to " + addr + ": " + err.Error()}
		}
		c, line = tc, fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", token, host)
	}
	if _, err := io.WriteString(c, line); err != nil {
		return Result{Status: "connected-write-failed", Detail: err.Error()}
	}
	return answered(c, "to "+addr)
}

// rebindJudge runs the judge's resolver and a canary at the row's address, has
// the guest connect to the allowed name, and holds the host to the answer:
// the canary must see nothing, and the resolver must have been asked.
func rebindJudge(r rebind) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		_, pc, err := bind(ctx, s, "udp4", net.JoinHostPort(judgeResolver, "53"))
		if err != nil {
			return false, "", fmt.Errorf("the judge's resolver: %w", err)
		}
		ns := serveNamesOn(pc, r)
		defer ns.stop()
		port, mode := forwardPort, "line"
		if r.sni {
			port, mode = "443", "sni"
		}
		t, err := listenTrap("tcp4", net.JoinHostPort(r.canary, port), s.Payload)
		if err != nil {
			return false, "", err
		}
		defer t.stop()
		want := newToken()
		res, err := s.Run(net.JoinHostPort(strings.TrimSuffix(allowedName, "."), port), want, mode)
		got := t.stop()
		asked := ns.stop()
		if err != nil {
			return false, "", err
		}
		told := fmt.Sprintf("the resolver was asked [%s] and says %s", strings.Join(asked, ", "), r.answers())
		pass, detail := verdict(got, lineToken, want, t.addr(), true, says(res))
		if !pass {
			return false, detail + "; " + told, nil
		}
		if len(asked) == 0 {
			return false, "", fmt.Errorf("nothing asked the judge's resolver for %s, so no address was vetted and nothing is proven (%s)", allowedName, says(res))
		}
		return true, detail + "; " + told, nil
	}
}

// nameServer is the judge as a resolver: one UDP socket, the row it answers
// for, and every question it was asked.
type nameServer struct {
	pc    net.PacketConn
	r     rebind
	mu    sync.Mutex
	asked []string
	done  bool
	wg    sync.WaitGroup
}

// serveNamesOn is the judge's resolver on pc, which is its from here.
func serveNamesOn(pc net.PacketConn, r rebind) *nameServer {
	ns := &nameServer{pc: pc, r: r}
	ns.wg.Go(ns.serve)
	return ns
}

func (ns *nameServer) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := ns.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q, ok := parseDNSQuery(buf[:n])
		if !ok {
			continue
		}
		ns.mu.Lock()
		ns.asked = append(ns.asked, typeNames[q.Type]+" "+q.Name)
		ns.mu.Unlock()
		ns.pc.WriteTo(ns.r.answer(q), from)
	}
}

// stop closes the resolver and returns every question it was asked.
func (ns *nameServer) stop() []string {
	ns.mu.Lock()
	done := ns.done
	ns.done = true
	ns.mu.Unlock()
	if !done {
		ns.pc.Close()
	}
	ns.wg.Wait()
	return ns.asked
}

// questions is a copy of what the resolver has been asked so far.
func (ns *nameServer) questions() []string {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return slices.Clone(ns.asked)
}

// typeNames names the types a resolver is asked, for the record of it.
var typeNames = map[uint16]string{dnsTypeA: "A", dnsTypeAAAA: "AAAA", dnsTypeCNAME: "CNAME", dnsTypeTXT: "TXT", dnsTypePTR: "PTR", dnsTypeANY: "ANY"}

// answer is the response to q: for a name of the row's, the CNAME when the
// row has one and then the row's records of the type asked, NOERROR with no
// record when it has none of that type; REFUSED for every other name.
func (r rebind) answer(q dnsQuestion) []byte {
	names := r.names
	if len(names) == 0 {
		names = []string{allowedName}
	}
	if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(q.Name, n) }) {
		return dnsResponse(q, dnsRcodeRefused, nil)
	}
	owner := q.Name
	var rrs []dnsRecord
	if r.cname != "" {
		rrs = append(rrs, dnsRecord{Name: owner, Type: dnsTypeCNAME, Data: encodeName(r.cname)})
		owner = r.cname
	}
	switch q.Type {
	case dnsTypeA:
		for _, a := range r.a {
			rrs = append(rrs, dnsRecord{Name: owner, Type: dnsTypeA, Data: net.ParseIP(a).To4()})
		}
	case dnsTypeAAAA:
		for _, a := range r.aaaa {
			rrs = append(rrs, dnsRecord{Name: owner, Type: dnsTypeAAAA, Data: net.ParseIP(a).To16()})
		}
	}
	return dnsResponse(q, 0, rrs)
}

// dnsRecord is one answer record: owner name, type and data, class IN.
type dnsRecord struct {
	Name string
	Type uint16
	Data []byte
}

// dnsResponse encodes the response to q: its id, QR, RD and RA set, the
// rcode, the question again and the records, each with TTL 0, so that
// nothing may cache what the judge said and every connection asks again.
func dnsResponse(q dnsQuestion, rcode uint16, rrs []dnsRecord) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], q.ID)
	b[2], b[3] = 0x81, 0x80|byte(rcode&0x0F)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], uint16(len(rrs)))
	b = append(b, encodeName(q.Name)...)
	b = binary.BigEndian.AppendUint16(b, q.Type)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	for _, rr := range rrs {
		b = append(b, encodeName(rr.Name)...)
		b = binary.BigEndian.AppendUint16(b, rr.Type)
		b = binary.BigEndian.AppendUint16(b, dnsClassIN)
		b = binary.BigEndian.AppendUint32(b, 0)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rr.Data)))
		b = append(b, rr.Data...)
	}
	return b
}
