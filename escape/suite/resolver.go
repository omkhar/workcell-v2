// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The resolver tests (I3) ask the resolver named in the guest's
// /etc/resolv.conf what it does with a name: an allowed name must come back
// with an address, and every other name must be refused, promptly, with a DNS
// answer that carries no address. A resolver that answers nothing passes the
// leak tests above and fails here: the invariant says the host resolver
// answers. The probe speaks the wire format itself (dns.go), so nothing in
// the guest's libc stands between it and the resolver; a response that never
// came is a failure too. The control sandbox (SPEC T2) names a naive resolver
// that answers every name, so every row here fails there.

// A lookup is one question a judge has the guest ask, and what the
// invariant demands of the answer: "addr", an address; "refused", a DNS
// answer with no address (REFUSED, NXDOMAIN, or NOERROR and no record), or
// "answered", any DNS answer at all. Each must come within fast.
type lookup struct {
	label, spec, want string
}

// The spec a judge hands the probe for one question: "type:name", where
// type is A, AAAA, TXT, PTR or ANY, "+edns" after it adds an OPT record,
// and TOKEN in the name stands for the run's token.
const (
	fast        = 2 * time.Second             // a refusal or an answer must come within this
	lookupWait  = fast + 500*time.Millisecond // the probe's deadline, past fast so that slow is told from silent
	garbageWait = 500 * time.Millisecond      // how long a hostile datagram is given to get an answer
	burstSize   = 200
	resolvConf  = "resolv.conf" // the target that means the guest's own configured resolver
	allowedName = "allowed.escape.test."
	deniedName  = "denied.escape.test."
)

// The lookups the rows ask. The allowed name must resolve however it is
// spelled; every other name, every other type for it, and the allowed name
// under a policy that allows nothing must be refused. The allowed row asks
// one denied name too: a resolver that answers everything, the control
// sandbox's, is then no pass (SPEC T2), and "only for allowed names" is
// shown on the one resolver that answered.
var (
	allowedLookups = []lookup{
		{"a", "A:" + allowedName, "addr"},
		{"u", "A:" + strings.ToUpper(allowedName), "addr"},
		{"m", "A:aLlOwEd.EsCaPe.TeSt.", "addr"},
		{"e", "A+edns:" + allowedName, "addr"},
		{"q", "AAAA:" + allowedName, "answered"},
		{"t", "TXT:" + allowedName, "answered"},
		{"d", "A:" + deniedName, "refused"},
	}
	deniedLookups = []lookup{
		{"d", "A:" + deniedName, "refused"},
		{"i", "A:TOKEN.invalid.", "refused"},
		{"s", "A:sub." + allowedName, "refused"},
		{"p", "A:evil" + allowedName, "refused"},
		{"x", "A:" + allowedName + "TOKEN.invalid.", "refused"},
		{"6", "AAAA:" + deniedName, "refused"},
		{"t", "TXT:" + deniedName, "refused"},
		{"y", "ANY:" + deniedName, "refused"},
		{"r", "PTR:1.0.0.127.in-addr.arpa.", "refused"},
		{"e", "A+edns:" + deniedName, "refused"},
	}
	bothLookups    = []lookup{allowedLookups[0], deniedLookups[0], deniedLookups[1]}
	nothingLookups = []lookup{{"a", "A:" + allowedName, "refused"}, {"d", "A:" + deniedName, "refused"}}
)

// reachable is the sandbox the resolver rows want: one allowed name and one
// denied, both of which the host resolver is to know of.
var reachable = Want{Allow: []string{"allowed.escape.test"}, Deny: []string{"denied.escape.test"}}

var queryTypes = map[string]uint16{"A": dnsTypeA, "AAAA": dnsTypeAAAA, "TXT": dnsTypeTXT, "PTR": dnsTypePTR, "ANY": dnsTypeANY}

// resolverAddr turns the target the judge named into an address: the first
// nameserver of the guest's /etc/resolv.conf at port 53, or a literal.
func resolverAddr(target string) (string, error) {
	if target != resolvConf {
		return target, nil
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return firstNameserver(f)
}

// firstNameserver reads a resolv.conf and returns its first nameserver as
// an address at port 53.
func firstNameserver(r io.Reader) (string, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil {
				return net.JoinHostPort(f[1], "53"), nil
			}
		}
	}
	return "", errors.New("resolv.conf names no resolver")
}

// encode builds the query for a spec, with a fresh id.
func encode(spec, token string) ([]byte, uint16, error) {
	typ, name, ok := strings.Cut(spec, ":")
	if !ok {
		return nil, 0, fmt.Errorf("spec %q is not type:name", spec)
	}
	typ, edns := strings.CutSuffix(typ, "+edns")
	t, ok := queryTypes[typ]
	if !ok {
		return nil, 0, fmt.Errorf("spec %q has an unknown type", spec)
	}
	var id [2]byte
	rand.Read(id[:])
	q := dnsQuestion{ID: binary.BigEndian.Uint16(id[:]), Name: strings.ReplaceAll(name, "TOKEN", token), Type: t}
	msg := dnsQuery(q)
	if edns {
		msg = withEDNS0(msg)
	}
	return msg, q.ID, nil
}

// ask sends one query to addr and says what came back and how soon:
// "addr:<ip>", "answered:<n>" (records, none an address), "nodata", an
// rcode's name, "garbled" (a reply that is not one, or not to this id),
// "unreachable" (the kernel's own refusal) or "timeout".
func ask(addr string, msg []byte, id uint16, wait time.Duration) (string, time.Duration) {
	start := time.Now()
	c, err := net.DialTimeout("udp", addr, wait)
	if err != nil {
		return "unreachable", time.Since(start)
	}
	defer c.Close()
	c.SetDeadline(start.Add(wait))
	if _, err := c.Write(msg); err != nil {
		return "unreachable", time.Since(start)
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		took := time.Since(start)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return "timeout", took
			}
			return "unreachable", took
		}
		r, ok := parseDNSReply(buf[:n])
		if !ok || r.ID != id {
			continue // not this query's answer: wait for one that is
		}
		return outcome(r), took
	}
}

func outcome(r dnsReply) string {
	if r.Rcode != 0 {
		if name, ok := rcodeNames[r.Rcode]; ok {
			return name
		}
		return "rcode" + strconv.Itoa(int(r.Rcode))
	}
	if a := r.addresses(); len(a) > 0 {
		return "addr:" + a[0]
	}
	if len(r.Answers) > 0 {
		return "answered:" + strconv.Itoa(len(r.Answers))
	}
	return "nodata"
}

// lookupProbe asks the resolver args[0] names, every "label=spec" in
// args[3:], all at once, and reports "label=outcome/ms" for each. args[1]
// is the token. First, as args[2] says, it sends nothing ("plain"), the
// hostile datagrams of garbage ("garbage"), each given garbageWait for an
// answer (the host must survive them, I12, and answer and refuse as
// before), or a burst of burstSize queries from one socket ("burst"),
// counting what came back within lookupWait; the burst is reported as one
// more field, "burst=sent/answered/refused/ms". Every question goes at once
// so that the run stays short when the resolver answers nothing.
func lookupProbe(args []string) Result {
	if len(args) < 4 {
		return Result{Status: "error", Detail: "want target, token, plain|garbage|burst and label=spec..."}
	}
	addr, err := resolverAddr(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	var first string
	switch args[2] {
	case "plain":
	case "garbage":
		replied, all := 0, garbage(args[1])
		for _, g := range all {
			if poke(addr, g) {
				replied++
			}
		}
		first = fmt.Sprintf("garbage=%d/%d ", replied, len(all))
	case "burst":
		first = "burst=" + burst(addr, args[1]) + " "
	default:
		return Result{Status: "error", Detail: "want plain, garbage or burst, not " + args[2]}
	}
	out := make([]string, len(args)-3)
	var wg sync.WaitGroup
	for i, s := range args[3:] {
		label, spec, ok := strings.Cut(s, "=")
		if !ok {
			return Result{Status: "error", Detail: fmt.Sprintf("%q is not label=spec", s)}
		}
		msg, id, err := encode(spec, args[1])
		if err != nil {
			return Result{Status: "error", Detail: err.Error()}
		}
		wg.Go(func() {
			got, took := ask(addr, msg, id, lookupWait)
			out[i] = fmt.Sprintf("%s=%s/%dms", label, got, took.Milliseconds())
		})
	}
	wg.Wait()
	return Result{Status: "asked", Detail: addr + " " + first + strings.Join(out, " ")}
}

// burst sends burstSize queries for distinct names under token.invalid to
// addr from one socket, as fast as it can, and tallies "sent/answered/
// refused/ms": how many went, how many got any answer within lookupWait,
// and how many of those were refusals.
func burst(addr, token string) string {
	c, err := net.DialTimeout("udp", addr, lookupWait)
	if err != nil {
		return "0/0/0/0ms"
	}
	defer c.Close()
	start := time.Now()
	c.SetDeadline(start.Add(lookupWait))
	sent := 0
	for i := range burstSize {
		if _, err := c.Write(dnsQuery(dnsQuestion{ID: uint16(i), Name: fmt.Sprintf("b%d.%s.invalid.", i, token), Type: dnsTypeA})); err != nil {
			break
		}
		sent++
	}
	seen := map[uint16]string{}
	buf := make([]byte, 65535)
	for len(seen) < sent {
		n, err := c.Read(buf)
		if err != nil {
			break
		}
		if r, ok := parseDNSReply(buf[:n]); ok && int(r.ID) < sent {
			seen[r.ID] = outcome(r)
		}
	}
	refused := 0
	for _, o := range seen {
		if o == "refused" || o == "nxdomain" || o == "nodata" {
			refused++
		}
	}
	return fmt.Sprintf("%d/%d/%d/%dms", sent, len(seen), refused, time.Since(start).Milliseconds())
}

// poke sends one hostile datagram and says whether anything came back
// within garbageWait. What came is not judged: silence and FORMERR are both
// fine; only the lookups after it count.
func poke(addr string, g []byte) bool {
	c, err := net.DialTimeout("udp", addr, garbageWait)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(garbageWait))
	if _, err := c.Write(g); err != nil {
		return false
	}
	n, err := c.Read(make([]byte, 65535))
	return err == nil && n > 0
}

// garbage is the hostile datagrams: a lone byte, a header that promises a
// question and brings none, a name that points at itself, a label past the
// limit, a question count of 65535 for one question, a query with the
// response bit set, and 65000 bytes of noise behind a valid header.
func garbage(token string) [][]byte {
	hdr := func(qd uint16) []byte {
		b := make([]byte, 12)
		b[0], b[1], b[2] = 0x55, 0xAA, 0x01
		binary.BigEndian.PutUint16(b[4:], qd)
		return b
	}
	loop := append(hdr(1), 0xC0, 12, 0, 1, 0, 1)
	long := append(hdr(1), 70)
	long = append(long, strings.Repeat("x", 70)...)
	long = append(long, 0, 0, 1, 0, 1)
	many := dnsQuery(dnsQuestion{ID: 0x55AA, Name: token + ".invalid.", Type: dnsTypeA})
	binary.BigEndian.PutUint16(many[4:], 65535)
	response := dnsQuery(dnsQuestion{ID: 0x55AA, Name: allowedName, Type: dnsTypeA})
	response[2] |= 0x80
	noise := make([]byte, 65000)
	rand.Read(noise)
	copy(noise, hdr(1))
	return [][]byte{{0x55}, hdr(1), loop, long, many, response, noise}
}

// resolverJudge has the guest ask target, resolvConf or a literal address
// with hostAddr in it, the lookups, after what first names (plain, garbage
// or burst, see lookupProbe), and holds every answer to what the lookup
// wants, the burst's tally too. The invariant holds only if all of them do.
func resolverJudge(target, first string, qs []lookup) Judge {
	if first == "burst" {
		qs = append([]lookup{{"burst", "a burst of " + strconv.Itoa(burstSize) + " queries", "burst"}}, qs...)
	}
	return func(ctx context.Context, s Session) (bool, string, error) {
		target, err := resolve(target)
		if err != nil {
			return false, "", err
		}
		args := []string{target, newToken(), first}
		for _, q := range qs {
			if q.want != "burst" {
				args = append(args, q.label+"="+q.spec)
			}
		}
		r, err := s.Run(args...)
		if err != nil {
			return false, "", err
		}
		got := fields(r.Detail)
		var bad []string
		for _, q := range qs {
			if why := q.judge(got[q.label]); why != "" {
				bad = append(bad, why)
			}
		}
		if len(bad) > 0 {
			return false, fmt.Sprintf("%s (%s)", strings.Join(bad, "; "), says(r)), nil
		}
		return true, "every answer was as the policy demands (" + says(r) + ")", nil
	}
}

// judge says what is wrong with an outcome, "" when nothing is.
func (q lookup) judge(got string) string {
	if got == "" {
		return fmt.Sprintf("no outcome for %s", q.spec)
	}
	if q.want == "burst" { // every query of the burst must have been answered, with a refusal
		var sent, answered, refused, ms int
		if n, _ := fmt.Sscanf(got, "%d/%d/%d/%dms", &sent, &answered, &refused, &ms); n != 4 || sent < burstSize || answered < sent || refused < sent {
			return fmt.Sprintf("of %s, %d were sent, %d answered and %d refused; every one must be refused", q.spec, sent, answered, refused)
		}
		return ""
	}
	what, ms, _ := strings.Cut(got, "/")
	took, _ := strconv.Atoi(strings.TrimSuffix(ms, "ms"))
	switch q.want {
	case "addr":
		if !strings.HasPrefix(what, "addr:") {
			return fmt.Sprintf("%s got %s, not an address", q.spec, what)
		}
	case "refused":
		if strings.HasPrefix(what, "addr:") {
			return fmt.Sprintf("%s, which no policy allows, got %s", q.spec, what)
		}
		if what != "refused" && what != "nxdomain" && what != "nodata" {
			return fmt.Sprintf("%s, which no policy allows, got %s, not a refusal", q.spec, what)
		}
	case "answered":
		switch what {
		case "timeout", "unreachable", "garbled":
			return fmt.Sprintf("%s got %s, not an answer", q.spec, what)
		}
	}
	if time.Duration(took)*time.Millisecond > fast {
		return fmt.Sprintf("%s got %s only after %s, past %s", q.spec, what, ms, fast)
	}
	return ""
}
