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

// The resolver tests (I3) ask the resolver the guest was configured with,
// the one named in its /etc/resolv.conf, what it does with a name: an
// allowed name must come back with an address, and every other name must be
// refused, promptly, with a DNS answer that carries no address. A resolver
// that answers nothing at all, so that every lookup times out, passes the
// leak tests above and fails here: the invariant says the host resolver
// answers. The probe speaks the wire format itself (dns.go) so that nothing
// in the guest's libc stands between it and the resolver; what the resolver
// said is the evidence, and a response that never came is a failure too.
//
// The control sandbox (SPEC T2) gives its guest a resolv.conf naming a naive
// resolver that answers every name, as an open resolver would; every row
// here fails there because a name no policy allows gets an address.

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
// args[2:], all at once, and reports "label=outcome/ms" for each. args[1]
// is the token. Every question goes at once so that the run stays short
// when the resolver answers nothing.
func lookupProbe(args []string) Result {
	if len(args) < 3 {
		return Result{Status: "error", Detail: "want target, token and label=spec..."}
	}
	addr, err := resolverAddr(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	out, err := lookups(addr, args[1], args[2:])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	return Result{Status: "asked", Detail: addr + " " + out}
}

// lookups runs every "label=spec" against addr concurrently and returns
// "label=outcome/ms" for each, in order.
func lookups(addr, token string, specs []string) (string, error) {
	out := make([]string, len(specs))
	var wg sync.WaitGroup
	for i, s := range specs {
		label, spec, ok := strings.Cut(s, "=")
		if !ok {
			return "", fmt.Errorf("%q is not label=spec", s)
		}
		msg, id, err := encode(spec, token)
		if err != nil {
			return "", err
		}
		wg.Go(func() {
			got, took := ask(addr, msg, id, lookupWait)
			out[i] = fmt.Sprintf("%s=%s/%dms", label, got, took.Milliseconds())
		})
	}
	wg.Wait()
	return strings.Join(out, " "), nil
}

// burstProbe sends burstSize queries for distinct names under TOKEN.invalid
// to args[0] from one socket, as fast as it can, counts what came back for
// each within lookupWait, and then asks the lookups in args[2:] as
// lookupProbe does: the resolver must still be there after the burst.
func burstProbe(args []string) Result {
	if len(args) < 3 {
		return Result{Status: "error", Detail: "want target, token and label=spec..."}
	}
	addr, err := resolverAddr(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	c, err := net.DialTimeout("udp", addr, lookupWait)
	if err != nil {
		return Result{Status: "error", Detail: "burst: " + err.Error()}
	}
	defer c.Close()
	start := time.Now()
	c.SetDeadline(start.Add(lookupWait))
	sent := 0
	for i := range burstSize {
		msg := dnsQuery(dnsQuestion{ID: uint16(i), Name: fmt.Sprintf("b%d.%s.invalid.", i, args[1]), Type: dnsTypeA})
		if _, err := c.Write(msg); err != nil {
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
	took := time.Since(start)
	tally := map[string]int{}
	for _, o := range seen {
		tally[o]++
	}
	var parts []string
	for _, k := range []string{"refused", "nxdomain", "nodata"} {
		if tally[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", k, tally[k]))
			delete(tally, k)
		}
	}
	for k, n := range tally {
		parts = append(parts, fmt.Sprintf("%s:%d", k, n))
	}
	after, err := lookups(addr, args[1], args[2:])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	return Result{Status: "asked", Detail: fmt.Sprintf("burst sent=%d got=%d %s in %dms; then %s", sent, len(seen), strings.Join(parts, ","), took.Milliseconds(), after)}
}

// garbageProbe sends the resolver datagrams no decoder should take, one at
// a time, each given garbageWait for an answer, and then asks the lookups in
// args[2:] as lookupProbe does. The host must survive the garbage (I12) and
// still answer and refuse as before.
func garbageProbe(args []string) Result {
	if len(args) < 3 {
		return Result{Status: "error", Detail: "want target, token and label=spec..."}
	}
	addr, err := resolverAddr(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	all := garbage(args[1])
	replied := 0
	for _, g := range all {
		if poke(addr, g) {
			replied++
		}
	}
	after, err := lookups(addr, args[1], args[2:])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	return Result{Status: "asked", Detail: fmt.Sprintf("%d of %d hostile datagrams got an answer; then %s", replied, len(all), after)}
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
// with hostAddr in it, the lookups, and holds every answer to what the
// lookup wants. The invariant holds only if all of them do.
func resolverJudge(target string, qs []lookup) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		target, err := resolve(target)
		if err != nil {
			return false, "", err
		}
		args := []string{target, newToken()}
		for _, q := range qs {
			args = append(args, q.label+"="+q.spec)
		}
		r, err := s.Run(args...)
		if err != nil {
			return false, "", err
		}
		got := map[string]string{}
		for _, f := range strings.Fields(r.Detail) {
			if label, rest, ok := strings.Cut(f, "="); ok {
				got[label] = rest
			}
		}
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
	what, ms, _ := strings.Cut(got, "/")
	if got == "" {
		return fmt.Sprintf("no outcome for %s", q.spec)
	}
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

// burstJudge has the guest send the burst and then the lookups: every query
// of the burst must get a refusal, and the lookups after must still hold.
func burstJudge(qs []lookup) Judge {
	inner := resolverJudge(resolvConf, qs)
	return func(ctx context.Context, s Session) (bool, string, error) {
		pass, detail, err := inner(ctx, s)
		if err != nil || !pass {
			return pass, detail, err
		}
		// The burst's own tally: "burst sent=N got=M refused:K,...".
		var sent, got, refused int
		for _, f := range strings.Fields(detail) {
			k, v, _ := strings.Cut(f, "=")
			switch k {
			case "sent":
				sent, _ = strconv.Atoi(v)
			case "got":
				got, _ = strconv.Atoi(v)
			}
			for _, kv := range strings.Split(f, ",") {
				if k, v, ok := strings.Cut(kv, ":"); ok && (k == "refused" || k == "nxdomain" || k == "nodata") {
					n, _ := strconv.Atoi(v)
					refused += n
				}
			}
		}
		if sent < burstSize || got < sent || refused < sent {
			return false, fmt.Sprintf("of %d queries in a burst, %d were answered and %d refused; every one must be refused (%s)", sent, got, refused, detail), nil
		}
		return true, detail, nil
	}
}
