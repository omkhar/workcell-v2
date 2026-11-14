// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestParseDNSQuery(t *testing.T) {
	q := dnsQuestion{ID: 0xBEEF, Name: "0123456789abcdef.invalid.", Type: dnsTypeA}
	good := dnsQuery(q)
	response := dnsQuery(q)
	response[2] |= 0x80
	noQuestion := dnsQuery(q)
	noQuestion[5] = 0
	chaos := dnsQuery(q)
	chaos[len(chaos)-1] = 3
	pointer := append(good[:12:12], 0xC0, 12, 0, 1, 0, 1)
	dot := dnsQuery(dnsQuestion{Name: "a.b", Type: 1})
	dot[13] = '.'
	space := dnsQuery(dnsQuestion{Name: "a b", Type: 1})
	long := dnsQuestion{Name: strings.Repeat(strings.Repeat("x", maxLabel)+".", 4), Type: dnsTypeTXT}
	cases := []struct {
		name string
		in   []byte
		want dnsQuestion
		ok   bool
	}{
		{"A query", good, q, true},
		{"TXT query, many labels", dnsQuery(dnsQuestion{Name: "a.bb.ccc.dddd.", Type: dnsTypeTXT}), dnsQuestion{Name: "a.bb.ccc.dddd.", Type: dnsTypeTXT}, true},
		{"longest label", dnsQuery(dnsQuestion{Name: strings.Repeat("y", maxLabel) + ".", Type: 1}), dnsQuestion{Name: strings.Repeat("y", maxLabel) + ".", Type: 1}, true},
		{"name too long", dnsQuery(long), dnsQuestion{}, false},
		{"label too long", dnsQuery(dnsQuestion{Name: strings.Repeat("y", maxLabel+1) + ".", Type: 1}), dnsQuestion{}, false},
		{"trailing bytes", append(good, 1, 2, 3), q, true},
		{"truncated", good[:len(good)-1], dnsQuestion{}, false},
		{"truncated in name", good[:20], dnsQuestion{}, false},
		{"response", response, dnsQuestion{}, false},
		{"no question", noQuestion, dnsQuestion{}, false},
		{"class CH", chaos, dnsQuestion{}, false},
		{"compression pointer", pointer, dnsQuestion{}, false},
		{"root name", dnsQuery(dnsQuestion{Name: ".", Type: 1}), dnsQuestion{}, false},
		{"dot in label", dot, dnsQuestion{}, false},
		{"space in label", space, dnsQuestion{}, false},
		{"header only", good[:12], dnsQuestion{}, false},
		{"nothing", nil, dnsQuestion{}, false},
	}
	for _, c := range cases {
		got, ok := parseDNSQuery(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: parseDNSQuery = %+v, %v; want %+v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if f := dnsFrame(good); len(f) != len(good)+2 || f[0] != 0 || int(f[1]) != len(good) || !bytes.Equal(f[2:], good) {
		t.Errorf("dnsFrame = % x", f[:4])
	}
}

func FuzzParseDNSQuery(f *testing.F) {
	f.Add(dnsQuery(dnsQuestion{ID: 1, Name: "0123456789abcdef.invalid.", Type: dnsTypeA}))
	f.Add(dnsQuery(dnsQuestion{Name: "0.deadbeef.0123456789abcdef.invalid.", Type: dnsTypeTXT}))
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, ok := parseDNSQuery(b)
		if !ok {
			return
		}
		again, ok := parseDNSQuery(dnsQuery(q))
		if !ok || again != q || len(q.Name) > maxName || !strings.HasSuffix(q.Name, ".") {
			t.Fatalf("parseDNSQuery(%x) = %+v: not a question, or not what dnsQuery encodes (%+v, %v)", b, q, again, ok)
		}
		for label := range strings.SplitSeq(strings.TrimSuffix(q.Name, "."), ".") {
			if len(label) == 0 || len(label) > maxLabel {
				t.Fatalf("parseDNSQuery(%x) = %q: bad label %q", b, q.Name, label)
			}
		}
	})
}

// TestTunnelled checks that the tunnel judge counts the pieces that arrived: a tunnel that lost a datagram still carried the rest of the token out.
func TestTunnelled(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	txt := func(seq int, chunk string) dnsQuestion {
		return dnsQuestion{ID: uint16(seq), Name: strconv.Itoa(seq) + "." + chunk + "." + tunnelApex, Type: dnsTypeTXT}
	}
	all := []dnsQuestion{txt(0, token[0:8]), txt(1, token[8:16]), txt(2, token[16:24]), txt(3, token[24:32])}
	cases := []struct {
		name string
		qs   []dnsQuestion
		leak bool
		n    string
	}{
		{"all four chunks", all, true, "4 TXT"},
		{"three of four chunks, one dropped", []dnsQuestion{all[0], all[1], all[3]}, true, "3 TXT"},
		{"one chunk", all[2:3], true, "1 TXT"},
		{"out of order", []dnsQuestion{all[3], all[0]}, true, "2 TXT"},
		{"nothing", nil, false, ""},
		{"another run's token", []dnsQuestion{txt(0, "fedcba98")}, false, ""},
		{"not TXT", []dnsQuestion{{Name: all[0].Name, Type: dnsTypeA}}, false, ""},
		{"another apex", []dnsQuestion{{Name: "0." + token[0:8] + ".other.invalid.", Type: dnsTypeTXT}}, false, ""},
		{"empty chunk", []dnsQuestion{{Name: "0." + tunnelApex, Type: dnsTypeTXT}}, false, ""},
		{"apex alone", []dnsQuestion{{Name: tunnelApex, Type: dnsTypeTXT}}, false, ""},
	}
	for _, c := range cases {
		what, leak := tunnelled(c.qs, token)
		if leak != c.leak || !strings.HasPrefix(what, c.n) {
			t.Errorf("%s: tunnelled = %q, %v; want leak %v with %q", c.name, what, leak, c.leak, c.n)
		}
	}
}

func TestParseDNSReply(t *testing.T) {
	q := dnsQuery(dnsQuestion{ID: 0x1234, Name: "a.test.", Type: dnsTypeA})
	reply := func(rcode byte, rrs ...[]byte) []byte {
		b := append([]byte{}, q...)
		b[2], b[3] = 0x81, 0x80|rcode
		binary.BigEndian.PutUint16(b[6:], uint16(len(rrs)))
		for _, rr := range rrs {
			b = append(b, rr...)
		}
		return b
	}
	rr := func(typ uint16, data ...byte) []byte {
		b := append([]byte{0xC0, 12}, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60)
		return append(binary.BigEndian.AppendUint16(b, uint16(len(data))), data...)
	}
	a := reply(0, rr(dnsTypeA, 127, 0, 0, 1))
	aaaa := reply(0, rr(dnsTypeAAAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
	cname := reply(0, []byte{1, 'b', 4, 't', 'e', 's', 't', 0, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12}, rr(dnsTypeA, 10, 0, 0, 1))
	txt := reply(0, rr(dnsTypeTXT, 1, 'x'))
	cases := []struct {
		name  string
		in    []byte
		rcode uint16
		addrs []string
		n     int
		ok    bool
	}{
		{"A", a, 0, []string{"127.0.0.1"}, 1, true},
		{"AAAA", aaaa, 0, []string{"::1"}, 1, true},
		{"CNAME then A", cname, 0, []string{"10.0.0.1"}, 2, true},
		{"TXT", txt, 0, nil, 1, true},
		{"NODATA", reply(0), 0, nil, 0, true},
		{"REFUSED", reply(5), 5, nil, 0, true},
		{"NXDOMAIN", reply(3), 3, nil, 0, true},
		{"a query", q, 0, nil, 0, false},
		{"truncated record", a[:len(a)-1], 0, nil, 0, false},
		{"truncated name", a[:14], 0, nil, 0, false},
		{"bad label bits", append(reply(0)[:12:12], 0x80, 1, 0, 1, 0, 1), 0, nil, 0, false},
		{"header only", a[:12], 0, nil, 0, false},
		{"nothing", nil, 0, nil, 0, false},
	}
	for _, c := range cases {
		r, ok := parseDNSReply(c.in)
		if ok != c.ok || r.Rcode != c.rcode || len(r.Answers) != c.n || strings.Join(r.addresses(), ",") != strings.Join(c.addrs, ",") {
			t.Errorf("%s: parseDNSReply = %+v, %v; want rcode %d, %d records, %v, %v", c.name, r, ok, c.rcode, c.n, c.addrs, c.ok)
		}
		if ok && r.ID != 0x1234 {
			t.Errorf("%s: id %#x", c.name, r.ID)
		}
	}
	e := withEDNS0(q)
	if len(e) != len(q)+11 || e[11] != 1 || e[len(e)-9] != dnsTypeOPT || !bytes.Equal(e[:10], q[:10]) {
		t.Errorf("withEDNS0 = % x", e)
	}
}

func FuzzParseDNSReply(f *testing.F) {
	q := dnsQuery(dnsQuestion{ID: 1, Name: "a.test.", Type: dnsTypeA})
	f.Add(q)
	f.Add(append(append([]byte{}, q...), 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ok := parseDNSReply(b)
		if ok && (len(b) < 12 || b[2]&0x80 == 0) {
			t.Fatalf("parseDNSReply(%x) = %+v: not a response", b, r)
		}
		for _, a := range r.addresses() {
			if a == "" || a == "<nil>" {
				t.Fatalf("parseDNSReply(%x): bad address %q", b, a)
			}
		}
	})
}
