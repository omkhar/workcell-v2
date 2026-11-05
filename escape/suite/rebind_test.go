// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"slices"
	"testing"
)

// TestRebindAnswer checks what the judge's resolver says, read back with
// the suite's own reply parser: the allowed name gets the row's records of
// the type asked, however the name is spelled, a CNAME first when the row
// has one, nothing of a type it lacks, and every other name is refused.
func TestRebindAnswer(t *testing.T) {
	loop := rebind{a: []string{"127.0.0.1"}}
	both := rebind{a: []string{"10.255.255.254", "169.254.169.254"}, aaaa: []string{"::ffff:127.0.0.1"}}
	alias := rebind{cname: deniedName, a: []string{"127.0.0.1"}}
	cases := []struct {
		name    string
		r       rebind
		q       dnsQuestion
		rcode   uint16
		answers int
		addrs   []string
	}{
		{"A", loop, dnsQuestion{ID: 7, Name: allowedName, Type: dnsTypeA}, 0, 1, []string{"127.0.0.1"}},
		{"A, upper case", loop, dnsQuestion{ID: 8, Name: "ALLOWED.ESCAPE.TEST.", Type: dnsTypeA}, 0, 1, []string{"127.0.0.1"}},
		{"AAAA, none", loop, dnsQuestion{Name: allowedName, Type: dnsTypeAAAA}, 0, 0, nil},
		{"TXT, none", loop, dnsQuestion{Name: allowedName, Type: dnsTypeTXT}, 0, 0, nil},
		{"two A", both, dnsQuestion{Name: allowedName, Type: dnsTypeA}, 0, 2, []string{"10.255.255.254", "169.254.169.254"}},
		{"AAAA mapped", both, dnsQuestion{Name: allowedName, Type: dnsTypeAAAA}, 0, 1, []string{"127.0.0.1"}},
		{"CNAME then A", alias, dnsQuestion{Name: allowedName, Type: dnsTypeA}, 0, 2, []string{"127.0.0.1"}},
		{"CNAME, no AAAA", alias, dnsQuestion{Name: allowedName, Type: dnsTypeAAAA}, 0, 1, nil},
		{"other name", loop, dnsQuestion{ID: 9, Name: deniedName, Type: dnsTypeA}, dnsRcodeRefused, 0, nil},
		{"subdomain", loop, dnsQuestion{Name: "sub." + allowedName, Type: dnsTypeA}, dnsRcodeRefused, 0, nil},
		{"the alias target", alias, dnsQuestion{Name: deniedName, Type: dnsTypeA}, dnsRcodeRefused, 0, nil},
	}
	for _, c := range cases {
		got, ok := parseDNSReply(c.r.answer(c.q))
		if !ok {
			t.Errorf("%s: the answer does not parse", c.name)
			continue
		}
		if got.ID != c.q.ID || got.Rcode != c.rcode || len(got.Answers) != c.answers || !slices.Equal(got.addresses(), c.addrs) {
			t.Errorf("%s: id %d rcode %d, %d answers, addresses %v; want id %d rcode %d, %d answers, %v", c.name, got.ID, got.Rcode, len(got.Answers), got.addresses(), c.q.ID, c.rcode, c.answers, c.addrs)
		}
		if c.r.cname != "" && c.answers > 0 && (got.Answers[0].Type != dnsTypeCNAME || string(got.Answers[0].Data) != string(encodeName(c.r.cname))) {
			t.Errorf("%s: the first answer is not the CNAME: %+v", c.name, got.Answers[0])
		}
	}
	// The question comes back as asked, and a query is not a reply.
	q := dnsQuestion{ID: 0x1234, Name: allowedName, Type: dnsTypeA}
	a := loop.answer(q)
	if qs := dnsQuery(q); string(a[12:12+len(qs)-12]) != string(qs[12:]) {
		t.Errorf("the question section differs: % x vs % x", a[12:12+len(qs)-12], qs[12:])
	}
	if _, ok := parseDNSQuery(a); ok {
		t.Error("the answer reads as a query")
	}
	if a[2]&0x80 == 0 || a[2]&0x01 == 0 || a[3]&0x80 == 0 {
		t.Errorf("flags % x: want QR, RD and RA", a[2:4])
	}
}
