// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"strings"
	"testing"
)

func TestFirstNameserver(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"nameserver 127.0.0.1\n", "127.0.0.1:53"},
		{"# comment\nsearch example\n  nameserver   10.0.0.2 \nnameserver 10.0.0.3\n", "10.0.0.2:53"},
		{"nameserver ::1\n", "[::1]:53"},
		{"nameserver notanip\nnameserver 192.0.2.1\n", "192.0.2.1:53"},
		{"search example\n", ""},
		{"", ""},
	}
	for _, c := range cases {
		got, err := firstNameserver(strings.NewReader(c.in))
		if got != c.want || (err == nil) != (c.want != "") {
			t.Errorf("firstNameserver(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestEncodeLookup(t *testing.T) {
	msg, id, err := encode("A+edns:TOKEN.invalid.", "tok")
	if err != nil {
		t.Fatal(err)
	}
	q, ok := parseDNSQuery(msg)
	if !ok || q.ID != id || q.Name != "tok.invalid." || q.Type != dnsTypeA || msg[11] != 1 {
		t.Errorf("encode = %+v, %v (arcount %d)", q, ok, msg[11])
	}
	for _, bad := range []string{"A", "MX:a.", ":a."} {
		if _, _, err := encode(bad, "tok"); err == nil {
			t.Errorf("encode(%q) succeeded", bad)
		}
	}
	for _, g := range garbage("tok") {
		if len(g) == 0 || len(g) > 65000 {
			t.Errorf("garbage of %d bytes", len(g))
		}
	}
}

// TestLookupJudge checks what each want accepts: an address, a refusal
// without one, any answer; never silence, never a slow one.
func TestLookupJudge(t *testing.T) {
	cases := []struct {
		want, got string
		ok        bool
	}{
		{"addr", "addr:127.0.0.1/2ms", true},
		{"addr", "addr:::1/2ms", true},
		{"addr", "nodata/2ms", false},
		{"addr", "refused/2ms", false},
		{"addr", "timeout/2500ms", false},
		{"addr", "addr:127.0.0.1/2100ms", false},
		{"addr", "", false},
		{"refused", "refused/1ms", true},
		{"refused", "nxdomain/1ms", true},
		{"refused", "nodata/1ms", true},
		{"refused", "servfail/1ms", false},
		{"refused", "addr:192.0.2.2/1ms", false},
		{"refused", "answered:1/1ms", false},
		{"refused", "timeout/2500ms", false},
		{"refused", "unreachable/0ms", false},
		{"refused", "refused/2001ms", false},
		{"answered", "refused/1ms", true},
		{"answered", "servfail/1ms", true},
		{"answered", "addr:127.0.0.1/1ms", true},
		{"answered", "timeout/2500ms", false},
		{"answered", "garbled/3ms", false},
	}
	for _, c := range cases {
		q := lookup{"a", "A:x.", c.want}
		if why := q.judge(c.got); (why == "") != c.ok {
			t.Errorf("want %s, got %q: judge = %q", c.want, c.got, why)
		}
	}
}

// TestResolverJudges runs the judges on a guest that says what a canned
// resolver answered.
func TestResolverJudges(t *testing.T) {
	session := func(detail string) Session {
		return Session{Run: func(args ...string) (Result, error) {
			for _, a := range args[2:] {
				if !strings.Contains(a, "=") {
					t.Errorf("probe argument %q is not label=spec", a)
				}
			}
			return Result{Status: "asked", Detail: detail}, nil
		}}
	}
	cases := []struct {
		name   string
		judge  Judge
		detail string
		pass   bool
	}{
		{"both right", resolverJudge(resolvConf, bothLookups), "127.0.0.1:53 a=addr:127.0.0.1/1ms d=refused/1ms i=nxdomain/1ms", true},
		{"nothing answered", resolverJudge(resolvConf, bothLookups), "127.0.0.1:53 a=timeout/2500ms d=timeout/2500ms i=timeout/2500ms", false},
		{"everything resolved", resolverJudge(resolvConf, bothLookups), "127.0.0.1:53 a=addr:1.2.3.4/1ms d=addr:1.2.3.4/1ms i=addr:1.2.3.4/1ms", false},
		{"a label missing", resolverJudge(resolvConf, bothLookups), "127.0.0.1:53 a=addr:127.0.0.1/1ms d=refused/1ms", false},
		{"burst all refused", burstJudge(bothLookups), "burst sent=200 got=200 refused:200 in 9ms; then a=addr:127.0.0.1/1ms d=refused/1ms i=refused/1ms", true},
		{"burst mixed refusals", burstJudge(bothLookups), "burst sent=200 got=200 nxdomain:150,refused:50 in 9ms; then a=addr:127.0.0.1/1ms d=refused/1ms i=refused/1ms", true},
		{"burst one lost", burstJudge(bothLookups), "burst sent=200 got=199 refused:199 in 2500ms; then a=addr:127.0.0.1/1ms d=refused/1ms i=refused/1ms", false},
		{"burst resolved", burstJudge(bothLookups), "burst sent=200 got=200 addr:1.2.3.4:200 in 9ms; then a=addr:127.0.0.1/1ms d=refused/1ms i=refused/1ms", false},
		{"burst short", burstJudge(bothLookups), "burst sent=10 got=10 refused:10 in 9ms; then a=addr:127.0.0.1/1ms d=refused/1ms i=refused/1ms", false},
		{"burst then dead", burstJudge(bothLookups), "burst sent=200 got=200 refused:200 in 9ms; then a=timeout/2500ms d=timeout/2500ms i=timeout/2500ms", false},
	}
	for _, c := range cases {
		pass, detail, err := c.judge(context.Background(), session(c.detail))
		if err != nil || pass != c.pass {
			t.Errorf("%s: pass %v, %v (%s); want %v", c.name, pass, err, detail, c.pass)
		}
	}
}
