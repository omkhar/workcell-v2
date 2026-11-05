// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/proxy"
	"github.com/omkhar/workcell/v2/internal/resolver"
)

func TestDenyMessage(t *testing.T) {
	const cfg = "/c/config.toml"
	remedy := func(e string) string {
		return `allow it with  workcell run --allow ` + e + `  or add "` + e + `" to [network] allow in /c/config.toml`
	}
	tests := []struct {
		name string
		d    proxy.DenyLine
		want string
	}{
		{"a refused name", proxy.DenyLine{Host: "registry.npmjs.org", Port: 53, Reason: "name_not_allowed"}, "denied registry.npmjs.org (dns): " + remedy("registry.npmjs.org")},
		{"a refused SNI", proxy.DenyLine{Host: "api.example", Port: 443, Reason: "sni_not_allowed"}, "denied api.example (tls): " + remedy("api.example")},
		{"upper case is lowered", proxy.DenyLine{Host: "API.Example", Port: 443, Reason: "sni_not_allowed"}, "denied api.example (tls): " + remedy("api.example")},
		{"an SNI with a space", proxy.DenyLine{Host: "a b.example", Port: 443, Reason: "sni_not_allowed"}, "denied (invalid) (tls): not a host name, so there is nothing to allow"},
		{"an SNI with a control byte", proxy.DenyLine{Host: "a\x1b[2J.example", Port: 443, Reason: "sni_not_allowed"}, "denied (invalid) (tls): not a host name, so there is nothing to allow"},
		{"a name of no plain letters", proxy.DenyLine{Host: "", Port: 53, Reason: "name_not_allowed"}, "denied (invalid) (dns): not a host name, so there is nothing to allow"},
		{"no SNI", proxy.DenyLine{Port: 443, Reason: "no_sni"}, "denied a TLS connection with no server name (tls): there is no host name to allow"},
		{"a port", proxy.DenyLine{Port: 8080, Reason: "port_not_allowed"}, "denied port 8080 (tcp): a bare name allows 443 only, and host:8080 forwards this port: " + remedy("host:8080")},
		{"a host mismatch", proxy.DenyLine{Host: "a.example", Port: 443, Reason: "host_mismatch"}, "denied a.example (tls): the request named another host than its TLS name"},
		{"any other reason", proxy.DenyLine{Host: "a.example", Port: 443, Reason: "method_refused"}, "denied a.example port 443: method_refused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyMessage(tc.d, cfg); got != tc.want || strings.Contains(got, "\n") {
				t.Errorf("denyMessage = %q, want one line %q", got, tc.want)
			}
		})
	}
}

func TestDenyReader(t *testing.T) {
	tests := []struct {
		name   string
		chunks []string
		want   string
		bad    int
	}{
		{"a line", []string{"{\"host\":\"a.example\",\"port\":53,\"reason\":\"name_not_allowed\",\"count\":1,\"seq\":1}\n"}, "denied a.example (dns): allow it with  workcell run --allow a.example  or add \"a.example\" to [network] allow in C\n", 0},
		{"a line in two reads", []string{"{\"host\":\"a.example\",\"port\":53,", "\"reason\":\"name_not_allowed\",\"count\":1,\"seq\":1}\n"}, "denied a.example (dns): allow it with  workcell run --allow a.example  or add \"a.example\" to [network] allow in C\n", 0},
		{"half a line stays unshown", []string{"{\"host\":\"a.example\""}, "", 0},
		{"the full marker", []string{"{\"reason\":\"deny_log_full\"}\n"}, "deny log full, later denials were dropped\n", 0},
		{"malformed lines are counted, not printed", []string{"not json\n", "{\"host\":\"a\",\"port\":0,\"reason\":\"x\",\"count\":1,\"seq\":1}\n", "\n"}, "", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := denyReader{cfg: "C"}
			for _, c := range tc.chunks {
				r.feed([]byte(c), &out)
			}
			if out.String() != tc.want || r.malformed != tc.bad {
				t.Errorf("shown %q with %d malformed, want %q with %d", out.String(), r.malformed, tc.want, tc.bad)
			}
		})
	}
}

// TestAcceptBlockedNpmInstallNamesTheHostToAllow is the accept demonstration of U-308 at unit
// level: the guest's npm asks for registry.npmjs.org, the resolver refuses it and tells the
// proxy's real Deny, and the log, read the way `workcell log` reads it, has exactly one line, which
// names the host and the remedy.
func TestAcceptBlockedNpmInstallNamesTheHostToAllow(t *testing.T) {
	var denyLog bytes.Buffer
	p := proxy.New(nil, &denyLog)
	dns := resolver.New(nil, func(name string) { p.Deny(name, dnsPort, "name_not_allowed") })
	q := append([]byte{0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "\x08registry\x05npmjs\x03org\x00\x00\x01\x00\x01"...)
	if a := dns.Answer(q); len(a) < 4 || a[3]&0x0F != 5 {
		t.Fatalf("reply %x, want REFUSED", a)
	}
	var out bytes.Buffer
	(&denyReader{cfg: "/home/me/.config/workcell/config.toml"}).feed(denyLog.Bytes(), &out)
	want := "denied registry.npmjs.org (dns): allow it with  workcell run --allow registry.npmjs.org  or add \"registry.npmjs.org\" to [network] allow in /home/me/.config/workcell/config.toml\n"
	if out.String() != want {
		t.Errorf("workcell log shows %q, want %q", out.String(), want)
	}
}
