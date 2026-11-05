// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
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
		d    audit.Record
		want string
	}{
		{"a refused name", audit.Record{Host: "registry.npmjs.org", Port: 53, Result: "name_not_allowed"}, "denied registry.npmjs.org (dns): " + remedy("registry.npmjs.org")},
		{"a refused SNI", audit.Record{Host: "api.example", Port: 443, Result: "sni_not_allowed"}, "denied api.example (tls): " + remedy("api.example")},
		{"upper case is lowered", audit.Record{Host: "API.Example", Port: 443, Result: "sni_not_allowed"}, "denied api.example (tls): " + remedy("api.example")},
		{"an SNI with a space", audit.Record{Host: "a b.example", Port: 443, Result: "sni_not_allowed"}, "denied (invalid) (tls): not a host name, so there is nothing to allow"},
		{"an SNI with a control byte", audit.Record{Host: "a\x1b[2J.example", Port: 443, Result: "sni_not_allowed"}, "denied (invalid) (tls): not a host name, so there is nothing to allow"},
		{"a name of no plain letters", audit.Record{Host: "", Port: 53, Result: "name_not_allowed"}, "denied (invalid) (dns): not a host name, so there is nothing to allow"},
		{"no SNI", audit.Record{Port: 443, Result: "no_sni"}, "denied a TLS connection with no server name (tls): there is no host name to allow"},
		{"a port", audit.Record{Port: 8080, Result: "port_not_allowed"}, "denied port 8080 (tcp): a bare name allows 443 only, and host:8080 forwards this port: " + remedy("host:8080")},
		{"a host mismatch", audit.Record{Host: "a.example", Port: 443, Result: "host_mismatch"}, "denied a.example (tls): the request named another host than its TLS name"},
		{"any other reason", audit.Record{Host: "a.example", Port: 443, Result: "method_refused"}, "denied a.example port 443: method_refused"},
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
	const ts = `{"time":"2026-01-02T03:04:05Z",`
	const denied = ts + `"event":"connect","host":"a.example","port":53,"result":"name_not_allowed"}` + "\n"
	const deniedText = "denied a.example (dns): allow it with  workcell run --allow a.example  or add \"a.example\" to [network] allow in C\n"
	const allowed = ts + `"event":"connect","host":"b.example","port":443,"result":"allowed"}` + "\n"
	tests := []struct {
		name   string
		chunks []string
		want   string
		bad    int
	}{
		{"a refusal", []string{denied}, deniedText, 0},
		{"a refusal in two reads", []string{denied[:40], denied[40:]}, deniedText, 0},
		{"half a line stays unshown", []string{denied[:40]}, "", 0},
		{"another record is shown as it is", []string{allowed}, allowed, 0},
		{"the full marker", []string{ts + `"event":"log_full"}` + "\n"}, "log full, later connections were not recorded\n", 0},
		{"malformed lines are counted, not printed", []string{"not json\n", ts + `"event":""}` + "\n", "\n"}, "", 3},
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
	dir := t.TempDir()
	key, err := audit.LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := audit.Create(dir, key, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(nil, record)
	dns := resolver.New(nil, func(name string) { p.Deny(name, dnsPort, "name_not_allowed") })
	q := append([]byte{0x42, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, "\x08registry\x05npmjs\x03org\x00\x00\x01\x00\x01"...)
	if a := dns.Answer(q); len(a) < 4 || a[3]&0x0F != 5 {
		t.Fatalf("reply %x, want REFUSED", a)
	}
	var out bytes.Buffer
	written, err := os.ReadFile(filepath.Join(dir, audit.LogName))
	if err != nil {
		t.Fatal(err)
	}
	(&denyReader{cfg: "/home/me/.config/workcell/config.toml"}).feed(written, &out)
	want := "denied registry.npmjs.org (dns): allow it with  workcell run --allow registry.npmjs.org  or add \"registry.npmjs.org\" to [network] allow in /home/me/.config/workcell/config.toml\n"
	if out.String() != want {
		t.Errorf("workcell log shows %q, want %q", out.String(), want)
	}
}
