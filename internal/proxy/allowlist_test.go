// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/allowlist_test.go

package proxy

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestParseAllowlist(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		text    string
		sni     []string
		forward map[uint16]string
		wantErr string
	}{
		{name: "sni hosts share 443", text: "api.example.com:443\nb.example:443", sni: []string{"api.example.com", "b.example"}},
		{name: "comments blanks and case", text: "# header\n\n API.Example.COM:443 # trailing\n", sni: []string{"api.example.com"}},
		{name: "trailing dot", text: "api.example.com.:443", sni: []string{"api.example.com"}},
		{name: "one host per forward port", text: "db.example:5432\nDB.example:5432\nssh.example:22", forward: map[uint16]string{5432: "db.example", 22: "ssh.example"}},
		{name: "two hosts on a forward port", text: "a.example:5432\nb.example:5432", wantErr: "more than one host"},
		{name: "ipv4 literal", text: "10.0.0.5:443", wantErr: "IP literal"},
		{name: "ipv6 literal", text: "[2001:db8::1]:443", wantErr: "IP literal"},
		{name: "bad grammar", text: "under_score:443", wantErr: "invalid endpoint"},
		{name: "wildcard", text: "*.example.com:443", wantErr: "invalid endpoint"},
		{name: "empty label", text: "a..example:443", wantErr: "invalid endpoint"},
		{name: "hyphen at label edge", text: "-a.example:443", wantErr: "invalid endpoint"},
		{name: "label too long", text: strings.Repeat("a", 64) + ".example:443", wantErr: "invalid endpoint"},
		{name: "name too long", text: strings.Repeat("a.", 127) + "ab:443", wantErr: "invalid endpoint"},
		{name: "missing port", text: "api.example.com", wantErr: "invalid endpoint"},
		{name: "port zero", text: "api.example.com:0", wantErr: "invalid endpoint port"},
		{name: "empty", text: "# nothing\n", wantErr: "no endpoints"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAllowlist(tc.text, "allowlist")
			if (err != nil) != (tc.wantErr != "") || err != nil && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseAllowlist(%q) error = %v, want %q", tc.text, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			sni := map[string]bool{}
			for _, host := range tc.sni {
				sni[host] = true
			}
			if !maps.Equal(got.sni, sni) || !maps.Equal(got.forward, tc.forward) {
				t.Errorf("ParseAllowlist(%q) = sni %v, forward %v; want %v and %v", tc.text, got.sni, got.forward, tc.sni, tc.forward)
			}
		})
	}
}

func TestAllowlistPorts(t *testing.T) {
	t.Parallel()
	a := must(ParseAllowlist("db.example:5432\napi.example.com:443\nssh.example:22\nDB.example:443\n", "allowlist"))
	if got, want := a.Ports(), []uint16{22, 443, 5432}; !slices.Equal(got, want) {
		t.Fatalf("Ports() = %v, want %v", got, want)
	}
	if got, want := a.Hosts(), []string{"api.example.com", "db.example", "ssh.example"}; !slices.Equal(got, want) {
		t.Fatalf("Hosts() = %v, want %v", got, want)
	}
}
