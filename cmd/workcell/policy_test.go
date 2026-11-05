// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/proxy"
)

func TestConfigDir(t *testing.T) {
	tests := []struct {
		name, xdg, home, want string
	}{
		{"XDG_CONFIG_HOME wins", "/x/config", "/home/u", "/x/config/workcell"},
		{"HOME otherwise", "", "/home/u", "/home/u/.config/workcell"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tc.xdg)
			t.Setenv("HOME", tc.home)
			got, err := configDir()
			if err != nil || got != tc.want {
				t.Errorf("configDir() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestAllowlist(t *testing.T) {
	entries := func(texts ...string) (es []policy.Entry) {
		for i, s := range texts {
			es = append(es, policy.Entry{Text: s, Line: i + 2})
		}
		return es
	}
	tests := []struct {
		name  string
		allow []policy.Entry
		ports []uint16 // nil: no allowlist
		err   string   // the start of the error
	}{
		{"nothing allowed", nil, nil, ""},
		{"a bare name is 443 by SNI", entries("api.example.com"), []uint16{443}, ""},
		{"name:443 is the same", entries("api.example.com:443"), []uint16{443}, ""},
		{"name:port forwards that port", entries("allowed.escape.test:8443"), []uint16{8443}, ""},
		{"the SPEC example", entries("api.anthropic.com", "github.com", "proxy.golang.org"), []uint16{443}, ""},
		{"mixed, sorted", entries("b.example:8443", "a.example", "c.example:80"), []uint16{80, 443, 8443}, ""},
		{"one name twice on a port", entries("a.example:80", "A.example:80"), []uint16{80}, ""},
		{"two names on one forward port", entries("a.example", "a.example:8443", "b.example:8443"), nil, "config.toml:4 maps port 8443 to more than one host"},
		{"an IP literal", entries("a.example", "10.0.0.1:443"), nil, "config.toml:3 has an IP literal endpoint"},
		{"an IPv6 literal with no port", entries("[::1]"), nil, "config.toml:2 has an invalid endpoint"},
		{"a bad port", entries("a.example:0"), nil, "config.toml:2 has an invalid endpoint port"},
		{"a port out of range", entries("a.example:65536"), nil, "config.toml:2 has an invalid endpoint port"},
		{"an empty entry", entries(""), nil, "config.toml:2 has an invalid endpoint: \"\""},
		{"two entries in one string", entries("a.example:443 b.example:443"), nil, "config.toml:2 has an invalid endpoint"},
		{"a wildcard", entries("*.example"), nil, "config.toml:2 has an invalid endpoint"},
		{"a URL", entries("https://a.example"), nil, "config.toml:2 has an invalid endpoint"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := allowlist(policy.Policy{Allow: tc.allow}, "config.toml")
			if tc.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.err) || strings.Contains(err.Error(), "\n") {
					t.Fatalf("allowlist = %v, want one line starting %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var ports []uint16
			if got != nil {
				ports = got.Ports()
			}
			if !slices.Equal(ports, tc.ports) {
				t.Errorf("ports = %v, want %v", ports, tc.ports)
			}
		})
	}
}

// TestBindings: a [[secret]] row becomes a grant and a rule with one fresh placeholder, the host
// canonical and the header lowercase in both, and explain names it without its source; a row whose
// host is not a bare allowed name, or that the proxy refuses, or that binds a pair again, or
// whose env is not a variable name, is refused with its line.
func TestBindings(t *testing.T) {
	allow, err := allowlist(policy.Policy{Allow: []policy.Entry{{Text: "a.example", Line: 2}, {Text: "db.example:5432", Line: 2}}}, "config.toml")
	if err != nil {
		t.Fatal(err)
	}
	row := policy.Secret{Name: "k", Source: "file:/s", Host: "A.example.", Header: "X-Api-Key", Line: 5}
	with := func(f func(s *policy.Secret)) policy.Secret { s := row; f(&s); return s }
	tests := []struct {
		name string
		rows []policy.Secret
		text string // what explain prints
		err  string // the start of the error
	}{
		{"none", nil, "secrets: none\n", ""},
		{"a row", []policy.Secret{row}, "secrets: swapped in by the session proxy; the guest holds a placeholder\n  k: in x-api-key to https://a.example\n", ""},
		{"every key", []policy.Secret{with(func(s *policy.Secret) { s.Env, s.Method, s.Path = "A_KEY", "POST", "/v1/" })},
			"secrets: swapped in by the session proxy; the guest holds a placeholder\n  k: in x-api-key to https://a.example, POST only, under /v1/, as $A_KEY\n", ""},
		{"two headers on one host", []policy.Secret{row, with(func(s *policy.Secret) { s.Header, s.Line = "authorization", 9 })},
			"secrets: swapped in by the session proxy; the guest holds a placeholder\n  k: in x-api-key to https://a.example\n  k: in authorization to https://a.example\n", ""},
		{"host not allowed", []policy.Secret{with(func(s *policy.Secret) { s.Host = "b.example" })}, "", "config.toml:5: secret \"k\": host \"b.example\" is not a bare name"},
		{"host allowed on a forward port alone", []policy.Secret{with(func(s *policy.Secret) { s.Host = "db.example" })}, "", "config.toml:5: secret \"k\": host \"db.example\" is not a bare name"},
		{"an IP host", []policy.Secret{with(func(s *policy.Secret) { s.Host = "10.0.0.1" })}, "", "config.toml:5: secret \"k\": terminate rule"},
		{"a bad header", []policy.Secret{with(func(s *policy.Secret) { s.Header = "x api key" })}, "", "config.toml:5: secret \"k\": terminate rule has an invalid header name"},
		{"a bad method", []policy.Secret{with(func(s *policy.Secret) { s.Method = "post" })}, "", "config.toml:5: secret \"k\": terminate rule method"},
		{"a bad path", []policy.Secret{with(func(s *policy.Secret) { s.Path = "v1" })}, "", "config.toml:5: secret \"k\": terminate rule path"},
		{"a bad env", []policy.Secret{with(func(s *policy.Secret) { s.Env = "1KEY=" })}, "", "config.toml:5: secret \"k\": env \"1KEY=\" is not a variable name"},
		{"the pair bound twice", []policy.Secret{row, with(func(s *policy.Secret) { s.Name, s.Header, s.Line = "j", "x-API-key", 9 })}, "", "config.toml:9: secret \"j\": header x-api-key on a.example is already bound on line 5"},
		{"a sign-in source", []policy.Secret{with(func(s *policy.Secret) {
			s.Source, s.Header, s.Env = "signin:A.example/oauth/token", "authorization", "A_KEY"
		})},
			"secrets: swapped in by the session proxy; the guest holds a placeholder\n  k: in authorization to https://a.example, signed in at https://a.example/oauth/token, as $A_KEY\n", ""},
		{"a sign-in host not allowed", []policy.Secret{with(func(s *policy.Secret) { s.Source = "signin:b.example/oauth/token" })}, "", "config.toml:5: secret \"k\": sign-in host \"b.example\" is not a bare name"},
		{"a bad sign-in source", []policy.Secret{with(func(s *policy.Secret) { s.Source = "signin:a.example" })}, "", "config.toml:5: secret \"k\": sign-in source must be signin:HOST/PATH"},
		{"the token endpoint bound twice", []policy.Secret{with(func(s *policy.Secret) { s.Source = "signin:a.example/t" }), with(func(s *policy.Secret) { s.Source, s.Header, s.Line = "signin:a.example/t", "authorization", 9 })},
			"", "config.toml:9: secret \"k\": token endpoint a.example/t is already bound on line 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bindings(policy.Policy{Secret: tc.rows}, allow, "config.toml")
			if tc.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.err) || strings.Contains(err.Error(), "\n") {
					t.Fatalf("bindings = %v, want one line starting %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for i, b := range got {
				if b.grant.Name != tc.rows[i].Name || b.grant.Source != tc.rows[i].Source || b.grant.Host != b.rule.Host || b.grant.Header != b.rule.Header || b.rule.Placeholder == "" || seen[b.rule.Placeholder] {
					t.Errorf("binding %d = %+v, want the row's name and source, the rule's host and header, a fresh placeholder", i, b)
				}
				seen[b.rule.Placeholder] = true
				if s := b.rule.SignIn; s != nil && (seen[s.Refresh] || !proxy.IsPlaceholder(s.Refresh)) {
					t.Errorf("binding %d has refresh placeholder %q, want a fresh one", i, s.Refresh)
				}
				if s := b.rule.SignIn; s != nil {
					seen[s.Refresh] = true
				}
			}
			if text := bound(got); text != tc.text || strings.Contains(text, "file:") {
				t.Errorf("bound = %q, want %q", text, tc.text)
			}
		})
	}
}

// TestAllowlistFlags: each --allow value is judged as a config entry is, and joins the file's.
func TestAllowlistFlags(t *testing.T) {
	file := []policy.Entry{{Text: "a.example", Line: 3}}
	tests := []struct {
		name  string
		file  []policy.Entry
		flags []string
		ports []uint16
		hosts []string
		err   string
	}{
		{"a bare name", nil, []string{"npm.example"}, []uint16{443}, []string{"npm.example"}, ""},
		{"name:port", nil, []string{"db.example:5432"}, []uint16{5432}, []string{"db.example"}, ""},
		{"the file and the flag", file, []string{"b.example", "b.example:80"}, []uint16{80, 443}, []string{"a.example", "b.example"}, ""},
		{"a bad value", file, []string{"a b"}, nil, nil, "--allow has an invalid endpoint"},
		{"an IP", nil, []string{"10.0.0.1"}, nil, nil, "--allow has an IP literal endpoint"},
		{"a port the file gave to another name", []policy.Entry{{Text: "a.example:80", Line: 2}}, []string{"b.example:80"}, nil, nil, "--allow maps port 80 to more than one host"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := policy.Policy{Allow: tc.file}
			for _, f := range tc.flags {
				p.Allow = append(p.Allow, policy.Entry{Text: f})
			}
			got, err := allowlist(p, "config.toml")
			if tc.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.err) {
					t.Fatalf("allowlist = %v, want an error starting %q", err, tc.err)
				}
				return
			}
			if err != nil || !slices.Equal(got.Ports(), tc.ports) || !slices.Equal(got.Hosts(), tc.hosts) {
				t.Errorf("allowlist = %v, %v; want ports %v hosts %v", got, err, tc.ports, tc.hosts)
			}
		})
	}
}
