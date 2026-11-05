// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/policy"
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
