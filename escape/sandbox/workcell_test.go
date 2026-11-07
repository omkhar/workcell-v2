// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"slices"
	"testing"
)

func TestUnsupported(t *testing.T) {
	cases := []struct {
		cfg  Config
		want bool // refused
	}{
		{Config{}, false},
		{Config{CPUs: 2, MemoryMiB: 1024}, false},
		{Config{CPUs: 32}, false},
		{Config{MemoryMiB: 128}, false},
		{Config{DiskMiB: 100}, false},
		{Config{CPUs: 1, MemoryMiB: 256, DiskMiB: 64}, false},
		{Config{Workspace: "/w", Allow: []string{"a"}, Deny: []string{"b"}, Secret: &Secret{}}, false},
		{Config{Isolated: true}, true},
		{Config{Isolated: true, Resolver: "127.0.0.1"}, !steersResolver},
	}
	for _, c := range cases {
		if got := unsupported(c.cfg) != ""; got != c.want {
			t.Errorf("%+v: refused %v, want %v", c.cfg, got, c.want)
		}
	}
}

// TestPolicyTOML checks the one file the adapter writes for a session: each
// allowed name quoted, nothing for a denied one, the secret as one table
// naming its file source and only the keys it has, and a refusal of a name
// or a value that would change what the file says, or of a secret bound to
// a name the policy does not allow.
func TestPolicyTOML(t *testing.T) {
	bound := &Secret{Name: "escape", Value: "sk-x", Host: "a.escape.test", Header: "x-api-key", Env: "ESCAPE_API_KEY"}
	narrow := &Secret{Name: "escape", Value: "sk-x", Host: "a.escape.test", Header: "x-api-key", Method: "POST", Path: "/v1/"}
	cases := []struct {
		cfg  Config
		want string // the file, or "" for a refusal
	}{
		{Config{}, "[network]\nallow = []\n"},
		{Config{Deny: []string{"denied.escape.test"}}, "[network]\nallow = []\n"},
		{Config{Allow: []string{"allowed.escape.test:8443"}}, "[network]\nallow = [\"allowed.escape.test:8443\"]\n"},
		{Config{Allow: []string{"a.escape.test", "b.escape.test:80"}, Deny: []string{"c.escape.test"}}, "[network]\nallow = [\"a.escape.test\", \"b.escape.test:80\"]\n"},
		{Config{Allow: []string{"a.escape.test", "b.escape.test"}, Secret: bound},
			"[network]\nallow = [\"a.escape.test\", \"b.escape.test\"]\n\n[[secret]]\nname = \"escape\"\nsource = \"file:/s/secret\"\nhost = \"a.escape.test\"\nheader = \"x-api-key\"\nenv = \"ESCAPE_API_KEY\"\n"},
		{Config{Allow: []string{"a.escape.test"}, Secret: &Secret{Name: "git", Host: "a.escape.test", Header: "authorization", Repos: []string{"octo/allowed", "octo/also"}}},
			"[network]\nallow = [\"a.escape.test\"]\n\n[[secret]]\nname = \"git\"\nsource = \"file:/s/secret\"\nhost = \"a.escape.test\"\nheader = \"authorization\"\nrepos = [\"octo/allowed\", \"octo/also\"]\n"},
		{Config{Allow: []string{"a.escape.test"}, Secret: &Secret{Name: "a", Host: "a.escape.test", Header: "x", Repos: []string{"octo/a\"b"}}}, ""},
		{Config{Allow: []string{"a.escape.test"}, Secret: narrow},
			"[network]\nallow = [\"a.escape.test\"]\n\n[[secret]]\nname = \"escape\"\nsource = \"file:/s/secret\"\nhost = \"a.escape.test\"\nheader = \"x-api-key\"\nmethod = \"POST\"\npath = \"/v1/\"\n"},
		{Config{Allow: []string{"a.escape.test", "b.escape.test"}, Secret: &Secret{Name: "escape", Host: "a.escape.test", Header: "authorization", Env: "ESCAPE_API_KEY", Source: "signin:b.escape.test/oauth/token"}},
			"[network]\nallow = [\"a.escape.test\", \"b.escape.test\"]\n\n[[secret]]\nname = \"escape\"\nsource = \"signin:b.escape.test/oauth/token\"\nhost = \"a.escape.test\"\nheader = \"authorization\"\nenv = \"ESCAPE_API_KEY\"\n"},
		{Config{Allow: []string{"b.escape.test"}, Secret: bound}, ""},
		{Config{Allow: []string{"a.escape.test"}, Secret: &Secret{Name: "a\"b", Host: "a.escape.test", Header: "x"}}, ""},
		{Config{Allow: []string{"a.escape.test"}, Secret: &Secret{Name: "a", Host: "a.escape.test", Header: "x", Path: "/v1/\n"}}, ""},
		{Config{Allow: []string{"a.escape.test"}, Deny: []string{"a.escape.test"}}, ""},
		{Config{Allow: []string{`a"b`}}, ""},
		{Config{Allow: []string{`a\b`}}, ""},
		{Config{Allow: []string{"a\nb"}}, ""},
		{Config{Allow: []string{"a\x7fb"}}, ""},
		{Config{Allow: []string{"ok", "a\tb"}}, ""},
	}
	for _, c := range cases {
		got, err := policyTOML(c.cfg, "/s/secret")
		if (err != nil) != (c.want == "") || string(got) != c.want {
			t.Errorf("%+v: %q, %v; want %q", c.cfg, got, err, c.want)
		}
	}
}

func TestRunArgs(t *testing.T) {
	tail := []string{"--", "/bin/sh", "-c", "L", "sh", "probe", "x"}
	cases := []struct {
		cfg  Config
		caps []string
	}{
		{Config{}, nil},
		{Config{CPUs: 2, MemoryMiB: 1024}, []string{"--cpus", "2", "--memory", "1024MiB"}},
		{Config{DiskMiB: 64}, []string{"--disk", "64MiB"}},
		{Config{CPUs: 1, MemoryMiB: 256, DiskMiB: 64}, []string{"--cpus", "1", "--memory", "256MiB", "--disk", "64MiB"}},
		{Config{Mount: true}, []string{"--mount"}},
		{Config{Mount: true, CPUs: 2}, []string{"--mount", "--cpus", "2"}},
	}
	for _, c := range cases {
		want := append(append([]string{"run"}, c.caps...), tail...)
		if got := runArgs(c.cfg, "L", "probe", "x"); !slices.Equal(got, want) {
			t.Errorf("%+v: argv %q, want %q", c.cfg, got, want)
		}
	}
}
