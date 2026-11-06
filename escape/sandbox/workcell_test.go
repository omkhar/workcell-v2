// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"slices"
	"strconv"
	"testing"
)

func TestCpioEntry(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"init", "#!x"},    // header+name 115 -> padded to 116; data 3 -> 4
		{"a", ""},          // header+name 112: no pad; no data
		{"TRAILER!!!", ""}, // 121 -> 124
		{"abcdef", "12345678"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := cpioEntry(&b, c.name, 0o100755, []byte(c.data)); err != nil {
				t.Fatal(err)
			}
			out := b.Bytes()
			if len(out)%4 != 0 || string(out[:6]) != "070701" {
				t.Fatalf("entry is %d bytes, starts %q", len(out), out[:6])
			}
			field := func(i int) int64 {
				n, err := strconv.ParseInt(string(out[6+8*i:14+8*i]), 16, 64)
				if err != nil {
					t.Fatalf("field %d: %v", i, err)
				}
				return n
			}
			if field(1) != 0o100755 || field(6) != int64(len(c.data)) || field(11) != int64(len(c.name)+1) {
				t.Fatalf("mode %o size %d namesize %d", field(1), field(6), field(11))
			}
			nameEnd := 110 + len(c.name)
			if string(out[110:nameEnd]) != c.name || out[nameEnd] != 0 {
				t.Fatalf("name field %q", out[110:nameEnd+1])
			}
			dataAt := (nameEnd + 1 + 3) &^ 3
			if string(out[dataAt:dataAt+len(c.data)]) != c.data {
				t.Fatalf("data at %d is %q", dataAt, out[dataAt:])
			}
			for _, z := range out[nameEnd+1 : dataAt] {
				if z != 0 {
					t.Fatal("name padding is not zero")
				}
			}
		})
	}
}

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
