// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package provider

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// good is a minimal valid file; the refusals below each break one thing in it.
const good = `[provider]
name = "demo"
binary = "demo"
hosts = ["api.example.com", "login.example.com"]

[install]
method = "binary"
pin = "demo"

[[secret]]
name = "demo"
host = "api.example.com"
header = "authorization"
prefix = "Bearer "
env = "DEMO_API_KEY"
`

func TestEmbeddedProviders(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range all {
		names = append(names, p.Name)
		if len(p.Secrets) == 0 || p.Install.Method == "" {
			t.Errorf("%s: no secret or no install: %+v", p.Name, p)
		}
		if got, ok := Lookup(p.Name); !ok || got.Binary != p.Binary {
			t.Errorf("Lookup(%q) = %+v, %v", p.Name, got, ok)
		}
	}
	if want := []string{"claude", "codex", "copilot", "gemini"}; !slices.Equal(names, want) {
		t.Errorf("providers = %v, want %v", names, want)
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup found a provider that is not there")
	}
	for name, want := range map[string]string{"anthropic": "claude", "openai": "codex", "github": "copilot", "gemini": "gemini", "nope": ""} {
		if s, p, ok := FindSecret(name); ok != (want != "") || p.Name != want || ok && s.Name != name || ok && s.Prefix != map[string]string{"openai": "Bearer ", "github": "Bearer "}[name] {
			t.Errorf("FindSecret(%q) = %+v, %q, %v; want provider %q", name, s, p.Name, ok, want)
		}
	}
}

// TestAddProviderIsOneDataFile is the accept of U-402: a provider that no Go code knows loads
// from one more file, and the embedded set is checked by the same rules as this one.
func TestAddProviderIsOneDataFile(t *testing.T) {
	fsys := fstest.MapFS{"demo.toml": {Data: []byte(good)}}
	all, err := Load(fsys)
	if err != nil || len(all) != 1 {
		t.Fatalf("Load = %+v, %v", all, err)
	}
	want := Secret{"demo", "api.example.com", "authorization", "Bearer ", "DEMO_API_KEY", 10}
	if p := all[0]; p.Name != "demo" || p.Install != (Install{"binary", "demo", ""}) || len(p.Hosts) != 2 || p.Secrets[0] != want {
		t.Errorf("loaded %+v", p)
	}
}

func TestLoadRefuses(t *testing.T) {
	sub := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	npm := func(install string) string { return sub("method = \"binary\"\npin = \"demo\"", install) }
	for _, tc := range []struct{ name, text, want string }{
		{"unknown key", sub("binary = \"demo\"", "binary = \"demo\"\ntier = \"x\""), "demo.toml:4: unknown key \"tier\" in [provider]"},
		{"unknown table", good + "[flags]\n", "demo.toml:16: table [flags]"},
		{"table twice", good + "[install]\n", "demo.toml:16: table [install] is defined twice, first on line 6"},
		{"missing field", sub("binary = \"demo\"\n", ""), "demo.toml:1: [provider] needs a binary"},
		{"missing table", sub("[install]\nmethod = \"binary\"\npin = \"demo\"\n", ""), "needs a [provider] and an [install]"},
		{"hosts not an array", sub(`hosts = ["api.example.com", "login.example.com"]`, `hosts = "api.example.com"`), "demo.toml:4: hosts must be an array"},
		{"integer", sub(`env = "DEMO_API_KEY"`, "env = 7"), "demo.toml:15: env must be a string"},
		{"name is not the file", sub(`name = "demo"`, `name = "other"`), "provider name \"other\" is not the file's name"},
		{"host with port", sub(`"login.example.com"`, `"login.example.com:443"`), "demo.toml:4: hosts:"},
		{"host with scheme", sub(`"login.example.com"`, `"https://login.example.com"`), "demo.toml:4: hosts:"},
		{"host with a second host", sub(`"login.example.com"`, `"a.example.com:80 b.example.com"`), "demo.toml:4: hosts:"},
		{"host upper case", sub(`"login.example.com"`, `"Login.example.com"`), "demo.toml:4: hosts:"},
		{"host an IP", sub(`"login.example.com"`, `"192.0.2.1"`), "demo.toml:4: hosts:"},
		{"host not a name", sub(`"login.example.com"`, `"a_b.example.com"`), "demo.toml:4: hosts:"},
		{"secret host not a provider host", sub(`host = "api.example.com"`, `host = "other.example.com"`), "host other.example.com is not one of the provider's hosts"},
		{"header upper case", sub(`"authorization"`, `"Authorization"`), "demo.toml:10: [secret]: header \"Authorization\" must be lower-case"},
		{"bad prefix", sub(`"Bearer "`, `"Token "`), "prefix must be"},
		{"bad env", sub(`"DEMO_API_KEY"`, `"1BAD"`), "env \"1BAD\" is not a variable name"},
		{"no env", sub("env = \"DEMO_API_KEY\"\n", ""), "needs an env"},
		{"duplicate credential", good + "\n" + good[strings.Index(good, "[[secret]]"):], "demo.toml:17: [secret]: header authorization on api.example.com is already bound on line 10"},
		{"version in a pin", npm("method = \"binary\"\npin = \"demo-1.2.3\""), "[install]: method binary wants a pin"},
		{"version in a package", npm("method = \"npm\"\npackage = \"@x/demo@1.2.3\""), "[install]: method npm wants a package"},
		{"unknown version key", sub("pin = \"demo\"", "pin = \"demo\"\nversion = \"1.2.3\""), "unknown key \"version\" in [install]"},
		{"pin and package", sub("pin = \"demo\"", "pin = \"demo\"\npackage = \"demo\""), "[install]: method binary wants a pin"},
		{"bad method", npm("method = \"curl\""), "method must be binary or npm"},
		{"binary is a path", sub(`binary = "demo"`, `binary = "/bin/demo"`), "binary must be an executable's name"},
		{"syntax", sub(`pin = "demo"`, `pin = 'demo'`), "demo.toml:8: literal strings"},
		{"an npm package is fine", npm("method = \"npm\"\npackage = \"@x/demo\""), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(fstest.MapFS{"demo.toml": {Data: []byte(tc.text)}})
			if (err == nil) != (tc.want == "") || err != nil && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Load error = %v, want it to hold %q", err, tc.want)
			}
		})
	}
}
