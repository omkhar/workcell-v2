// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/proxy"
	"github.com/omkhar/workcell/v2/internal/secret"
)

// configDir is where the policy lives: $XDG_CONFIG_HOME/workcell, or ~/.config/workcell (SPEC
// section 5), on every OS alike, as dataDir does for the data directory.
func configDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "workcell"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "workcell"), nil
}

// configFile is the policy file, which may not exist.
func configFile() (string, error) {
	dir, err := configDir()
	return filepath.Join(dir, "config.toml"), err
}

// loadPolicy reads the policy and builds what a session needs from it: the proxy's allowlist,
// with the entries of this session's --allow flags added to the file's (I13: the operator typed
// them on the host), and the secret bindings. A nil allowlist means the policy allows nothing:
// no TCP port is relayed. An error names the file and line, or the flag. Only the user's own
// file is read: nothing in a repository can add or change a secret (I13).
func loadPolicy(extra []string) (*proxy.Allowlist, []binding, error) {
	file, err := configFile()
	if err != nil {
		return nil, nil, err
	}
	p, err := policy.Read(file)
	if err != nil {
		return nil, nil, err
	}
	for _, text := range extra {
		p.Allow = append(p.Allow, policy.Entry{Text: text}) // line 0: it comes from a flag
	}
	allow, err := allowlist(p, file)
	if err != nil {
		return nil, nil, err
	}
	secrets, err := bindings(p, allow, file)
	return allow, secrets, err
}

// binding is one [[secret]] row ready for a session: the grant the broker releases, the rule
// the proxy swaps by, holding the placeholder minted here, and the guest variable that carries
// the placeholder, "" for none. The value itself is read by the broker, per use, on the host (I5).
type binding struct {
	grant secret.Grant
	rule  proxy.TerminateRule
	env   string
}

// envName is a variable name as the guest's environment takes it.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// bindings turns the policy's [[secret]] rows into the session's bindings, one fresh placeholder
// each. The proxy judges host, header, method and path (A3); the host must then be a bare name
// of the allow list, so that the proxy terminates it and swaps there (I6); no two rows may bind
// one header on one host; and env must be a variable name. A fault is reported with its line.
func bindings(p policy.Policy, allow *proxy.Allowlist, file string) ([]binding, error) {
	var out []binding
	bound := map[string]int{} // the line that bound each host and header
	for _, s := range p.Secret {
		at := fmt.Sprintf("%s:%d: secret %q", file, s.Line, s.Name)
		rule, err := proxy.NewTerminateRule(s.Host, s.Header, s.Method, s.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		pair := rule.Host + " " + rule.Header
		switch {
		case allow == nil || !slices.Contains(allow.TLSHosts(), rule.Host):
			return nil, fmt.Errorf("%s: host %q is not a bare name in [network] allow", at, s.Host)
		case bound[pair] != 0:
			return nil, fmt.Errorf("%s: header %s on %s is already bound on line %d", at, rule.Header, rule.Host, bound[pair])
		case s.Env != "" && !envName.MatchString(s.Env):
			return nil, fmt.Errorf("%s: env %q is not a variable name", at, s.Env)
		}
		bound[pair] = s.Line
		out = append(out, binding{grant: secret.Grant{Name: s.Name, Source: s.Source, Host: rule.Host, Header: rule.Header}, rule: rule, env: s.Env})
	}
	return out, nil
}

// allowlist turns the policy's allow entries into the proxy's allowlist, nil for none. A bare
// name is port 443 by SNI; "name:port" forwards that one port to the name. The proxy's parser
// judges each entry (A3), and an entry it refuses is reported with its line (or as --allow, for
// an entry of that flag), a port two names claim with the line of the second.
func allowlist(p policy.Policy, file string) (*proxy.Allowlist, error) {
	if len(p.Allow) == 0 {
		return nil, nil
	}
	var all []string
	first := map[uint16]string{} // the entry that opened each forward port
	for _, e := range p.Allow {
		at := "--allow"
		if e.Line > 0 {
			at = fmt.Sprintf("%s:%d", file, e.Line)
		}
		if e.Text == "" || strings.ContainsAny(e.Text, " \t#") {
			return nil, fmt.Errorf("%s has an invalid endpoint: %q (want a host name, or host:port)", at, e.Text)
		}
		text := e.Text
		if !strings.Contains(text, ":") {
			text += ":443"
		}
		one, err := proxy.ParseAllowlist(text, at)
		if err != nil {
			return nil, err
		}
		for _, port := range one.Ports() {
			if port == 443 {
				continue
			}
			if prev, ok := first[port]; ok {
				if _, err := proxy.ParseAllowlist(prev+"\n"+text, at); err != nil {
					return nil, err
				}
			} else {
				first[port] = text
			}
		}
		all = append(all, text)
	}
	return proxy.ParseAllowlist(strings.Join(all, "\n"), file)
}
