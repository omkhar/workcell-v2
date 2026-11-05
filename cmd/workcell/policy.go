// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/provider"
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

// repoFile is the policy a repository may carry, in the directory a session starts in.
const repoFile = "workcell.toml"

// loadPolicy reads the policy and builds what a session needs from it: the proxy's allowlist,
// and the secret bindings. The user's file is narrowed by the workcell.toml of the current directory,
// which may take grants away and give none (I13); then the entries of this session's --allow flags are
// added (I13: the operator typed them on the host, and the repository may not undo that). A
// repository file that is not a regular file is ignored, with a line on stderr. A nil allowlist means
// the policy allows nothing: no TCP port is relayed. An error names the file and line, or the flag.
// note is a line for `explain` about what the repository file took away or asked for in vain, "" for none.
func loadPolicy(extra []string, stderr io.Writer) (allow *proxy.Allowlist, secrets []binding, note string, err error) {
	file, err := configFile()
	if err != nil {
		return nil, nil, "", err
	}
	p, err := policy.Read(file)
	if err != nil {
		return nil, nil, "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, "", err
	}
	repo, err := policy.ReadRepo(filepath.Join(cwd, repoFile))
	if errors.Is(err, policy.ErrNotRegular) {
		fmt.Fprintf(stderr, "workcell: %v: ignored, a policy file must be a regular file\n", err)
		repo, err = policy.Policy{}, nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	narrowed, asked := policy.Narrow(p, repo)
	asked = slices.DeleteFunc(asked, func(s string) bool { return slices.Contains(extra, s) })
	note = repoNote(asked, len(narrowed.Allow) < len(p.Allow) || len(narrowed.Secret) < len(p.Secret), file)
	p = narrowed
	for _, text := range extra {
		p.Allow = append(p.Allow, policy.Entry{Text: text}) // line 0: it comes from a flag
	}
	if allow, err = allowlist(p, file); err != nil {
		return nil, nil, "", err
	}
	secrets, err = bindings(p, allow, file)
	return allow, secrets, note, err
}

// repoNote is the line `explain` adds about the repository's workcell.toml, "" when it changed nothing.
func repoNote(asked []string, narrowed bool, file string) string {
	switch {
	case len(asked) > 0:
		return repoFile + " asks for " + strings.Join(asked, ", ") + ": not granted; allow it in " + file + " or with --allow\n"
	case narrowed:
		return repoFile + " narrows the policy of " + file + "\n"
	}
	return ""
}

// binding is one [[secret]] row ready for a session: the grant the broker releases, the rule
// the proxy swaps by, holding the placeholder minted here, and the guest variable that carries
// the placeholder, "" for none, and the provider whose defaults filled the row, "" for none. The
// value itself is read by the broker, per use, on the host (I5).
type binding struct {
	grant  secret.Grant
	rule   proxy.TerminateRule
	env    string
	serves string
}

// placeholderEnv is the guest's variables that carry placeholders, one per binding with an env:
// the only form of a secret the guest ever holds (A4).
func placeholderEnv(secrets []binding) (env []string) {
	for _, s := range secrets {
		if s.env != "" {
			env = append(env, s.env+"="+s.rule.Placeholder)
		}
	}
	return env
}

// envName is a variable name as the guest's environment takes it.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// bindings turns the policy's [[secret]] rows into the session's bindings, one fresh placeholder
// each. The proxy judges host, header, method, path and repos (A3); the host must then be a bare name
// of the allow list, so that the proxy terminates it and swaps there (I6), as must the host of a
// sign-in source; no two rows may bind one header on one host, or one token endpoint; and env
// must be a variable name. A row that gives a name and source but no host and no header takes
// them, and env unless it gives one, from the provider secret of that name: a convenience that
// grants nothing, since the host must still be in the allow list (I13). The provider's prefix
// needs no rule: the proxy keeps a "Bearer " the guest sends before the placeholder. A fault is
// reported with its line.
func bindings(p policy.Policy, allow *proxy.Allowlist, file string) ([]binding, error) {
	var out []binding
	bound := map[string]int{} // the line that bound each host and header, and each token endpoint
	for _, s := range p.Secret {
		at := fmt.Sprintf("%s:%d: secret %q", file, s.Line, s.Name)
		serves := ""
		if s.Host == "" && s.Header == "" {
			if d, prov, ok := provider.FindSecret(s.Name); ok {
				s.Host, s.Header, serves = d.Host, d.Header, prov.Name
				if s.Env == "" {
					s.Env = d.Env
				}
			}
		}
		if s.Host == "" || s.Header == "" {
			return nil, fmt.Errorf("%s: host and header are missing: name a provider's secret or give host and header", at)
		}
		rule, err := proxy.NewTerminateRule(s.Host, s.Header, s.Method, s.Path, s.Repos)
		if err == nil && strings.HasPrefix(s.Source, "signin:") {
			rule.SignIn, err = proxy.NewSignIn(s.Source)
			if err == nil && len(s.Repos) > 0 {
				err = errors.New("repos cannot narrow a sign-in source")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		pair, endpoint := rule.Host+" "+rule.Header, ""
		if rule.SignIn != nil {
			endpoint = rule.SignIn.Host + rule.SignIn.Path
		}
		switch {
		case allow == nil || !slices.Contains(allow.TLSHosts(), rule.Host):
			return nil, fmt.Errorf("%s: host %q is not a bare name in [network] allow: add %q there, or pass --allow %s", at, s.Host, rule.Host, rule.Host)
		case bound[pair] != 0:
			return nil, fmt.Errorf("%s: header %s on %s is already bound on line %d", at, rule.Header, rule.Host, bound[pair])
		case endpoint != "" && !slices.Contains(allow.TLSHosts(), rule.SignIn.Host):
			return nil, fmt.Errorf("%s: sign-in host %q is not a bare name in [network] allow", at, rule.SignIn.Host)
		case endpoint != "" && bound[endpoint] != 0:
			return nil, fmt.Errorf("%s: token endpoint %s is already bound on line %d", at, endpoint, bound[endpoint])
		case s.Env != "" && !envName.MatchString(s.Env):
			return nil, fmt.Errorf("%s: env %q is not a variable name", at, s.Env)
		}
		bound[pair] = s.Line
		if endpoint != "" {
			bound[endpoint] = s.Line
		}
		out = append(out, binding{grant: secret.Grant{Name: s.Name, Source: s.Source, Host: rule.Host, Header: rule.Header}, rule: rule, env: s.Env, serves: serves})
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
