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
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/provider"
	"github.com/omkhar/workcell/v2/internal/proxy"
	"github.com/omkhar/workcell/v2/internal/secret"
)

// configFile is the policy file, $XDG_CONFIG_HOME/workcell/config.toml or ~/.config/workcell/config.toml, which may not exist.
func configFile() (string, error) {
	dir, err := xdgDir("XDG_CONFIG_HOME", ".config")
	return filepath.Join(dir, "config.toml"), err
}

const repoFile = "workcell.toml" // the policy a repository may carry, in the directory a session starts in

// loadPolicy reads the policy and builds what a session needs from it: the proxy's allowlist (nil: nothing is relayed) and the secret bindings. The user's file is narrowed by the workcell.toml of the current directory, which may take grants away and give none (I13), then this session's --allow entries are added (the operator typed them on the host, and the repository may not undo that). A repository file that is not a regular file is ignored, with a line on stderr. An error names the file and line, or the flag; note is a line for `explain` about what the repository file took away.
func loadPolicy(extra []string, stderr io.Writer) (allow *proxy.Allowlist, secrets []binding, note, file string, err error) {
	if file, err = configFile(); err != nil {
		return nil, nil, "", "", err
	}
	p, err := policy.Read(file)
	if err != nil {
		return nil, nil, "", "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, "", "", err
	}
	repo, err := policy.ReadRepo(repoFile) // this process's own directory, by identity: its error names the file alone, not the directory's spelling, which the guest may have chosen (C61, C62)
	if errors.Is(err, policy.ErrNotRegular) {
		fmt.Fprintf(stderr, "workcell: %v: ignored, a policy file must be a regular file\n", err)
		repo, err = policy.Policy{}, nil
	}
	if err != nil {
		return nil, nil, "", "", err
	}
	narrowed, asked := policy.Narrow(p, repo)
	asked = slices.DeleteFunc(asked, func(s string) bool {
		return slices.ContainsFunc(extra, func(x string) bool { return strconv.Quote(x) == s })
	})
	switch { // the line `explain` adds about the repository's file, "" when it changed nothing
	case len(asked) > 0:
		note = repoFile + " asks for " + strings.Join(asked, ", ") + ": not granted; allow it in " + file + " or with --allow\n"
	case len(narrowed.Allow) < len(p.Allow) || len(narrowed.Secret) < len(p.Secret):
		note = repoFile + " narrows the policy of " + file + "\n"
	}
	for _, text := range extra {
		narrowed.Allow = append(narrowed.Allow, policy.Entry{Text: text}) // line 0: it comes from a flag
	}
	if allow, err = allowlist(narrowed, file); err != nil {
		return nil, nil, "", "", err
	}
	for _, s := range p.Secret { // a dropped sign-in row whose token host stays would hand the guest the real tokens of a sign-in made there (I5)
		if si, err := proxy.NewSignIn(s.Source); err == nil && allow != nil && slices.Contains(allow.TLSHosts(), si.Host) && !slices.ContainsFunc(narrowed.Secret, func(n policy.Secret) bool { return n.Line == s.Line }) {
			return nil, nil, "", "", fmt.Errorf("%s:%d: secret %q: %s drops this sign-in row but keeps its token host %q: name the row there, or drop the host", file, s.Line, s.Name, repoFile, si.Host)
		}
	}
	data, err := dataDir()
	if err == nil {
		secrets, err = bindings(narrowed, allow, file)
	}
	for _, s := range p.Secret { // the user's rows, whatever workcell.toml kept (I13, C58): the one path the host opens or runs, a file: path or the program of a cmd: source, is judged as the kernel walks it, since a prefix in cwd (the guest's under --mount) or in the data directory lets the guest serve the key or swap the program, and a key in cwd goes into the export (I5, C54). What a program reads through its arguments is its own (ADR-006, SPEC section 2).
		scheme, _, _ := strings.Cut(s.Source, ":")
		at, path := fmt.Sprintf("%s:%d: secret %q: source %s", file, s.Line, s.Name, s.Source), sourcePath(s.Source)
		switch {
		case err != nil:
		case !slices.Contains([]string{"file", "cmd", "secret-service", "keychain", "signin"}, scheme):
			err = fmt.Errorf("%s: the scheme %q is not file, cmd, secret-service, keychain or signin", at, scheme)
		case scheme != "file" && scheme != "cmd": // the other schemes name no path
		case !filepath.IsAbs(path):
			err = fmt.Errorf("%s: %q is not an absolute path, and the broker reads a file: path or runs a cmd: program from no directory", at, path)
		case leadsInto(path, cwd, data):
			err = fmt.Errorf("%s: %s lies inside the directory %q, which the guest gets as /workspace, or inside workcell's data directory %s, or a prefix of it leads into one: keep it outside", at, path, cwd, data)
		case scheme == "file": // one regular file with one name, by Stat so that a FIFO does not hang the load: a hard link's other name may lie where the guest writes, as holds() refuses for config.toml; a program is not held to one name, since a store such as Nix hard-links binaries
			if fi, e := os.Stat(path); e != nil {
				err = fmt.Errorf("%s: %w", at, e)
			} else if n := fi.Sys().(*syscall.Stat_t).Nlink; !fi.Mode().IsRegular() || n > 1 {
				err = fmt.Errorf("%s: %s must be a regular file with one name: it has mode %v and %d names", at, path, fi.Mode(), n)
			}
		}
	}
	return allow, secrets, note, file, err
}

// sourcePath is the one path the host opens or runs for a [[secret]] source: a file: path, or the program of a cmd: source as Resolve splits argv; "" for a scheme that names none. loadPolicy judges it against the working directory and holds against a pull's destination, so the two never diverge (C54, C93).
func sourcePath(source string) string {
	scheme, rest, _ := strings.Cut(source, ":")
	return map[string]string{"file": rest, "cmd": append(strings.Fields(rest), "")[0]}[scheme]
}

// binding is one [[secret]] row ready for a session: the grant the broker releases, the rule the proxy swaps by, holding the placeholder minted here, and the guest variable that carries the placeholder, "" for none. The value itself is read by the broker, per use, on the host (I5).
type binding struct {
	grant secret.Grant
	rule  proxy.TerminateRule
	env   string
}

// placeholderEnv is the guest's variables that carry placeholders, one per binding with an env: the only form of a secret the guest ever holds (A4).
func placeholderEnv(secrets []binding) (env []string) {
	for _, s := range secrets {
		if s.env != "" {
			env = append(env, s.env+"="+s.rule.Placeholder)
		}
	}
	return env
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`) // a variable name as the guest's environment takes it

// bindings turns the policy's [[secret]] rows into the session's bindings, one fresh placeholder each. The proxy judges host, header, path and repos (A3); the host must then be a bare name of the allow list, so that the proxy terminates it and swaps there (I6), as must the host of a sign-in source, and env must be a variable name. Two rows on one header of one host, or on one token endpoint, are refused by the proxy. A row with a name and source but no host and no header takes them, and env unless it gives one, from the provider secret of that name: a convenience that grants nothing, since the host must still be in the allow list (I13); the provider's prefix needs no rule, as the proxy keeps a "Bearer " the guest sends before the placeholder. A fault is reported with its line.
func bindings(p policy.Policy, allow *proxy.Allowlist, file string) ([]binding, error) {
	var out []binding
	for _, s := range p.Secret {
		at := fmt.Sprintf("%s:%d: secret %q", file, s.Line, s.Name)
		if s.Host == "" && s.Header == "" {
			if d, _, ok := provider.FindSecret(s.Name); ok {
				s.Host, s.Header = d.Host, d.Header
				if s.Env == "" {
					s.Env = d.Env
				}
			}
		}
		if s.Host == "" || s.Header == "" {
			return nil, fmt.Errorf("%s: host and header are missing: name a provider's secret or give host and header", at)
		}
		rule, err := proxy.NewTerminateRule(s.Host, s.Header, s.Path, s.Repos)
		if err == nil && strings.HasPrefix(s.Source, "signin:") {
			rule.SignIn, err = proxy.NewSignIn(s.Source)
			if err == nil && len(s.Repos) > 0 {
				err = errors.New("repos cannot narrow a sign-in source")
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		switch {
		case allow == nil || !slices.Contains(allow.TLSHosts(), rule.Host):
			return nil, fmt.Errorf("%s: host %q is not a bare name in [network] allow: add %q there, or pass --allow %s", at, s.Host, rule.Host, rule.Host)
		case rule.SignIn != nil && !slices.Contains(allow.TLSHosts(), rule.SignIn.Host):
			return nil, fmt.Errorf("%s: sign-in host %q is not a bare name in [network] allow", at, rule.SignIn.Host)
		case s.Env != "" && !envName.MatchString(s.Env):
			return nil, fmt.Errorf("%s: env %q is not a variable name", at, s.Env)
		}
		out = append(out, binding{grant: secret.Grant{Name: s.Name, Source: s.Source, Host: rule.Host, Header: rule.Header}, rule: rule, env: s.Env})
	}
	return out, nil
}

// allowlist turns the policy's allow entries into the proxy's allowlist, nil for none. A bare name is port 443 by SNI; "name:port" forwards that port. The proxy's parser judges the entries as each joins (A3): one it refuses is reported with its line (or as --allow), a claimed port with the second's.
func allowlist(p policy.Policy, file string) (*proxy.Allowlist, error) {
	if len(p.Allow) == 0 {
		return nil, nil
	}
	var all []string
	for _, e := range p.Allow {
		at := "--allow"
		if e.Line > 0 {
			at = fmt.Sprintf("%s:%d", file, e.Line)
		}
		if e.Text == "" || strings.ContainsFunc(e.Text, unicode.IsSpace) || strings.Contains(e.Text, "#") {
			return nil, fmt.Errorf("%s has an invalid endpoint: %q (want a host name, or host:port)", at, e.Text)
		}
		text := e.Text
		if !strings.Contains(text, ":") {
			text += ":443"
		}
		all = append(all, text)
		if _, err := proxy.ParseAllowlist(strings.Join(all, "\n"), at); err != nil { // what this entry adds, named for it
			return nil, err
		}
	}
	return proxy.ParseAllowlist(strings.Join(all, "\n"), file)
}
