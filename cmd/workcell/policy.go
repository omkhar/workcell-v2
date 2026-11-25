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

// sep says whether r, read from a word of a cmd: source, begins or ends a path there: every ASCII byte that is not a letter, a digit, '.', '_', '-' or '/'. A byte of 0x80 or above is part of a name, so no cut falls inside a UTF-8 rune.
func sep(r rune) bool {
	return r < 0x80 && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._-/", r)
}

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
	secrets, err = bindings(narrowed, allow, file)
	for _, s := range p.Secret { // a file: or cmd: source under cwd would be exported into, or served live as, the guest's /workspace, whether or not the repository kept the row (I5)
		scheme, rest, _ := strings.Cut(s.Source, ":") // cmd: the words are the program and each argument, split as the broker splits them (it runs the program from /, so a relative one never means cwd); file: the path, one word; the other schemes name no path
		words := strings.FieldsFunc(rest, func(r rune) bool { return scheme == "cmd" && unicode.IsSpace(r) })
		for _, w := range words { // a word is judged from its first slash on, so a path inside an option word, --key=/x or -k/x, is judged as /x (C72); a relative a/b is judged as /b, and refused when that lies in cwd
			if err == nil && (scheme == "file" || scheme == "cmd") && strings.ContainsAny(w, "~$`\\'\"*?[{") { // this check reads literal paths only: a shell the helper runs rewrites these in a word (a home, a variable or substitution, an escape or quote pair, a glob, a brace), so such a word can spell a path under cwd that no reading of its text finds (C78)
				return nil, nil, "", "", fmt.Errorf("%s:%d: secret %q: word %s holds one of ~ $ ` \\ ' \" * ? [ {, which a shell rewrites, and this check reads literal paths only: spell the path out, or put the line in a script outside the directory %q, which the guest gets as /workspace", file, s.Line, s.Name, w, cwd)
			}
			for i := 0; i < len(w); i += 1 + strings.IndexFunc(w[i:]+":", sep) { // and so is the text from the first slash after each separator of a list word, --files=/a:/b, to the word's end: cwd itself may hold a separator, so the word is never split
				p := w[i+max(strings.IndexByte(w[i:], '/'), 0):]
				for j := len(p); err == nil && (scheme == "file" || scheme == "cmd") && filepath.IsAbs(p) && j > 0; j-- { // the spelling, each prefix that ends before a slash (its lexical ancestors) and, under cmd:, each that ends before a separator (C75), resolved: under --mount the guest may replace any of them
					if (j == len(p) || p[j] == '/' || scheme == "cmd" && sep(rune(p[j]))) && within(cwd, p[:j]) {
						return nil, nil, "", "", fmt.Errorf("%s:%d: secret %q: source %s lies inside the directory %q, which the guest gets as /workspace: keep it outside", file, s.Line, s.Name, p, cwd)
					}
				}
			}
		}
	}
	return allow, secrets, note, file, err
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

// bindings turns the policy's [[secret]] rows into the session's bindings, one fresh placeholder each. The proxy judges host, header, method, path and repos (A3); the host must then be a bare name of the allow list, so that the proxy terminates it and swaps there (I6), as must the host of a sign-in source, and env must be a variable name. Two rows on one header of one host, or on one token endpoint, are refused by the proxy. A row with a name and source but no host and no header takes them, and env unless it gives one, from the provider secret of that name: a convenience that grants nothing, since the host must still be in the allow list (I13); the provider's prefix needs no rule, as the proxy keeps a "Bearer " the guest sends before the placeholder. A fault is reported with its line.
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
