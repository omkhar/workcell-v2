// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package provider holds what Workcell knows about each coding-agent CLI, as one TOML data
// file per provider, compiled in: the hosts it must reach, the API-key credentials it reads
// and how, and how it is installed. Adding a provider is one file here and no Go code. The CLI
// is guest content (A10): its version is a row of pins/, so no file names one. The files are
// read with the policy reader, the product's only TOML reader.
package provider

import (
	"cmp"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/proxy"
)

//go:embed *.toml
var files embed.FS

// Provider is one data file.
type Provider struct {
	Name, Binary string   // the provider's name, and the CLI's executable in the guest
	Hosts        []string // bare DNS names the CLI must reach, terminated at 443 like [network] allow
	Install      Install
	Secrets      []Secret
}

// Install says where the artifact comes from: Method "binary" is the pin of that name in pins/;
// "npm" is the package, whose pin is found by it. Neither holds a version.
type Install struct{ Method, Pin, Package string }

// Secret is an API-key credential, shaped like a [[secret]] row of the policy without its
// source, which the user chooses. The CLI sends it in Header to Host, after Prefix ("" or
// "Bearer "). It reads the placeholder from the variable Env, or from File, a path under the
// guest home, in which JSON key Field holds it. Line is the row's.
type Secret struct {
	Name, Host, Header, Prefix, Env, File, Field string
	Line                                         int
}

var (
	nameRE   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	binaryRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	pkgRE    = regexp.MustCompile(`^(@[a-z0-9-]+/)?[a-z0-9-]+$`) // a name; "@1.2.3" or ".2" is a version
	headerRE = regexp.MustCompile(`^[a-z0-9-]+$`)
	envRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`) // as cmd/workcell's bindings takes it
)

// All is the providers compiled into the binary, by name.
var All = sync.OnceValues(func() ([]Provider, error) { return Load(files) })

// Lookup is the compiled-in provider of the name.
func Lookup(name string) (Provider, bool) {
	all, _ := All()
	i := slices.IndexFunc(all, func(p Provider) bool { return p.Name == name })
	if i < 0 {
		return Provider{}, false
	}
	return all[i], true
}

// Load reads every *.toml of the root of fsys, in name order. A file is named for its provider.
// Any fault refuses the whole set, as "file:line: what".
func Load(fsys fs.FS) ([]Provider, error) {
	names, err := fs.Glob(fsys, "*.toml")
	if err != nil {
		return nil, err
	}
	var out []Provider
	for _, file := range names {
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		p, err := parse(string(b), file)
		if err != nil {
			return nil, err
		}
		if want := strings.TrimSuffix(file, ".toml"); p.Name != want {
			return nil, fmt.Errorf("%s:1: provider name %q is not the file's name %q", file, p.Name, want)
		}
		out = append(out, p)
	}
	return out, nil
}

// parse reads and checks one file.
func parse(text, file string) (Provider, error) {
	tables, err := policy.Tables(text, file)
	if err != nil {
		return Provider{}, err
	}
	var p Provider
	seen := map[string]int{}
	bound := map[string]int{} // the line that bound each host and header
	for _, t := range tables {
		fail := func(line int, format string, args ...any) error {
			return fmt.Errorf("%s:%d: %s", file, line, fmt.Sprintf(format, args...))
		}
		if seen[t.Name] != 0 && t.Name != "secret" {
			return Provider{}, fail(t.Line, "table [%s] is defined twice, first on line %d", t.Name, seen[t.Name])
		}
		seen[t.Name] = t.Line
		switch want := map[string][]string{"provider": {"name", "binary", "hosts"}, "install": {"method"}, "secret": {"name", "host", "header"}}[t.Name]; {
		case want == nil:
			return Provider{}, fail(t.Line, "table [%s] is not one of provider, install, secret", t.Name)
		case t.Array != (t.Name == "secret"):
			return Provider{}, fail(t.Line, "[%s] is the wrong kind of table", t.Name)
		default:
			if err := checkKeys(t, file, want, map[string][]string{"install": {"pin", "package"}, "secret": {"prefix", "env", "file", "field"}}[t.Name]); err != nil {
				return Provider{}, err
			}
		}
		k := func(key string) string { return t.Keys[key].Str }
		var bad string
		switch t.Name {
		case "provider":
			p.Name, p.Binary = k("name"), k("binary")
			for _, h := range t.Keys["hosts"].Strs {
				if err := bareHost(h.Text); err != nil {
					return Provider{}, fail(h.Line, "hosts: %v", err)
				}
				p.Hosts = append(p.Hosts, h.Text)
			}
			switch {
			case !nameRE.MatchString(p.Name):
				bad = "name must be lower-case letters, digits and -"
			case !binaryRE.MatchString(p.Binary):
				bad = "binary must be an executable's name, not a path"
			case len(p.Hosts) == 0:
				bad = "hosts is empty"
			}
		case "install":
			p.Install = Install{k("method"), k("pin"), k("package")}
			switch in := p.Install; {
			case in.Method == "binary" && (in.Package != "" || !nameRE.MatchString(in.Pin)):
				bad = "method binary wants a pin (a name in pins/, no version) and no package"
			case in.Method == "npm" && (in.Pin != "" || !pkgRE.MatchString(in.Package)):
				bad = "method npm wants a package (a name, no version: versions live in pins/) and no pin"
			case in.Method != "binary" && in.Method != "npm":
				bad = "method must be binary or npm"
			}
		case "secret":
			s := Secret{k("name"), k("host"), k("header"), k("prefix"), k("env"), k("file"), k("field"), t.Line}
			pair := s.Host + " " + s.Header
			switch {
			case bareHost(s.Host) != nil:
				bad = fmt.Sprintf("host: %v", bareHost(s.Host))
			case !headerRE.MatchString(s.Header):
				bad = fmt.Sprintf("header %q must be lower-case letters, digits and -", s.Header)
			case bound[pair] != 0:
				bad = fmt.Sprintf("header %s on %s is already bound on line %d", s.Header, s.Host, bound[pair])
			case s.Prefix != "" && s.Prefix != "Bearer ":
				bad = `prefix must be "" or "Bearer "`
			case s.Env != "" && !envRE.MatchString(s.Env):
				bad = fmt.Sprintf("env %q is not a variable name", s.Env)
			case s.Env == "" && s.File == "":
				bad = "needs an env or a file to carry the placeholder"
			case (s.File == "") != (s.Field == ""):
				bad = "file and field go together"
			case s.File != "" && (!fs.ValidPath(s.File) || s.File == "."):
				bad = fmt.Sprintf("file %q must be a clean path under the guest home, with no .. and not absolute", s.File)
			}
			bound[pair] = t.Line
			p.Secrets = append(p.Secrets, s)
		}
		if bad != "" {
			return Provider{}, fail(t.Line, "[%s]: %s", t.Name, bad)
		}
	}
	for _, s := range p.Secrets {
		if !slices.Contains(p.Hosts, s.Host) {
			return Provider{}, fmt.Errorf("%s:%d: secret %q host %s is not one of the provider's hosts", file, s.Line, s.Name, s.Host)
		}
	}
	if seen["provider"] == 0 || seen["install"] == 0 {
		return Provider{}, fmt.Errorf("%s:1: needs a [provider] and an [install] table", file)
	}
	return p, nil
}

// checkKeys refuses a key that is neither required nor optional, a required key left out, and a
// key of the wrong kind: hosts is an array of strings, every other key a string.
func checkKeys(t policy.Table, file string, required, optional []string) error {
	keys := make([]string, 0, len(t.Keys))
	for k := range t.Keys {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Compare(t.Keys[a].Line, t.Keys[b].Line) })
	for _, k := range keys {
		switch f := t.Keys[k]; {
		case !slices.Contains(required, k) && !slices.Contains(optional, k):
			return fmt.Errorf("%s:%d: unknown key %q in [%s]", file, f.Line, k, t.Name)
		case f.Int || f.List != (k == "hosts"):
			return fmt.Errorf("%s:%d: %s must be %s", file, f.Line, k, map[bool]string{true: "an array of strings", false: "a string"}[k == "hosts"])
		}
	}
	for _, k := range required {
		if f := t.Keys[k]; f.Str == "" && len(f.Strs) == 0 {
			return fmt.Errorf("%s:%d: [%s] needs a %s", file, t.Line, t.Name, k)
		}
	}
	return nil
}

// bareHost refuses what [network] allow would not take as a bare name: anything but a lower-case
// DNS name, so no port, scheme, path or IP literal. The proxy's allowlist is the judge of the name.
func bareHost(h string) error {
	if h != strings.ToLower(h) || strings.HasSuffix(h, ".") || strings.ContainsAny(h, ":/@ \t#") {
		return fmt.Errorf("%q is not a bare lower-case DNS name", h)
	}
	_, err := proxy.ParseAllowlist(h+":443", "provider")
	return err
}
