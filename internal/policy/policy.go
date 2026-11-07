// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package policy reads the session policy of SPEC section 5, ~/.config/workcell/config.toml.
// The file is TOML, but only the subset the specification shows: tables [name] and [[name]],
// bare keys, basic double-quoted strings, integers, arrays of strings and # comments. The
// reader is the package's own, so that no module sits on the trust path: ReadRepo reads a
// repository-controlled workcell.toml with it (I13), which is why it is fuzzed (T5). Anything
// outside the subset is refused with the line it stands on.
package policy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/omkhar/workcell/v2/internal/pins"
)

// maxBytes bounds a policy file; the standard allowlist limit, far above any real policy.
const maxBytes = 1 << 20

// Policy is what the file grants, as far as this build reads it.
type Policy struct {
	// Allow is the allow array of the [network] table: each entry a bare DNS name, which means
	// port 443 by SNI, or "name:port", with the line it stands on. The entries are checked by
	// the proxy's allowlist, not here. Nothing allowed means no TCP port is relayed.
	Allow []Entry
	// AllowSet is whether the file has an allow array, even an empty one: for a repository's file
	// that is the difference between narrowing the network to nothing and not speaking of it.
	AllowSet bool
	// Secret is the [[secret]] rows, in file order. Each is checked by the proxy and the
	// broker, not here, beyond what the file must say.
	Secret []Secret
	// Update is the [update] table, the user's alone: ReadRepo refuses a file that carries it (I13).
	Update Update
}

// Update is the [update] table (SPEC B10): Channel "stable", "hold" or an https URL, "" when left
// out; Cooloff, more wait than the project's; CA, the path of a PEM file whose certificates alone
// are trusted; Key, the one public key trusted, nil for the built-in keys; Line, the table's, 0 for none.
type Update struct {
	Channel, CA string
	Cooloff     time.Duration
	Key         []byte
	Line        int
}

// Secret is one [[secret]] row: the secret Name, read on the host from Source, is sent only
// in Header to Host (both "" when a provider's secret of that name is to fill them in). Env names
// the guest variable that carries its placeholder, Method and Path narrow the swap to requests of
// that method under that path prefix; each is "" when the row leaves it out. Repos is the repos
// array, the git repositories "owner/name" the swap is narrowed to instead; nil when left out.
// Line is the row's, for an error that names it.
type Secret struct {
	Name, Source, Host, Header, Env, Method, Path string
	Repos                                         []string
	Line                                          int
}

// Entry is one string of an array and the line it stands on, for an error that names it.
type Entry struct {
	Text string
	Line int
}

// Read reads the policy file at path. A file that does not exist grants nothing.
func Read(path string) (Policy, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()
	return readAll(f, path)
}

// ErrNotRegular is what ReadRepo says of a symbolic link, a pipe, a directory or any other thing but a file.
var ErrNotRegular = errors.New("not a regular file")

// ReadRepo reads a repository's workcell.toml, the bytes of which the guest may have written (R6):
// the last name is opened without following a link and without waiting for a writer, and only a regular
// file is read. A file that does not exist is an empty policy; anything else that is not a regular file
// is ErrNotRegular, never opened for reading.
func ReadRepo(path string) (Policy, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Policy{}, nil
	case errors.Is(err, syscall.ELOOP):
		return Policy{}, fmt.Errorf("%s: %w (a symbolic link)", path, ErrNotRegular)
	case err != nil:
		return Policy{}, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	p, err := readAll(f, path)
	if err == nil && p.Update.Line != 0 {
		err = fmt.Errorf("%s:%d: [update] is the user's table: a repository's file may not carry it", path, p.Update.Line)
	}
	return p, err
}

func readAll(f *os.File, path string) (Policy, error) {
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(b) > maxBytes {
		return Policy{}, fmt.Errorf("%s: larger than %d bytes", path, maxBytes)
	}
	return Parse(string(b), path)
}

// Narrow is the user's policy as a repository's file leaves it (I13): that file can take grants away
// and give none. With an allow array, only the user's entries it names, with exactly the same text, stay, and a secret whose host that drops goes too;
// with [[secret]] rows, only the user's rows whose name a row of it names stay, as the user wrote them. Of a
// repository's row only the name is read. [workspace] and [resources] are not read. What the
// repository asked for that the user did not grant comes back as asked: a host or a secret's name, each quoted.
func Narrow(user, repo Policy) (got Policy, asked []string) {
	got = user
	if repo.AllowSet {
		got.Allow, asked = keep(user.Allow, repo.Allow, func(e Entry) string { return e.Text }, "")
	}
	if len(repo.Secret) > 0 {
		var more []string
		got.Secret, more = keep(user.Secret, repo.Secret, func(s Secret) string { return s.Name }, "secret ")
		asked = append(asked, more...)
	}
	if repo.AllowSet { // a secret goes with its host when the host is narrowed away
		has := func(es []Entry, h string) bool {
			return slices.ContainsFunc(es, func(e Entry) bool { return e.Text == h })
		}
		got.Secret = slices.DeleteFunc(slices.Clone(got.Secret), func(s Secret) bool { return has(user.Allow, s.Host) && !has(got.Allow, s.Host) })
	}
	return got, asked
}

// keep is the user's entries whose key a repository's entry has, and, each quoted after what, the
// keys the repository has that the user lacks.
func keep[T any](user, repo []T, key func(T) string, what string) (kept []T, asked []string) {
	has := func(es []T, k string) bool { return slices.ContainsFunc(es, func(e T) bool { return key(e) == k }) }
	for _, u := range user {
		if has(repo, key(u)) {
			kept = append(kept, u)
		}
	}
	for _, r := range repo {
		if !has(user, key(r)) {
			asked = append(asked, what+strconv.Quote(key(r)))
		}
	}
	return kept, asked
}

// tables are the tables SPEC section 5 names, and whether each is an array of tables; [workspace] and [resources] are read past.
var tables = map[string]bool{"network": false, "secret": true, "workspace": false, "resources": false, "update": false}

// Parse reads the policy in text; name labels the file in errors, as "name:line: what".
func Parse(text, name string) (Policy, error) {
	doc, err := parse(text)
	if err != nil {
		return Policy{}, fmt.Errorf("%s:%d: %s", name, err.line, err.msg)
	}
	var p Policy
	first := map[string]int{} // the line of each single table seen
	for _, t := range doc {
		array, known := tables[t.Name]
		switch {
		case !known:
			return Policy{}, fmt.Errorf("%s:%d: table [%s] is not one of network, secret, workspace, resources, update", name, t.Line, t.Name)
		case array && !t.Array:
			return Policy{}, fmt.Errorf("%s:%d: [%s] is an array of tables: write [[%s]]", name, t.Line, t.Name, t.Name)
		case !array && t.Array:
			return Policy{}, fmt.Errorf("%s:%d: [[%s]] is a table: write [%s]", name, t.Line, t.Name, t.Name)
		case !array && first[t.Name] != 0:
			return Policy{}, fmt.Errorf("%s:%d: table [%s] is defined twice, first on line %d", name, t.Line, t.Name, first[t.Name])
		}
		first[t.Name] = t.Line
		switch t.Name {
		case "network":
			for key, v := range t.Keys {
				if key != "allow" {
					return Policy{}, fmt.Errorf("%s:%d: unknown key %q in [network]: allow is the only one", name, v.Line, key)
				}
				if !v.List {
					return Policy{}, fmt.Errorf("%s:%d: allow must be an array of strings", name, v.Line)
				}
				p.Allow, p.AllowSet = v.Strs, true
			}
		case "secret":
			s, err := secretRow(t, name)
			if err != nil {
				return Policy{}, err
			}
			p.Secret = append(p.Secret, s)
		case "update":
			if err := updateTable(t, name, &p.Update); err != nil {
				return Policy{}, err
			}
		}
	}
	return p, nil
}

// updateTable reads the [update] table: channel, "stable", "hold" or an https URL; cooloff, a
// duration that is not negative; ca, a path; key, 64 hex characters; each a string, each optional,
// and nothing else.
func updateTable(t Table, name string, u *Update) error {
	u.Line = t.Line
	for key, v := range t.Keys {
		var err error
		switch {
		case v.List || v.Int:
			err = errors.New("must be a string")
		case key == "channel":
			if u.Channel = v.Str; v.Str != "stable" && v.Str != "hold" && pins.HTTPSURL(v.Str) != nil {
				err = errors.New(`must be "stable", "hold" or an https URL`)
			}
		case key == "cooloff":
			if u.Cooloff, err = time.ParseDuration(v.Str); err == nil && u.Cooloff < 0 {
				err = errors.New("must not be negative")
			}
		case key == "ca":
			u.CA = v.Str
		case key == "key":
			if u.Key, err = hex.DecodeString(v.Str); err != nil || len(u.Key) != 32 {
				err = errors.New("must be 64 hex characters")
			}
		default:
			err = errors.New("is not one of channel, cooloff, ca and key")
		}
		if err != nil {
			return fmt.Errorf("%s:%d: [update] %s %v", name, v.Line, key, err)
		}
	}
	return nil
}

// Table is one [name] or [[name]] of a document, with its keys; the provider data files are read as Tables too (I13).
type Table struct {
	Name  string
	Line  int
	Array bool // [[name]]
	Keys  map[string]Field
}

// Field is a value of the subset: a string in Str, an array of strings in Strs (List), or an integer (Int).
type Field struct {
	Line      int
	Str       string
	Strs      []Entry
	List, Int bool
}

// Tables reads text as a document of any table names; name labels the file in errors.
func Tables(text, name string) ([]Table, error) {
	doc, err := parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s:%d: %s", name, err.line, err.msg)
	}
	return doc, nil
}

// secretRow reads one [[secret]] table: name and source, each a string, with host, header, env,
// method and path optional, repos an optional array of strings, and nothing else. An empty string
// or array is as good as no key. A row without host and header names a provider's secret, which
// supplies them (cmd/workcell).
func secretRow(t Table, name string) (Secret, error) {
	s := Secret{Line: t.Line}
	fields := map[string]*string{"name": &s.Name, "source": &s.Source, "host": &s.Host, "header": &s.Header, "env": &s.Env, "method": &s.Method, "path": &s.Path}
	for key, v := range t.Keys {
		if key == "repos" {
			if !v.List {
				return Secret{}, fmt.Errorf("%s:%d: repos must be an array of strings", name, v.Line)
			}
			for _, e := range v.Strs {
				s.Repos = append(s.Repos, e.Text)
			}
			continue
		}
		field, ok := fields[key]
		if !ok {
			return Secret{}, fmt.Errorf("%s:%d: unknown key %q in [[secret]]: name, source, host, header, env, method, path and repos are the keys", name, v.Line, key)
		}
		if v.List || v.Int {
			return Secret{}, fmt.Errorf("%s:%d: %s must be a string", name, v.Line, key)
		}
		*field = v.Str
	}
	for _, key := range []string{"name", "source"} {
		if *fields[key] == "" {
			return Secret{}, fmt.Errorf("%s:%d: [[secret]] needs a %s", name, t.Line, key)
		}
	}
	return s, nil
}

// A parse error carries the line it was found on.
type parseError struct {
	line int
	msg  string
}

// Tokens of the subset. A bare token is a key or an integer; the parser decides which.
type tokKind int

const (
	tEOF tokKind = iota
	tNewline
	tLBracket  // [
	tRBracket  // ]
	tLLBracket // [[
	tRRBracket // ]]
	tEqual
	tComma
	tString // text is the decoded string
	tBare   // text is the bare characters
)

type token struct {
	kind tokKind
	text string
	line int
}

func (t token) String() string {
	if t.kind == tBare {
		return strconv.Quote(t.text)
	}
	return [...]string{tEOF: "end of file", tNewline: "end of line", tString: "a string", tLBracket: `"["`, tRBracket: `"]"`, tLLBracket: `"[["`, tRRBracket: `"]]"`, tEqual: `"="`, tComma: `","`}[t.kind]
}

// scanner yields tokens from text, one at a time, with the line each begins on.
type scanner struct {
	s    string
	pos  int
	line int
}

func (sc *scanner) fail(format string, args ...any) *parseError {
	return &parseError{sc.line, fmt.Sprintf(format, args...)}
}

// next is the next token. Whitespace and comments are skipped; a newline is a token.
func (sc *scanner) next() (token, *parseError) {
	for sc.pos < len(sc.s) {
		c := sc.s[sc.pos]
		switch {
		case c == ' ' || c == '\t':
			sc.pos++
		case c == '\r' && sc.pos+1 < len(sc.s) && sc.s[sc.pos+1] == '\n':
			sc.pos++
		case c == '#':
			for sc.pos < len(sc.s) && sc.s[sc.pos] != '\n' {
				if b := sc.s[sc.pos]; b < ' ' && b != '\t' || b == 0x7f {
					return token{}, sc.fail("control character %#x in a comment", b)
				}
				sc.pos++
			}
		default:
			return sc.token()
		}
	}
	return token{tEOF, "", sc.line}, nil
}

func (sc *scanner) token() (token, *parseError) {
	t := token{line: sc.line}
	c := sc.s[sc.pos]
	switch {
	case c == '\n':
		sc.pos++
		sc.line++
		t.kind = tNewline
	case c == '[' || c == ']':
		t.kind = tLBracket
		if c == ']' {
			t.kind = tRBracket
		}
		sc.pos++
		if sc.pos < len(sc.s) && sc.s[sc.pos] == c {
			sc.pos++
			t.kind += 2 // the double bracket
		}
	case c == '=':
		sc.pos++
		t.kind = tEqual
	case c == ',':
		sc.pos++
		t.kind = tComma
	case c == '"':
		s, err := sc.basicString()
		if err != nil {
			return token{}, err
		}
		t.kind, t.text = tString, s
	case c == '\'':
		return token{}, sc.fail("literal strings ('...') are not supported: use double quotes")
	case bareChar(c):
		start := sc.pos
		for sc.pos < len(sc.s) && bareChar(sc.s[sc.pos]) {
			sc.pos++
		}
		t.kind, t.text = tBare, sc.s[start:sc.pos]
	case c < ' ' || c == 0x7f:
		return token{}, sc.fail("control character %#x", c)
	case c == '.':
		return token{}, sc.fail("unexpected '.': dotted keys and decimals are not supported")
	case c == '{':
		return token{}, sc.fail("unexpected '{': inline tables are not supported")
	case c >= 0x80:
		return token{}, sc.fail("a non-ASCII character outside a string")
	default:
		return token{}, sc.fail("unexpected %q", c)
	}
	return t, nil
}

// bareChar is a character of a bare key or an integer.
func bareChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '+'
}

// basicString decodes one "..." string at sc.pos, with the standard escapes.
func (sc *scanner) basicString() (string, *parseError) {
	if strings.HasPrefix(sc.s[sc.pos:], `"""`) {
		return "", sc.fail(`multi-line strings ("""...""") are not supported`)
	}
	sc.pos++ // the opening quote
	var b strings.Builder
	for sc.pos < len(sc.s) {
		c := sc.s[sc.pos]
		sc.pos++
		switch {
		case c == '"':
			if !utf8.ValidString(b.String()) {
				return "", sc.fail("a string holds invalid UTF-8")
			}
			return b.String(), nil
		case c == '\n':
			return "", sc.fail("unterminated string")
		case c < ' ' && c != '\t' || c == 0x7f:
			return "", sc.fail("control character %#x in a string", c)
		case c != '\\':
			b.WriteByte(c)
			continue
		}
		if sc.pos >= len(sc.s) {
			return "", sc.fail("unterminated string")
		}
		e := sc.s[sc.pos]
		sc.pos++
		switch e {
		case '"', '\\':
			b.WriteByte(e)
		case 'b', 't', 'n', 'f', 'r':
			b.WriteByte("\b\t\n\f\r"[strings.IndexByte("btnfr", e)])
		case 'u', 'U':
			n := 4
			if e == 'U' {
				n = 8
			}
			if sc.pos+n > len(sc.s) {
				return "", sc.fail("unterminated string")
			}
			r, err := strconv.ParseUint(sc.s[sc.pos:sc.pos+n], 16, 32)
			if err != nil || !utf8.ValidRune(rune(r)) {
				return "", sc.fail(`\%c wants %d hex digits of a Unicode scalar value, got %s`, e, n, strconv.Quote(sc.s[sc.pos:sc.pos+n]))
			}
			b.WriteRune(rune(r))
			sc.pos += n
		default:
			if e <= ' ' || e >= 0x7f {
				return "", sc.fail("a backslash before byte %#x in a string", e)
			}
			return "", sc.fail(`unknown escape \%c in a string`, e)
		}
	}
	return "", sc.fail("unterminated string")
}

// parser reads a document from its scanner.
type parser struct{ sc scanner }

// parse reads the whole document: its tables in file order, each with its keys.
func parse(text string) ([]Table, *parseError) {
	p := &parser{sc: scanner{s: text, line: 1}}
	var doc []Table
	var cur *Table
	for {
		t, err := p.sc.next()
		if err != nil {
			return nil, err
		}
		switch t.kind {
		case tEOF:
			return doc, nil
		case tNewline:
		case tLBracket, tLLBracket:
			h, err := p.header(t)
			if err != nil {
				return nil, err
			}
			doc = append(doc, h)
			cur = &doc[len(doc)-1]
		case tBare:
			if cur == nil {
				return nil, &parseError{t.line, fmt.Sprintf("key %s before any table", t)}
			}
			if err := p.keyValue(cur, t); err != nil {
				return nil, err
			}
		default:
			return nil, &parseError{t.line, fmt.Sprintf("unexpected %s at the start of a line", t)}
		}
	}
}

// header reads [name] or [[name]] after its opening bracket.
func (p *parser) header(open token) (Table, *parseError) {
	t, err := p.sc.next()
	if err != nil {
		return Table{}, err
	}
	if t.kind != tBare || !bareKey(t.text) {
		return Table{}, &parseError{t.line, fmt.Sprintf("want a table name, got %s", t)}
	}
	closing := tRBracket
	if open.kind == tLLBracket {
		closing = tRRBracket
	}
	if err := p.expect(closing); err != nil {
		return Table{}, err
	}
	if err := p.endOfLine(); err != nil {
		return Table{}, err
	}
	return Table{Name: t.text, Line: open.line, Array: open.kind == tLLBracket, Keys: map[string]Field{}}, nil
}

// keyValue reads "= value" after the key, to the end of the line, into t.
func (p *parser) keyValue(t *Table, key token) *parseError {
	if !bareKey(key.text) {
		return &parseError{key.line, fmt.Sprintf("%s is not a key", key)}
	}
	if _, dup := t.Keys[key.text]; dup {
		return &parseError{key.line, fmt.Sprintf("key %s is defined twice", key)}
	}
	if err := p.expect(tEqual); err != nil {
		return err
	}
	v, err := p.value()
	if err != nil {
		return err
	}
	if err := p.endOfLine(); err != nil {
		return err
	}
	t.Keys[key.text] = v
	return nil
}

// bareKey is a TOML bare key: letters, digits, '_' and '-'.
func bareKey(s string) bool { return s != "" && !strings.ContainsAny(s, "+") }

// value reads one value: a string, an integer or an array of strings, which may span lines.
func (p *parser) value() (Field, *parseError) {
	t, err := p.sc.next()
	if err != nil {
		return Field{}, err
	}
	switch t.kind {
	case tString:
		return Field{Line: t.line, Str: t.text}, nil
	case tBare:
		if _, err := strconv.ParseInt(t.text, 10, 64); err != nil {
			return Field{}, &parseError{t.line, fmt.Sprintf("%s is not a string, an integer or an array of strings", t)}
		}
		return Field{Line: t.line, Int: true}, nil
	case tLLBracket:
		return Field{}, &parseError{t.line, "nested arrays are not supported"}
	case tLBracket:
	default:
		return Field{}, &parseError{t.line, fmt.Sprintf("want a value, got %s", t)}
	}
	v := Field{Line: t.line, List: true}
	for {
		t, err := p.skipNewlines()
		if err != nil {
			return Field{}, err
		}
		if t.kind == tRBracket {
			return v, nil
		}
		if t.kind != tString {
			return Field{}, &parseError{t.line, fmt.Sprintf("an array may hold strings alone, got %s", t)}
		}
		v.Strs = append(v.Strs, Entry{t.text, t.line})
		if t, err = p.skipNewlines(); err != nil {
			return Field{}, err
		}
		switch t.kind {
		case tComma:
		case tRBracket:
			return v, nil
		default:
			return Field{}, &parseError{t.line, fmt.Sprintf("want ',' or ']' in an array, got %s", t)}
		}
	}
}

// skipNewlines is the next token that is not a newline: an array may span lines.
func (p *parser) skipNewlines() (token, *parseError) {
	for {
		t, err := p.sc.next()
		if err != nil || t.kind != tNewline {
			return t, err
		}
	}
}

// expect reads one token of the kind.
func (p *parser) expect(k tokKind) *parseError {
	t, err := p.sc.next()
	if err != nil {
		return err
	}
	if t.kind != k {
		return &parseError{t.line, fmt.Sprintf("want %s, got %s", token{kind: k}, t)}
	}
	return nil
}

// endOfLine reads the newline, or the end of the file, that ends a header or a key.
func (p *parser) endOfLine() *parseError {
	t, err := p.sc.next()
	if err != nil {
		return err
	}
	if t.kind != tNewline && t.kind != tEOF {
		return &parseError{t.line, fmt.Sprintf("unexpected %s after the value", t)}
	}
	return nil
}
