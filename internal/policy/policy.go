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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
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

// ErrNotRegular is what ReadRepo says of a path that is a symbolic link, a pipe, a directory or any
// other thing but a file.
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
	return readAll(f, path)
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
// and give none. With an allow array, only the user's entries it names, with exactly the same text, stay;
// with [[secret]] rows, only the user's rows whose name a row of it names stay, as the user wrote them. Of a
// repository's row only the name is read. [workspace], [resources] and [update] are not read. What the
// repository asked for that the user did not grant comes back as asked: a host as written, a secret as its name quoted.
func Narrow(user, repo Policy) (got Policy, asked []string) {
	got = user
	if repo.AllowSet {
		got.Allow = nil
		for _, e := range user.Allow {
			if slices.ContainsFunc(repo.Allow, func(r Entry) bool { return r.Text == e.Text }) {
				got.Allow = append(got.Allow, e)
			}
		}
		for _, r := range repo.Allow {
			if !slices.ContainsFunc(user.Allow, func(e Entry) bool { return e.Text == r.Text }) {
				asked = append(asked, r.Text)
			}
		}
	}
	if len(repo.Secret) > 0 {
		got.Secret = nil
		for _, u := range user.Secret {
			if slices.ContainsFunc(repo.Secret, func(r Secret) bool { return r.Name == u.Name }) {
				got.Secret = append(got.Secret, u)
			}
		}
		for _, r := range repo.Secret {
			if !slices.ContainsFunc(user.Secret, func(u Secret) bool { return u.Name == r.Name }) {
				asked = append(asked, "secret "+strconv.Quote(r.Name))
			}
		}
	}
	return got, asked
}

// tables are the tables SPEC section 5 names, and whether each is an array of tables. Only
// [network] and [[secret]] are read today; the others are read past, since reading them costs nothing.
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
		array, known := tables[t.name]
		switch {
		case !known:
			return Policy{}, fmt.Errorf("%s:%d: table [%s] is not one of network, secret, workspace, resources, update", name, t.line, t.name)
		case array && !t.array:
			return Policy{}, fmt.Errorf("%s:%d: [%s] is an array of tables: write [[%s]]", name, t.line, t.name, t.name)
		case !array && t.array:
			return Policy{}, fmt.Errorf("%s:%d: [[%s]] is a table: write [%s]", name, t.line, t.name, t.name)
		case !array && first[t.name] != 0:
			return Policy{}, fmt.Errorf("%s:%d: table [%s] is defined twice, first on line %d", name, t.line, t.name, first[t.name])
		}
		first[t.name] = t.line
		switch t.name {
		case "network":
			for key, v := range t.keys {
				if key != "allow" {
					return Policy{}, fmt.Errorf("%s:%d: unknown key %q in [network]: allow is the only one", name, v.line, key)
				}
				if v.kind != kStrings {
					return Policy{}, fmt.Errorf("%s:%d: allow must be an array of strings", name, v.line)
				}
				p.Allow, p.AllowSet = v.strs, true
			}
		case "secret":
			s, err := secretRow(t, name)
			if err != nil {
				return Policy{}, err
			}
			p.Secret = append(p.Secret, s)
		}
	}
	return p, nil
}

// Table is one [name] or [[name]] of a document that Tables reads, with its keys. U-402 reads
// the provider data files with it, so that the product has the one reader (I13).
type Table struct {
	Name  string
	Line  int
	Array bool // [[name]]
	Keys  map[string]Field
}

// Field is a value of the subset: a string in Str, an array of strings in Strs (List), or an
// integer (Int), which the caller usually refuses.
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
	out := make([]Table, len(doc))
	for i, t := range doc {
		out[i] = Table{Name: t.name, Line: t.line, Array: t.array, Keys: map[string]Field{}}
		for k, v := range t.keys {
			out[i].Keys[k] = Field{Line: v.line, Str: v.str, Strs: v.strs, List: v.kind == kStrings, Int: v.kind == kInteger}
		}
	}
	return out, nil
}

// secretRow reads one [[secret]] table: name and source, each a string, with host, header, env,
// method and path optional, repos an optional array of strings, and nothing else. An empty string
// or array is as good as no key. A row without host and header names a provider's secret, which
// supplies them (cmd/workcell).
func secretRow(t *table, name string) (Secret, error) {
	s := Secret{Line: t.line}
	fields := map[string]*string{"name": &s.Name, "source": &s.Source, "host": &s.Host, "header": &s.Header, "env": &s.Env, "method": &s.Method, "path": &s.Path}
	for key, v := range t.keys {
		if key == "repos" {
			if v.kind != kStrings {
				return Secret{}, fmt.Errorf("%s:%d: repos must be an array of strings", name, v.line)
			}
			for _, e := range v.strs {
				s.Repos = append(s.Repos, e.Text)
			}
			continue
		}
		field, ok := fields[key]
		if !ok {
			return Secret{}, fmt.Errorf("%s:%d: unknown key %q in [[secret]]: name, source, host, header, env, method, path and repos are the keys", name, v.line, key)
		}
		if v.kind != kString {
			return Secret{}, fmt.Errorf("%s:%d: %s must be a string", name, v.line, key)
		}
		*field = v.str
	}
	for _, key := range []string{"name", "source"} {
		if *fields[key] == "" {
			return Secret{}, fmt.Errorf("%s:%d: [[secret]] needs a %s", name, t.line, key)
		}
	}
	return s, nil
}

// A parsed document: tables in file order, each with its keys. The subset has three value kinds.
type kind int

const (
	kString kind = iota
	kInteger
	kStrings
)

type value struct {
	kind kind
	line int
	str  string
	int  int64
	strs []Entry
}

type table struct {
	name  string
	line  int
	array bool // [[name]]
	keys  map[string]value
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
	switch t.kind {
	case tEOF:
		return "end of file"
	case tNewline:
		return "end of line"
	case tString:
		return "a string"
	case tBare:
		return strconv.Quote(t.text)
	}
	return strconv.Quote([...]string{tLBracket: "[", tRBracket: "]", tLLBracket: "[[", tRRBracket: "]]", tEqual: "=", tComma: ","}[t.kind])
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

// parse reads the whole document.
func parse(text string) ([]*table, *parseError) {
	p := &parser{sc: scanner{s: text, line: 1}}
	var doc []*table
	var cur *table
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
			cur, err = p.header(t)
			if err != nil {
				return nil, err
			}
			doc = append(doc, cur)
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
func (p *parser) header(open token) (*table, *parseError) {
	t, err := p.sc.next()
	if err != nil {
		return nil, err
	}
	if t.kind != tBare || !bareKey(t.text) {
		return nil, &parseError{t.line, fmt.Sprintf("want a table name, got %s", t)}
	}
	closing := tRBracket
	if open.kind == tLLBracket {
		closing = tRRBracket
	}
	if err := p.expect(closing); err != nil {
		return nil, err
	}
	if err := p.endOfLine(); err != nil {
		return nil, err
	}
	return &table{name: t.text, line: open.line, array: open.kind == tLLBracket, keys: map[string]value{}}, nil
}

// keyValue reads "= value" after the key, to the end of the line, into t.
func (p *parser) keyValue(t *table, key token) *parseError {
	if !bareKey(key.text) {
		return &parseError{key.line, fmt.Sprintf("%s is not a key", key)}
	}
	if _, dup := t.keys[key.text]; dup {
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
	t.keys[key.text] = v
	return nil
}

// bareKey is a TOML bare key: letters, digits, '_' and '-'.
func bareKey(s string) bool { return s != "" && !strings.ContainsAny(s, "+") }

// value reads one value: a string, an integer or an array of strings, which may span lines.
func (p *parser) value() (value, *parseError) {
	t, err := p.sc.next()
	if err != nil {
		return value{}, err
	}
	switch t.kind {
	case tString:
		return value{kind: kString, line: t.line, str: t.text}, nil
	case tBare:
		n, err := strconv.ParseInt(t.text, 10, 64)
		if err != nil {
			return value{}, &parseError{t.line, fmt.Sprintf("%s is not a string, an integer or an array of strings", t)}
		}
		return value{kind: kInteger, line: t.line, int: n}, nil
	case tLLBracket:
		return value{}, &parseError{t.line, "nested arrays are not supported"}
	case tLBracket:
	default:
		return value{}, &parseError{t.line, fmt.Sprintf("want a value, got %s", t)}
	}
	v := value{kind: kStrings, line: t.line}
	for {
		t, err := p.skipNewlines()
		if err != nil {
			return value{}, err
		}
		if t.kind == tRBracket {
			return v, nil
		}
		if t.kind != tString {
			return value{}, &parseError{t.line, fmt.Sprintf("an array may hold strings alone, got %s", t)}
		}
		v.strs = append(v.strs, Entry{t.text, t.line})
		if t, err = p.skipNewlines(); err != nil {
			return value{}, err
		}
		switch t.kind {
		case tComma:
		case tRBracket:
			return v, nil
		default:
			return value{}, &parseError{t.line, fmt.Sprintf("want ',' or ']' in an array, got %s", t)}
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
