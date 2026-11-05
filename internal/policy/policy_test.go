// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// specExample is the policy of SPEC section 5, as written there.
const specExample = `# ~/.config/workcell/config.toml grants. A repo-local workcell.toml may only narrow (I13).
[network]
allow = ["api.anthropic.com", "github.com", "proxy.golang.org"]

[[secret]]
name   = "anthropic"
source = "keychain:workcell/anthropic"   # keychain: | secret-service: | file: | cmd:
host   = "api.anthropic.com"
header = "x-api-key"

[workspace]
mode = "clone"                            # clone | mount

[resources]
cpus = 4
memory = "4GiB"
disk = "20GiB"
`

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []Entry // nil for nothing allowed
	}{
		{"the SPEC example", specExample, []Entry{{"api.anthropic.com", 3}, {"github.com", 3}, {"proxy.golang.org", 3}}},
		{"empty file", "", nil},
		{"comments and blank lines alone", "# nothing\n\n   # here\n", nil},
		{"no network table", "[workspace]\nmode = \"clone\"\n", nil},
		{"network without allow", "[network]\n", nil},
		{"empty allow", "[network]\nallow = []\n", nil},
		{"empty allow with room", "[network]\nallow = [ ]", nil},
		{"the escape adapter's forward entry", "[network]\nallow = [\"allowed.escape.test:8443\"]\n", []Entry{{"allowed.escape.test:8443", 2}}},
		{"bare name and name:port", "[network]\nallow = [\"a.example\", \"b.example:80\"]\n", []Entry{{"a.example", 2}, {"b.example:80", 2}}},
		{"an array over lines, with comments and a trailing comma", "[network]\nallow = [ # names\n  \"a.example\",\n\n  \"b.example:80\", # forward\n]\n",
			[]Entry{{"a.example", 3}, {"b.example:80", 5}}},
		{"escapes in a string", "[network]\nallow = [\"a\\u002Eexample\\t\\\"\\\\\\n\"]\n", []Entry{{"a.example\t\"\\\n", 2}}},
		{"a UTF-8 string", "[network]\nallow = [\"caf\u00e9\"]\n", []Entry{{"caf\u00e9", 2}}},
		{"CRLF line ends", "[network]\r\nallow = [\"a.example\"]\r\n", []Entry{{"a.example", 2}}},
		{"no final newline", "[network]\nallow = [\"a.example\"]", []Entry{{"a.example", 2}}},
		{"tabs and comments after a header", "[network]\t# the table\nallow\t=\t[\"a.example\"]\n", []Entry{{"a.example", 2}}},
		{"two secrets", "[[secret]]\nname = \"a\"\nsource = \"file:/a\"\nhost = \"h\"\nheader = \"k\"\n[[secret]]\nname = \"b\"\nsource = \"file:/b\"\nhost = \"h\"\nheader = \"j\"\n[network]\nallow = [\"a.example\"]\n", []Entry{{"a.example", 12}}},
		{"negative and signed integers elsewhere", "[resources]\ncpus = -1\ndisk = +7\n", nil},
		{"update table", "[update]\nchannel = \"hold\"\ncooloff = 14\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.text, "config.toml")
			if err != nil {
				t.Fatalf("Parse(%q) = %v", tc.text, err)
			}
			if !slices.Equal(got.Allow, tc.want) {
				t.Errorf("Parse(%q).Allow = %v, want %v", tc.text, got.Allow, tc.want)
			}
		})
	}
}

// TestParseSecret: each [[secret]] row comes back with its keys and its line, the optional
// keys "" when left out; the Allow entries are TestParse's concern.
func TestParseSecret(t *testing.T) {
	full := "[[secret]]\nname = \"a\"\nsource = \"file:/s\"\nhost = \"a.example\"\nheader = \"X-Api-Key\"\nenv = \"A_KEY\"\nmethod = \"POST\"\npath = \"/v1/\"\n"
	tests := []struct {
		name string
		text string
		want []Secret
	}{
		{"the SPEC example", specExample, []Secret{{Name: "anthropic", Source: "keychain:workcell/anthropic", Host: "api.anthropic.com", Header: "x-api-key", Line: 5}}},
		{"every key", full, []Secret{{"a", "file:/s", "a.example", "X-Api-Key", "A_KEY", "POST", "/v1/", 1}}},
		{"two rows, the second after another table", full + "[network]\n[[secret]]\nname = \"b\"\nsource = \"cmd:/bin/b\"\nhost = \"b.example\"\nheader = \"authorization\"\n",
			[]Secret{{"a", "file:/s", "a.example", "X-Api-Key", "A_KEY", "POST", "/v1/", 1}, {Name: "b", Source: "cmd:/bin/b", Host: "b.example", Header: "authorization", Line: 10}}},
		{"no secret", "[network]\nallow = []\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.text, "config.toml")
			if err != nil || !slices.Equal(got.Secret, tc.want) {
				t.Errorf("Parse(%q).Secret = %+v, %v; want %+v", tc.text, got.Secret, err, tc.want)
			}
		})
	}
}

// TestParseTables holds the generic reader to the same subset and errors as Parse, whatever the table names.
func TestParseTables(t *testing.T) {
	tabs, err := Tables("[a]\nx = \"s\"\nn = 3\n[[b]]\nl = [\"p\",\n\"q\"]\n", "f")
	if err != nil {
		t.Fatal(err)
	}
	a, b := tabs[0], tabs[1]
	if len(tabs) != 2 || a.Name != "a" || a.Array || !b.Array || b.Line != 4 {
		t.Fatalf("tables = %+v", tabs)
	}
	if x, n, l := a.Keys["x"], a.Keys["n"], b.Keys["l"]; x.Str != "s" || x.List || !n.Int || !l.List || len(l.Strs) != 2 || l.Strs[1].Line != 6 {
		t.Errorf("fields = %+v %+v %+v", x, n, l)
	}
	for text, want := range map[string]string{"x = 1": "f:1: key \"x\" before any table", "[a]\nx = 'y'": "f:2: literal strings"} {
		if _, err := Tables(text, "f"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Tables(%q) error = %v, want %q", text, err, want)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string // the start of the error: "config.toml:<line>: " and the first words
	}{
		{"unknown table", "[network]\n\n[other]\n", "config.toml:3: table [other] is not one of"},
		{"secret as a single table", "[secret]\nname = \"a\"\n", "config.toml:1: [secret] is an array of tables: write [[secret]]"},
		{"network as an array of tables", "\n[[network]]\n", "config.toml:2: [[network]] is a table: write [network]"},
		{"table defined twice", "[network]\nallow = []\n[network]\n", "config.toml:3: table [network] is defined twice, first on line 1"},
		{"key defined twice", "[network]\nallow = []\nallow = []\n", "config.toml:3: key \"allow\" is defined twice"},
		{"unknown key in network", "[network]\nallow = []\ndeny = []\n", "config.toml:3: unknown key \"deny\" in [network]"},
		{"unknown key in secret", "[[secret]]\nname = \"a\"\nvalue = \"sk\"\n", "config.toml:3: unknown key \"value\" in [[secret]]"},
		{"secret key not a string", "[[secret]]\nname = \"a\"\nsource = [\"file:/s\"]\n", "config.toml:3: source must be a string"},
		{"secret without a name", "\n[[secret]]\nsource = \"file:/s\"\nhost = \"h\"\nheader = \"k\"\n", "config.toml:2: [[secret]] needs a name"},
		{"secret without a source", "[[secret]]\nname = \"a\"\nhost = \"h\"\nheader = \"k\"\n", "config.toml:1: [[secret]] needs a source"},
		{"secret without a host", "[[secret]]\nname = \"a\"\nsource = \"file:/s\"\nheader = \"k\"\n", "config.toml:1: [[secret]] needs a host"},
		{"secret with an empty header", "[[secret]]\nname = \"a\"\nsource = \"file:/s\"\nhost = \"h\"\nheader = \"\"\n", "config.toml:1: [[secret]] needs a header"},
		{"allow is a string", "[network]\nallow = \"a.example\"\n", "config.toml:2: allow must be an array of strings"},
		{"allow is an integer", "[network]\nallow = 443\n", "config.toml:2: allow must be an array of strings"},
		{"array of integers", "[network]\nallow = [443]\n", "config.toml:2: an array may hold strings alone, got \"443\""},
		{"nested array", "[network]\nallow = [[\"a\"]]\n", "config.toml:2: nested arrays are not supported"},
		{"array element on a later line is refused there", "[network]\nallow = [\n  \"a\",\n  1,\n]\n", "config.toml:4: an array may hold strings alone"},
		{"key before any table", "allow = []\n[network]\n", "config.toml:1: key \"allow\" before any table"},
		{"literal string", "[network]\nallow = ['a']\n", "config.toml:2: literal strings"},
		{"multi-line string", "[network]\nallow = [\"\"\"a\"\"\"]\n", "config.toml:2: multi-line strings"},
		{"unterminated string", "[network]\nallow = [\"a]\n", "config.toml:2: unterminated string"},
		{"unterminated string at the end", "[network]\nallow = [\"a", "config.toml:2: unterminated string"},
		{"unterminated array", "[network]\nallow = [\"a\",\n", "config.toml:3: an array may hold strings alone, got end of file"},
		{"missing comma", "[network]\nallow = [\"a\" \"b\"]\n", "config.toml:2: want ',' or ']' in an array, got a string"},
		{"bad escape", "[network]\nallow = [\"\\x41\"]\n", "config.toml:2: unknown escape \\x"},
		{"bad unicode escape", "[network]\nallow = [\"\\uD800\"]\n", "config.toml:2: \\u wants 4 hex digits of a Unicode scalar value, got \"D800\""},
		{"short unicode escape", "[network]\nallow = [\"\\u41\"]\n", "config.toml:2: \\u wants 4 hex digits of a Unicode scalar value, got \"41\\\"]\""},
		{"unicode escape over a line end", "[network]\nallow = [\"\\u\n\n\n\n\"]\n", "config.toml:2: \\u wants 4 hex digits of a Unicode scalar value, got \"\\n\\n\\n\\n\""},
		{"backslash before a newline", "\"\\\n", "config.toml:1: a backslash before byte 0xa in a string"},
		{"backslash before a non-ASCII byte", "[network]\nallow = [\"\\\u00e9\"]\n", "config.toml:2: a backslash before byte 0xc3 in a string"},
		{"invalid UTF-8 in a string", "[network]\nallow = [\"\xff\"]\n", "config.toml:2: a string holds invalid UTF-8"},
		{"control character in a string", "[network]\nallow = [\"a\x01\"]\n", "config.toml:2: control character 0x1 in a string"},
		{"control character outside a string", "[network]\x01\n", "config.toml:1: control character 0x1"},
		{"control character in a comment", "# a\x07b\n", "config.toml:1: control character 0x7 in a comment"},
		{"lone carriage return", "[network]\rallow = []\n", "config.toml:1: control character 0xd"},
		{"non-ASCII outside a string", "[network]\nallow\u00e9 = []\n", "config.toml:2: a non-ASCII character outside a string"},
		{"dotted key", "[network]\na.b = 1\n", "config.toml:2: unexpected '.': dotted keys"},
		{"dotted table", "[network.extra]\n", "config.toml:1: unexpected '.': dotted keys"},
		{"float", "[resources]\ncpus = 1.5\n", "config.toml:2: unexpected '.'"},
		{"boolean", "[workspace]\nlive = true\n", "config.toml:2: \"true\" is not a string, an integer or an array of strings"},
		{"date", "[workspace]\nsince = 1979-05-27\n", "config.toml:2: \"1979-05-27\" is not a string"},
		{"inline table", "[network]\nallow = { a = 1 }\n", "config.toml:2: unexpected '{': inline tables"},
		{"missing equals", "[network]\nallow [\"a\"]\n", "config.toml:2: want \"=\", got \"[\""},
		{"missing value", "[network]\nallow =\n", "config.toml:2: want a value, got end of line"},
		{"two values on a line", "[network]\nallow = [] 7\n", "config.toml:2: unexpected \"7\" after the value"},
		{"text after a header", "[network] allow = []\n", "config.toml:1: unexpected \"allow\" after the value"},
		{"quoted key", "[network]\n\"allow\" = []\n", "config.toml:2: unexpected a string at the start of a line"},
		{"empty header", "[]\n", "config.toml:1: want a table name, got \"]\""},
		{"header with a plus", "[+]\n", "config.toml:1: want a table name, got \"+\""},
		{"key with a plus", "[network]\n+allow = []\n", "config.toml:2: \"+allow\" is not a key"},
		{"unbalanced header", "[[secret]\n", "config.toml:1: want \"]]\", got \"]\""},
		{"stray bracket at line start", "[network]\n]\n", "config.toml:2: unexpected \"]\" at the start of a line"},
		{"stray comma", "[network]\n, allow = []\n", "config.toml:2: unexpected \",\" at the start of a line"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text, "config.toml")
			if err == nil {
				t.Fatalf("Parse(%q) passed, want an error starting %q", tc.text, tc.want)
			}
			if msg := err.Error(); !strings.HasPrefix(msg, tc.want) || strings.Contains(msg, "\n") {
				t.Errorf("Parse(%q) = %q, want one line starting %q", tc.text, msg, tc.want)
			}
		})
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name  string
		write string // "" for no file
		want  []Entry
		err   string
	}{
		{"no file grants nothing", "", nil, ""},
		{"a file", "[network]\nallow = [\"a.example\"]\n", []Entry{{"a.example", 2}}, ""},
		{"an error names the path", "[network]\nallow = [1]\n", nil, ": an array may hold strings alone"},
		{"too large", strings.Repeat("#", maxBytes+1), nil, "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".toml")
			if tc.write != "" {
				if err := os.WriteFile(path, []byte(tc.write), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := Read(path)
			if tc.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), path) || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Read = %v, want an error starting %q and holding %q", err, path, tc.err)
				}
				return
			}
			if err != nil || !slices.Equal(got.Allow, tc.want) {
				t.Errorf("Read = %v, %v; want %v", got.Allow, err, tc.want)
			}
		})
	}
}

// FuzzParse holds the reader to never panicking or hanging on any bytes, and to naming a line
// that exists for every entry it returns. U-503 feeds it a repository's file (T5).
func FuzzParse(f *testing.F) {
	for _, seed := range []string{specExample, "", "[network]\nallow = [\n\"a\",\n]\n", "[network]\nallow = [\"\\u0041\\\"\"]", "[[secret]]\nx = -1", "\xff", "[network]\r\nallow = []\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		p, err := Parse(text, "f")
		if err != nil {
			if msg := err.Error(); !strings.HasPrefix(msg, "f:") || strings.Contains(msg, "\n") {
				t.Errorf("error %q does not name the file and line on one line", msg)
			}
			return
		}
		lines := strings.Count(text, "\n") + 1
		for _, e := range p.Allow {
			if e.Line < 1 || e.Line > lines {
				t.Errorf("entry %q on line %d of %d", e.Text, e.Line, lines)
			}
		}
	})
}
