// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"strings"
	"testing"
)

func TestSelect(t *testing.T) {
	saved := All
	defer func() { All = saved }()
	All = []Test{{ID: "I1", Name: "a"}, {ID: "I2", Name: "b"}, {ID: "I2", Name: "c"}}
	cases := []struct {
		only string
		want string // names, or "!" for an error
	}{
		{"", "a b c"},
		{" ", "a b c"},
		{"I1", "a"},
		{"I2", "b c"},
		{"I2, I1,", "b c a"},
		{"I3", "!"},
		{"I1,I3", "!"},
		{"i1", "!"},
	}
	for _, c := range cases {
		got, err := Select(c.only)
		var names []string
		for _, g := range got {
			names = append(names, g.Name)
		}
		if (err != nil) != (c.want == "!") || err == nil && strings.Join(names, " ") != c.want {
			t.Errorf("Select(%q) = %v, %v; want %q", c.only, names, err, c.want)
		}
	}
	if len(saved) == 0 {
		t.Fatal("the suite is empty")
	}
	for i, a := range saved {
		for _, b := range saved[i+1:] {
			if a.Name == b.Name {
				t.Errorf("two tests named %q", a.Name)
			}
		}
	}
}

func TestParseResult(t *testing.T) {
	long := strings.Repeat("x", maxDetail)
	cases := []struct {
		in   string
		want Result
		ok   bool
	}{
		{"escape-result connected to 127.0.0.1:1\n", Result{"connected", "to 127.0.0.1:1"}, true},
		{"escape-result refused \n", Result{"refused", ""}, true},
		{"escape-result a-1 " + long + "\n", Result{"a-1", long}, true},
		{"escape-result a-1 " + long + "x\n", Result{}, false},
		{"escape-result " + strings.Repeat("s", maxStatus+1) + " \n", Result{}, false},
		{"", Result{}, false},
		{"escape-result connected", Result{}, false},
		{"escape-result connected\n", Result{}, false},
		{"escape-result  x\n", Result{}, false},
		{"escape-result Connected x\n", Result{}, false},
		{"escape-result ok \x00\n", Result{}, false},
		{"escape-result ok \xff\n", Result{}, false},
		{"escape-result ok a\nb\n", Result{}, false},
		{"noise\nescape-result ok a\n", Result{}, false},
		{"escape-result ok a\n\n", Result{}, false},
		{strings.Repeat("a", MaxLine+1), Result{}, false},
	}
	for _, c := range cases {
		got, err := ParseResult([]byte(c.in))
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParseResult(%q) = %+v, %v; want %+v, ok=%v", c.in, got, err, c.want, c.ok)
		}
	}
}

func FuzzParseResult(f *testing.F) {
	f.Add([]byte("escape-result connected to x\n"))
	f.Add([]byte("escape-result \n"))
	f.Add(Format(Result{Status: "A B", Detail: "\x00\xff" + strings.Repeat("d", 300)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseResult(b)
		if err != nil {
			return
		}
		if again := Format(r); !bytes.Equal(again, b) {
			t.Fatalf("Format(ParseResult(%q)) = %q", b, again)
		}
	})
}

func FuzzFormat(f *testing.F) {
	f.Add("connected", "to x")
	f.Add("", "")
	f.Add("Bad Status\n", strings.Repeat("\xff", 300))
	f.Fuzz(func(t *testing.T, status, detail string) {
		line := Format(Result{Status: status, Detail: detail})
		if len(line) > MaxLine {
			t.Fatalf("Format produced %d bytes", len(line))
		}
		if _, err := ParseResult(line); err != nil {
			t.Fatalf("Format(%q, %q) = %q does not parse: %v", status, detail, line, err)
		}
	})
}
