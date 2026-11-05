// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package audit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var clock = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC) }

// session writes a log of five records into a new directory and returns the directory and the key.
func session(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	key, err := LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Create(dir, key, clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{
		{Event: SessionStart},
		{Event: Connect, Host: "a.example", Port: 443, Result: Allowed},
		{Event: Connect, Host: "b.example", Port: 443, Result: "sni_not_allowed"},
		{Event: Secret, Name: "anthropic", Host: "a.example", Header: "x-api-key", Result: "granted"},
		{Event: SessionEnd, Result: "exit 0"},
	} {
		if err := l.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, key
}

func TestVerifyFindsEveryOfflineEdit(t *testing.T) {
	tests := []struct {
		name string
		edit func(b []byte) []byte
		ok   bool
	}{
		{"no edit", func(b []byte) []byte { return b }, true},
		{"a middle line dropped", func(b []byte) []byte {
			l := bytes.SplitAfter(b, []byte("\n"))
			return bytes.Join(append(l[:2:2], l[3:]...), nil)
		}, false},
		{"one byte altered", func(b []byte) []byte {
			b = bytes.Clone(b)
			i := bytes.Index(b, []byte("b.example"))
			b[i] = 'c'
			return b
		}, false},
		{"cut to its first half", func(b []byte) []byte { return b[:len(b)/2] }, false},
		{"cut after a whole line", func(b []byte) []byte { return b[:bytes.LastIndex(b[:len(b)-1], []byte("\n"))+1] }, false},
		{"the last line twice", func(b []byte) []byte {
			l := bytes.SplitAfter(b, []byte("\n"))
			return append(bytes.Clone(b), l[len(l)-2]...)
		}, false},
		{"two lines swapped", func(b []byte) []byte {
			l := bytes.SplitAfter(b, []byte("\n"))
			l[1], l[2] = l[2], l[1]
			return bytes.Join(l, nil)
		}, false},
		{"a carriage return added", func(b []byte) []byte { return bytes.Replace(b, []byte("}\n"), []byte("}\r\n"), 1) }, false},
		{"a blank line added", func(b []byte) []byte { return append([]byte("\n"), b...) }, false},
		{"a forged line added", func(b []byte) []byte {
			return append(bytes.Clone(b), `{"time":"2026-01-02T03:04:05Z","event":"connect","host":"x"}`+"\n"...)
		}, false},
		{"emptied", func([]byte) []byte { return nil }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, key := session(t)
			path := filepath.Join(dir, LogName)
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(path, tc.edit(b), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Verify(dir, key.Public().(ed25519.PublicKey)); (err == nil) != tc.ok {
				t.Errorf("Verify = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestVerifyFindsAChangedSealOrKey(t *testing.T) {
	other, _ := LoadKey(t.TempDir())
	tests := []struct {
		name string
		edit func(dir string) ed25519.PublicKey
	}{
		{"another key", func(string) ed25519.PublicKey { return other.Public().(ed25519.PublicKey) }},
		{"a short key", func(string) ed25519.PublicKey { return ed25519.PublicKey{1} }},
		{"no seal", func(dir string) ed25519.PublicKey { os.Remove(filepath.Join(dir, SealName)); return nil }},
		{"a seal of an older log", func(dir string) ed25519.PublicKey {
			s, _ := os.ReadFile(filepath.Join(dir, SealName))
			s[0]++
			os.WriteFile(filepath.Join(dir, SealName), s, 0o600)
			return nil
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, key := session(t)
			pub := tc.edit(dir)
			if pub == nil {
				pub = key.Public().(ed25519.PublicKey)
			}
			if err := Verify(dir, pub); err == nil {
				t.Error("Verify accepted it")
			}
		})
	}
}

func TestRecordsAreBoundedAndEscaped(t *testing.T) {
	tests := []struct{ name, host string }{
		{"a line break", "a.example\n{\"event\":\"session_start\"}"},
		{"an escape sequence", "\x1b[2J.example"},
		{"a long name", strings.Repeat("a", 1000)},
		{"bytes that are no text", "\xff\xfe\x00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			key, _ := LoadKey(dir)
			l, _ := Create(dir, key, clock)
			if err := l.Note(Record{Event: Connect, Host: tc.host, Port: 443, Result: "sni_not_allowed"}); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(filepath.Join(dir, LogName))
			lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
			r, ok := ParseLine(lines[0])
			if len(lines) != 1 || !ok || len(r.Host) > maxField+3 || r.Event != Connect {
				t.Errorf("log %q: want one record with a bounded host", b)
			}
			if err := Verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestVolumeIsBounded(t *testing.T) {
	dir := t.TempDir()
	key, _ := LoadKey(dir)
	l, _ := Create(dir, key, clock)
	l.soft, l.hard = 600, 1000
	var notes, errs int
	for range 20 {
		if err := l.Note(Record{Event: Connect, Host: "a.example", Port: 443, Result: Allowed}); err != nil {
			errs++
		} else {
			notes++
		}
	}
	if notes == 0 || errs == 0 || !errors.Is(l.Note(Record{Event: Connect}), ErrFull) {
		t.Fatalf("%d notes kept, %d refused: want some of each", notes, errs)
	}
	if err := l.Record(Record{Event: Secret, Name: "k"}); err != nil {
		t.Errorf("a durable record past the soft limit: %v", err)
	}
	for l.Record(Record{Event: Secret, Name: "k"}) == nil {
	}
	b, _ := os.ReadFile(filepath.Join(dir, LogName))
	if n := strings.Count(string(b), LogFull); n != 1 || len(b) > 1000 {
		t.Errorf("log of %d bytes holds %d full markers, want one within the hard limit", len(b), n)
	}
	if err := Verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
		t.Error(err)
	}
}

func TestLifecycleRecordsIgnoreTheLimit(t *testing.T) {
	for _, event := range []string{SessionStart, SessionEnd} {
		t.Run(event, func(t *testing.T) {
			dir := t.TempDir()
			key, _ := LoadKey(dir)
			l, _ := Create(dir, key, clock)
			l.soft, l.hard = 600, 1000
			for l.Note(Record{Event: Connect, Host: "a.example", Port: 443, Result: Allowed}) == nil {
			}
			for l.Record(Record{Event: Secret, Name: "k"}) == nil {
			}
			if err := l.Record(Record{Event: Secret, Name: "k"}); !errors.Is(err, ErrFull) {
				t.Fatalf("log not full: %v", err)
			}
			if err := l.Record(Record{Event: event}); err != nil {
				t.Fatalf("%s refused: %v", event, err)
			}
			b, _ := os.ReadFile(filepath.Join(dir, LogName))
			if !strings.Contains(string(b), `"event":"`+event+`"`) {
				t.Errorf("no %s line in the log", event)
			}
			if err := Verify(dir, key.Public().(ed25519.PublicKey)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestAClosedOrNilLogRecordsNothing(t *testing.T) {
	dir := t.TempDir()
	key, _ := LoadKey(dir)
	l, _ := Create(dir, key, clock)
	l.Close()
	var nilLog *Log
	for name, log := range map[string]*Log{"closed": l, "nil": nilLog} {
		if log.Record(Record{Event: Secret}) == nil || log.Note(Record{Event: Connect}) == nil {
			t.Errorf("%s log took a record", name)
		}
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := LoadKey(dir); err != nil || !again.Equal(first) {
		t.Errorf("second load = %v, %v: want the same key", again, err)
	}
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
	}{
		{"readable by others", strings.Repeat("ab", 32), 0o644},
		{"not a key", "hello", 0o600},
		{"too short", strings.Repeat("ab", 16), 0o600},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, keyName), []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			os.Chmod(filepath.Join(dir, keyName), tc.mode)
			if _, err := LoadKey(dir); err == nil {
				t.Error("LoadKey took it")
			}
		})
	}
}

func TestParseLineAndSafeHost(t *testing.T) {
	const ts = `"time":"2026-01-02T03:04:05Z"`
	for line, want := range map[string]bool{
		`{` + ts + `,"event":"connect","host":"a.example","port":443,"result":"allowed"}`: true,
		`{` + ts + `,"event":"connect"} x`:                                                false,
		`{` + ts + `,"event":"connect","other":1}`:                                        false,
		`{` + ts + `}`:                           false,
		`{"time":"yesterday","event":"connect"}`: false,
		`not json`:                               false,
		strings.Repeat(" ", maxLine+1):           false,
	} {
		if _, ok := ParseLine(line); ok != want {
			t.Errorf("ParseLine(%.60q) = %v, want %v", line, ok, want)
		}
	}
	for in, want := range map[string]string{"": "", "A.Example": "a.example", "a b": "(invalid)", "a\x1b": "(invalid)", "é.example": "(invalid)"} {
		if got := SafeHost(in); got != want {
			t.Errorf("SafeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzEachLine feeds any bytes to the line reader: no line is over the bound or holds a newline,
// and the lines with their newlines are exactly the input, or the read fails.
func FuzzEachLine(f *testing.F) {
	f.Add([]byte("a\nb\n"))
	f.Add([]byte("a\r\n\n"))
	f.Add([]byte("no newline"))
	f.Add(bytes.Repeat([]byte("x"), maxLine+1))
	f.Fuzz(func(t *testing.T, in []byte) {
		var out []byte
		err := eachLine(bytes.NewReader(in), func(line []byte) error {
			if len(line) > maxLine || bytes.IndexByte(line, '\n') >= 0 {
				t.Fatalf("line of %d bytes: %q", len(line), line)
			}
			out = append(append(out, line...), '\n')
			return nil
		})
		if err == nil && !bytes.Equal(out, in) {
			t.Fatalf("read %q from %q", out, in)
		}
		ParseLine(string(in))
	})
}
