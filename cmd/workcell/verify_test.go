// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/audit"
)

const testID = "20260102T030405.000000000Z-0123abcd"

var testRecords = []audit.Record{
	{Event: audit.SessionStart},
	{Event: audit.Connect, Host: "a.example", Port: 443, Result: audit.Allowed},
	{Event: audit.Connect, Host: "b.example", Port: 53, Result: "name_not_allowed"},
	{Event: audit.Secret, Host: "api.example", Header: "authorization", Name: "tok", Result: "granted"},
	{Event: audit.Secret, Host: "api.example", Header: "authorization", Result: "not_granted"},
	{Event: audit.SessionEnd},
}

// auditSession writes testRecords with the audit package itself into a session of a new data directory.
func auditSession(t *testing.T) (dir string, log []byte) {
	t.Helper()
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	dir = filepath.Join(data, "workcell", "sessions", testID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := audit.LoadKey(filepath.Join(data, "workcell"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := audit.Create(dir, key, func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6e6, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range testRecords {
		if err := l.Record(r); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	log, err = os.ReadFile(filepath.Join(dir, audit.LogName))
	if err != nil {
		t.Fatal(err)
	}
	return dir, log
}

func TestVerify(t *testing.T) {
	lines := func(log []byte) []string { return strings.SplitAfter(string(log), "\n")[:len(testRecords)] }
	tests := []struct {
		name string
		edit func(log []byte) string // the log after an offline edit
		args []string
		want int
	}{
		{"untouched", func(l []byte) string { return string(l) }, []string{testID}, 0},
		{"an id that is no session", func(l []byte) string { return string(l) }, []string{"../x"}, 2},
		{"two ids", func(l []byte) string { return string(l) }, []string{testID, testID}, 2},
		{"a flag", func(l []byte) string { return string(l) }, []string{"-x"}, 2},
		{"the first record dropped", func(l []byte) string { return strings.Join(lines(l)[1:], "") }, []string{testID}, 1},
		{"a byte altered", func(l []byte) string { return strings.Replace(string(l), "a.example", "c.example", 1) }, []string{testID}, 1},
		{"truncated inside a record", func(l []byte) string { return string(l[:len(l)-5]) }, []string{testID}, 1},
		{"truncated at a record", func(l []byte) string { return strings.Join(lines(l)[:len(testRecords)-1], "") }, []string{testID}, 1},
		{"the last line repeated", func(l []byte) string { return string(l) + lines(l)[len(testRecords)-1] }, []string{testID}, 1},
		{"two records swapped", func(l []byte) string {
			s := lines(l)
			s[1], s[2] = s[2], s[1]
			return strings.Join(s, "")
		}, []string{testID}, 1},
		{"emptied", func([]byte) string { return "" }, []string{testID}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, log := auditSession(t)
			if err := os.WriteFile(filepath.Join(dir, audit.LogName), []byte(tc.edit(log)), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errs bytes.Buffer
			if got := verify(tc.args, &out, &errs); got != tc.want {
				t.Errorf("exit %d, want %d (stdout %q, stderr %q)", got, tc.want, out.String(), errs.String())
			}
			if (tc.want == 0) != (errs.Len() == 0) || (tc.want != 0 && strings.Count(errs.String(), "\n") != 1) {
				t.Errorf("stderr %q does not match exit %d: want nothing on success and one line otherwise", errs.String(), tc.want)
			}
		})
	}
}

func TestVerifyRefusesAnotherHostsKey(t *testing.T) {
	auditSession(t)
	if err := os.Remove(filepath.Join(os.Getenv("XDG_DATA_HOME"), "workcell", "audit.key")); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if got := verify([]string{testID}, &out, &errs); got != 1 {
		t.Errorf("exit %d, want 1 (stderr %q)", got, errs.String())
	}
}

func TestOCSF(t *testing.T) {
	auditSession(t)
	want := []struct{ class, category, activity, typeUID, status int }{
		{6002, 6, 3, 600203, 1},
		{4001, 4, 1, 400101, 1},
		{4001, 4, 5, 400105, 2},
		{6003, 6, 99, 600399, 1},
		{6003, 6, 99, 600399, 2},
		{6002, 6, 4, 600204, 1},
	}
	var out bytes.Buffer
	if got := logs([]string{"--format", "ocsf", testID}, &out, &out); got != 0 {
		t.Fatalf("exit %d: %s", got, out.String())
	}
	first := out.String()
	got := strings.Split(strings.TrimSuffix(first, "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d: %s", len(got), len(want), first)
	}
	for i, w := range want {
		var ev map[string]any
		if err := json.Unmarshal([]byte(got[i]), &ev); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		num := func(k string) int { f, _ := ev[k].(float64); return int(f) }
		if num("class_uid") != w.class || num("category_uid") != w.category || num("activity_id") != w.activity ||
			num("type_uid") != w.typeUID || num("status_id") != w.status || num("time") != 1767323045006 {
			t.Errorf("line %d: %s, want %+v", i, got[i], w)
		}
	}
	if !strings.Contains(got[2], `"dst_endpoint":{"hostname":"b.example","port":53}`) || !strings.Contains(got[2], `"status_detail":"name_not_allowed"`) {
		t.Errorf("a refusal does not name the host and the reason: %s", got[2])
	}
	if strings.Contains(first, `"unmapped":{"event"`) {
		t.Errorf("a known record kind came out as a base event: %s", first)
	}
	// determinism: the same log gives the same bytes
	var again bytes.Buffer
	logs([]string{"--format=ocsf", testID}, &again, &again)
	if again.String() != first {
		t.Errorf("a second export differs:\n%s\n%s", first, again.String())
	}
	for _, args := range [][]string{{"--format", "json", testID}, {"--format"}} {
		if got := logs(args, &out, &out); got != 2 {
			t.Errorf("log %v exit %d, want 2", args, got)
		}
	}
}
