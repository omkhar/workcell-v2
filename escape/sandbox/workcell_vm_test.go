// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || darwin

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestAuditReadsTheProductsRecords lays out sessions as the product keeps
// them under the data directory and checks that Audit returns the newest
// record's own path, every record oldest session first, and that a session
// found later keeps its place after those seen before, whatever its age.
func TestAuditReadsTheProductsRecords(t *testing.T) {
	defer func(xdg string) { prepared.xdg = xdg }(prepared.xdg)
	prepared.xdg = t.TempDir()
	sessions := filepath.Join(prepared.xdg, "workcell", "sessions")
	now := time.Now()
	write := func(id, body string, age time.Duration) {
		t.Helper()
		p := filepath.Join(sessions, id, "audit.log")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	w := &workcell{}
	if _, _, err := w.Audit(context.Background()); err == nil {
		t.Fatal("Audit before Start: want an error")
	}
	w.dir = t.TempDir()
	write("older", `{"n":1}`+"\n"+`{"n":2}`+"\n", 2*time.Hour)
	write("newer", `{"n":3}`+"\n", time.Hour)
	if err := os.Mkdir(filepath.Join(sessions, "empty"), 0o755); err != nil { // no record: not a session yet
		t.Fatal(err)
	}
	path, records, err := w.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(sessions, "newer", "audit.log"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if want := []string{`{"n":1}`, `{"n":2}`, `{"n":3}`}; !slices.Equal(records, want) {
		t.Errorf("records = %q, want %q", records, want)
	}
	write("late", `{"n":4}`+"\n", 3*time.Hour) // found after the others, so it comes after them
	path, records, err = w.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(sessions, "late", "audit.log"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if want := []string{`{"n":1}`, `{"n":2}`, `{"n":3}`, `{"n":4}`}; !slices.Equal(records, want) {
		t.Errorf("records = %q, want %q", records, want)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Audit(context.Background()); err == nil {
		t.Error("a session seen whose record is gone: want an error, since a judge would read a stale list as intact")
	}
}
