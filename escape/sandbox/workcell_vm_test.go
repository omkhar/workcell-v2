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
)

// TestAuditReadsTheProductsRecords lays out sessions as the product keeps
// them under the data directory and checks that Audit returns the newest
// record's own path and every record oldest session first.
func TestAuditReadsTheProductsRecords(t *testing.T) {
	defer func(xdg string) { prepared.xdg = xdg }(prepared.xdg)
	prepared.xdg = t.TempDir()
	sessions := filepath.Join(prepared.xdg, "workcell", "sessions")
	write := func(id, body string) {
		t.Helper()
		p := filepath.Join(sessions, id, "audit.log")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := &workcell{}
	if _, _, err := w.Audit(context.Background()); err == nil {
		t.Fatal("Audit before Start: want an error")
	}
	w.dir = t.TempDir()
	newer, older := "20260102T000000.000000000Z-newer", "20260101T000000.000000000Z-older"
	write(newer, `{"n":3}`+"\n") // written first: the id, not the file's age, orders
	write(older, `{"n":1}`+"\n"+`{"n":2}`+"\n")
	if err := os.Mkdir(filepath.Join(sessions, "20260103T000000.000000000Z-empty"), 0o755); err != nil { // no record: not a session yet
		t.Fatal(err)
	}
	path, records, err := w.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(sessions, newer, "audit.log"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if want := []string{`{"n":1}`, `{"n":2}`, `{"n":3}`}; !slices.Equal(records, want) {
		t.Errorf("records = %q, want %q", records, want)
	}
}
