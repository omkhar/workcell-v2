// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || darwin

package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestFetchKeepsVerifiedDownloads stands in for upstream with a server that counts its requests (T8). With the pinned bytes kept under the download folder fetch asks upstream for nothing; with the folder absent, one byte of the kept file wrong, or a link under its name to a file that holds the right bytes, it downloads once and ends with the pinned bytes, kept for the next run; a download whose digest is not the pinned one is an error and is not kept.
func TestFetchKeepsVerifiedDownloads(t *testing.T) {
	defer func(dir string) { cache = dir }(cache)
	cache = filepath.Join(t.TempDir(), "kept")
	want, serve, hits := []byte("the pinned artifact"), []byte("the pinned artifact"), 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; w.Write(serve) }))
	defer srv.Close()
	sum, ctx := digest(want), context.Background()
	kept, elsewhere := filepath.Join(cache, sum), filepath.Join(t.TempDir(), "elsewhere")
	wrong := append([]byte("T"), want[1:]...)
	cases := []struct {
		name  string
		plant func() error // the folder before the fetch
		hits  int          // downloads it costs
		fails bool
	}{{"pinned bytes kept", func() error { os.MkdirAll(cache, 0o755); return os.WriteFile(kept, want, 0o644) }, 0, false}, {"one byte wrong", func() error { return os.WriteFile(kept, wrong, 0o644) }, 1, false}, {"a link under the name", func() error { os.Rename(kept, elsewhere); return os.Symlink(elsewhere, kept) }, 1, false}, {"kept again", func() error { return nil }, 0, false}, {"nothing kept", func() error { return os.RemoveAll(cache) }, 1, false}, {"upstream replaced the file", func() error { serve = wrong; return os.RemoveAll(cache) }, 1, true}}
	for _, c := range cases {
		if err := c.plant(); err != nil {
			t.Fatal(c.name, err)
		}
		before := hits
		got, err := fetch(ctx, srv.URL, sum)
		if (err != nil) != c.fails || (!c.fails && string(got) != string(want)) || hits-before != c.hits {
			t.Fatalf("%s: fetch gave %d bytes, %v, and cost %d downloads; want %d bytes, failure %v, %d downloads", c.name, len(got), err, hits-before, len(want), c.fails, c.hits)
		}
		b, err := os.ReadFile(kept)
		if fi, lerr := os.Lstat(kept); (err == nil) == c.fails || (!c.fails && (string(b) != string(want) || lerr != nil || !fi.Mode().IsRegular())) { // what the next run finds: a regular file holding the pinned bytes, or nothing
			t.Fatalf("%s: afterwards the folder holds %q, %v, %v", c.name, b, err, lerr)
		}
	}
}

// TestAuditReadsTheProductsRecords lays out sessions as the product keeps them under the data directory and checks that Audit returns the newest record's own path and every record oldest session first.
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
