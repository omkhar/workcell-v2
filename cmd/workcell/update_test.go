// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/provider"
)

// tarball is a one-file layer, "package/bin/fake" holding body, gzip-compressed or plain.
func tarball(t *testing.T, body string, gz bool) []byte {
	var buf bytes.Buffer
	var w io.WriteCloser = gzip.NewWriter(&buf)
	if !gz {
		w = struct {
			io.Writer
			io.Closer
		}{&buf, io.NopCloser(nil)}
	}
	tw := tar.NewWriter(w)
	for _, h := range []*tar.Header{
		{Name: "package/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "package/bin/fake", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	w.Close()
	return buf.Bytes()
}

// TestUpdate walks one data directory through installs, a rollback, --to and the refusals,
// against a loopback TLS upstream (T8) with rows the test supplies (A11): the markers only
// ever name a complete image, a digest mismatch leaves current untouched, and the record
// holds one line per step.
func TestUpdate(t *testing.T) {
	bodies := map[string][]byte{"/v1.tgz": tarball(t, "one", true), "/v2.tgz": tarball(t, "two", true), "/v3.tar": tarball(t, "three", false)}
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if b, ok := bodies[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	sum := func(path string) string { s := sha256.Sum256(bodies[path]); return hex.EncodeToString(s[:]) }
	release := func(version, path, digest, arch string) pins.Release {
		return pins.Release{Version: version, Artifacts: map[string]pins.Artifact{arch: {URL: srv.URL + path, SHA256: digest}}}
	}
	v1 := release("1.0.0", "/v1.tgz", sum("/v1.tgz"), runtime.GOARCH)
	v2 := release("2.0.0", "/v2.tgz", sum("/v2.tgz"), runtime.GOARCH)
	v3 := release("3.0.0", "/v3.tar", sum("/v3.tar"), runtime.GOARCH)
	bad := release("3.0.0", "/v3.tar", sum("/v2.tgz"), runtime.GOARCH)
	row := func(cur pins.Release, prev *pins.Release) []pins.Pin {
		return []pins.Pin{{Name: "fake-cli", Release: cur, Previous: prev}}
	}
	img := func(r pins.Release) string {
		return r.Version + "-" + r.Artifacts[runtime.GOARCH].SHA256[:16] + ".ext4"
	}
	binary := provider.Provider{Name: "fake", Install: provider.Install{Method: "binary", Pin: "fake-cli"}}
	steps := []struct {
		name          string
		rows          []pins.Pin
		prov          provider.Provider
		to            string
		rollback      bool
		want          string // the result line; "" for a refusal
		refusal       string // text of the refusal
		cur, prev     string // the markers afterwards; "" for none
		fetch, result string
	}{
		{name: "rollback with nothing", rows: row(v1, nil), prov: binary, rollback: true, refusal: "no earlier layer", result: "refused"},
		{name: "first install", rows: row(v1, nil), prov: binary, want: "fake 1.0.0 " + v1.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v1), fetch: "/v1.tgz", result: "installed"},
		{name: "already current", rows: row(v1, nil), prov: binary, want: "fake 1.0.0 " + v1.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v1)},
		{name: "second install keeps the first", rows: row(v2, &v1), prov: binary, want: "fake 2.0.0 " + v2.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v2), prev: img(v1), fetch: "/v2.tgz", result: "installed"},
		{name: "rollback", rows: row(v2, &v1), prov: binary, rollback: true, want: "fake 1.0.0 " + v1.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v1), prev: img(v2), result: "rolled_back"},
		{name: "to the current version on disk", rows: row(v2, &v1), prov: binary, to: "2.0.0", want: "fake 2.0.0 " + v2.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v2), prev: img(v1), result: "rolled_back"},
		{name: "to the previous version on disk", rows: row(v2, &v1), prov: binary, to: "1.0.0", want: "fake 1.0.0 " + v1.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v1), prev: img(v2), result: "rolled_back"},
		{name: "to an unknown version", rows: row(v2, &v1), prov: binary, to: "9.9.9", refusal: "9.9.9 is not the row's current 2.0.0", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "digest mismatch", rows: row(bad, &v1), prov: binary, refusal: "sha256 " + sum("/v3.tar") + " is not the row's " + sum("/v2.tgz"), cur: img(v1), prev: img(v2), fetch: "/v3.tar", result: "refused"},
		{name: "no artifact for this arch", rows: row(release("3.0.0", "/v3.tar", sum("/v3.tar"), "other"), &v1), prov: binary, refusal: "no artifact with a digest for " + runtime.GOARCH, cur: img(v1), prev: img(v2), result: "refused"},
		{name: "not a binary install", rows: row(v3, &v1), prov: provider.Provider{Name: "fake", Install: provider.Install{Method: "npm", Package: "fake"}}, refusal: "binaries only", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "no row", rows: nil, prov: binary, refusal: "no row under pins/", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "third install from plain tar drops the oldest", rows: row(v3, &v2), prov: binary, want: "fake 3.0.0 " + v3.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v3), prev: img(v1), fetch: "/v3.tar", result: "installed"},
	}
	dir := filepath.Join(t.TempDir(), "data") // not there yet: the first step makes it
	layers := filepath.Join(dir, "layers", "fake")
	var results []string
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			before := hits.Load()
			got, err := installer{dir, s.rows, srv.Client()}.update(context.Background(), s.prov, s.to, s.rollback)
			switch {
			case s.want != "" && (err != nil || got != s.want):
				t.Fatalf("got %q, %v; want %q", got, err, s.want)
			case s.want == "" && (err == nil || !strings.Contains(err.Error(), s.refusal) || !strings.HasPrefix(err.Error(), "fake: ")):
				t.Fatalf("got %q, %v; want a refusal naming the agent and %q", got, err, s.refusal)
			}
			if n := hits.Load() - before; (n != 0) != (s.fetch != "") || n > 1 {
				t.Errorf("%d fetches; want one of %q or none", n, s.fetch)
			}
			if cur, prev := marker(layers, "current"), marker(layers, "previous"); cur != s.cur || prev != s.prev {
				t.Errorf("markers current=%q previous=%q; want %q, %q", cur, prev, s.cur, s.prev)
			}
			entries, _ := os.ReadDir(layers)
			var files []string
			for _, e := range entries {
				if n := e.Name(); n != "current" && n != "previous" {
					files = append(files, n)
				}
			}
			var want []string
			for _, m := range []string{s.cur, s.prev} {
				if m != "" {
					want = append(want, m)
				}
			}
			if slices.Sort(want); !slices.Equal(files, want) {
				t.Errorf("layer files %v; want exactly the marked images %v", files, want)
			}
			for _, m := range want {
				b, err := os.ReadFile(filepath.Join(layers, m))
				if err != nil || len(b) < 2048 || b[1024+0x38] != 0x53 || b[1024+0x39] != 0xEF {
					t.Errorf("%s: %v, %d bytes; want an ext4 image", m, err, len(b))
				}
			}
			if s.result != "" {
				results = append(results, s.result)
			}
		})
	}
	rec, err := os.ReadFile(filepath.Join(dir, "updates.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(rec), "\n"), "\n")
	if len(lines) != len(results) {
		t.Fatalf("%d record lines; want one per step that changed or refused: %d", len(lines), len(results))
	}
	for i, l := range lines {
		var r updateRecord
		if err := json.Unmarshal([]byte(l), &r); err != nil || r.Name != "fake" || r.Result != results[i] || r.Time == "" || !strings.HasPrefix(l, `{"time":`) {
			t.Errorf("line %d %s: %v; want result %s for fake, time first", i, l, err, results[i])
		}
		if r.Result != "refused" && (len(r.Digest) != 64 || r.Version == "") {
			t.Errorf("line %d %s: an install or rollback records the version and the full digest", i, l)
		}
	}
}

// TestUpdateUsage: the verb refuses --to with --rollback, either flag without an agent, and
// more than one agent, before it touches anything.
func TestUpdateUsage(t *testing.T) {
	for _, args := range [][]string{{"--to", "1.0.0", "--rollback", "x"}, {"--to", "1.0.0"}, {"--rollback"}, {"a", "b"}, {"--bogus"}} {
		if rc := update(args, io.Discard, io.Discard); rc != 2 {
			t.Errorf("update %v: exit %d, want 2", args, rc)
		}
	}
}
