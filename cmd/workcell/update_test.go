// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/channel"
	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/provider"
)

// tarball is a layer holding body at each of the names, as regular files of mode 0755,
// gzip-compressed or plain.
func tarball(t *testing.T, body string, gz bool, names ...string) []byte {
	var buf bytes.Buffer
	var w io.WriteCloser = gzip.NewWriter(&buf)
	if !gz {
		w = struct {
			io.Writer
			io.Closer
		}{&buf, io.NopCloser(nil)}
	}
	tw := tar.NewWriter(w)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	w.Close()
	return buf.Bytes()
}

// TestUnpack: a layer's shape is told by content. A bare file, a tar whose root holds one
// file under any name, and a tar that already holds bin/<binary> each give bin/<binary>,
// mode 0755; a tar whose root holds two files, or a bin/ without the binary, is refused.
func TestUnpack(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string // the bytes of bin/fake; "" for a refusal
	}{
		{"bare file", []byte("#!/bin/sh\n"), "#!/bin/sh\n"},
		{"one root file", tarball(t, "x", true, "fake-x86_64-unknown-linux-musl"), "x"},
		{"bin/fake already there", tarball(t, "y", false, "bin/fake", "LICENSE"), "y"},
		{"two root files", tarball(t, "z", true, "fake", "LICENSE"), ""},
		{"bin without the binary", tarball(t, "z", true, "fake", "bin/other"), ""},
		{"gzip that is not a tar", append([]byte{0x1f, 0x8b}, make([]byte, 300)...), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "artifact")
			if err != nil {
				t.Fatal(err)
			}
			f.Write(tc.body)
			f.Seek(0, io.SeekStart)
			tr, err := unpack(f, "fake")
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "bin/fake") && !strings.Contains(err.Error(), "layer") {
					t.Fatalf("got %v; want a refusal", err)
				}
				return
			}
			n := tr.Lookup("bin/fake")
			if err != nil || n == nil || n.Mode != 0o755 || string(n.Data) != tc.want || len(tr.Names("/")) != 1+strings.Count(tc.name, "already") {
				t.Fatalf("got %v, %+v; want bin/fake mode 0755 holding %q", err, n, tc.want)
			}
		})
	}
}

// TestUpdate walks one data directory through installs of each shape, a rollback, --to and
// the refusals, against a loopback TLS upstream (T8) with rows the test supplies (A11): the
// markers only ever name a complete image, a digest mismatch or a shape refused leaves them
// untouched, and the record holds one line per step.
func TestUpdate(t *testing.T) {
	bodies := map[string][]byte{"/v1.tgz": tarball(t, "one", true, "bin/fake"), "/v2.tgz": tarball(t, "two", true, "fake-x86_64-unknown-linux-musl"),
		"/v3.tar": tarball(t, "three", false, "bin/fake"), "/v4": []byte("#!/bin/sh\necho four\n"), "/v5.tgz": tarball(t, "five", true, "fake", "LICENSE")}
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
	v4 := release("4.0.0", "/v4", sum("/v4"), runtime.GOARCH)
	v5 := release("5.0.0", "/v5.tgz", sum("/v5.tgz"), runtime.GOARCH)
	bad := release("3.0.0", "/v3.tar", sum("/v2.tgz"), runtime.GOARCH)
	row := func(cur pins.Release, prev *pins.Release) []pins.Pin {
		return []pins.Pin{{Name: "fake-cli", Release: cur, Previous: prev}}
	}
	img := func(r pins.Release) string {
		return r.Version + "-" + r.Artifacts[runtime.GOARCH].SHA256 + ".ext4"
	}
	binary := provider.Provider{Name: "fake", Binary: "fake", Install: provider.Install{Method: "binary", Pin: "fake-cli"}}
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
		{name: "to an unknown version", rows: row(v2, &v1), prov: binary, to: "9.9.9", refusal: "9.9.9 is in neither pins nor previous", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "digest mismatch", rows: row(bad, &v1), prov: binary, refusal: "sha256 " + sum("/v3.tar") + " is not the pin's " + sum("/v2.tgz"), cur: img(v1), prev: img(v2), fetch: "/v3.tar", result: "refused"},
		{name: "no artifact for this arch falls back to the previous", rows: row(release("3.0.0", "/v3.tar", sum("/v3.tar"), "other"), &v1), prov: binary, want: "fake 1.0.0 " + v1.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v1), prev: img(v2)},
		{name: "not a binary install", rows: row(v3, &v1), prov: provider.Provider{Name: "fake", Install: provider.Install{Method: "npm", Package: "fake"}}, refusal: "binaries only", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "no row", rows: nil, prov: binary, refusal: "no row under pins/", cur: img(v1), prev: img(v2), result: "refused"},
		{name: "third install from plain tar drops the oldest", rows: row(v3, &v2), prov: binary, want: "fake 3.0.0 " + v3.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v3), prev: img(v1), fetch: "/v3.tar", result: "installed"},
		{name: "two root files", rows: row(v5, &v3), prov: binary, refusal: "neither bin/fake nor one file", cur: img(v3), prev: img(v1), fetch: "/v5.tgz", result: "refused"},
		{name: "unpinned row", rows: []pins.Pin{{Name: "fake-cli"}}, prov: binary, refusal: "pins no release yet", cur: img(v3), prev: img(v1), result: "refused"},
		{name: "bare file install", rows: row(v4, &v3), prov: binary, want: "fake 4.0.0 " + v4.Artifacts[runtime.GOARCH].SHA256[:16], cur: img(v4), prev: img(v3), fetch: "/v4", result: "installed"},
	}
	dir := filepath.Join(t.TempDir(), "data") // not there yet: the first step makes it
	layers := filepath.Join(dir, "layers", "fake")
	var results []string
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			before := hits.Load()
			got, err := installer{dir: dir, rows: s.rows, client: srv.Client()}.update(context.Background(), s.prov, nil, s.to, s.rollback)
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

// TestChannel runs the product's own update client, as the [update] table of a config file sets it up (channel,
// ca, key), against a loopback channel (T8): a valid manifest installs its pin and advances the serial kept; each
// hostile manifest installs nothing and leaves the serial where a verified one put it; a redirect of channel.json is not
// followed, nor one of the artifact to a listener that is not https, while one to a path of the same https server is; channel.json
// is read to 64 KiB and no further; --to outside pins and previous installs nothing; a valid successor installs again; the cool-off with nothing before it installs nothing.
func TestChannel(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	served, moved, seen := map[string][]byte{}, map[string]string{}, map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen[r.URL.Path]++
		switch b, ok := served[r.URL.Path]; {
		case moved[r.URL.Path] != "":
			http.Redirect(w, r, moved[r.URL.Path], http.StatusFound)
		case ok:
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	})
	srv, plain := httptest.NewTLSServer(handler), httptest.NewServer(handler) // the channel and its upstream; a listener that is not https
	defer srv.Close()
	defer plain.Close()
	set := func(path string, b []byte) { mu.Lock(); served[path] = b; mu.Unlock() }
	move := func(path, to string) { mu.Lock(); moved[path] = to; mu.Unlock() }
	cfg, data := t.TempDir(), t.TempDir()
	ca := filepath.Join(cfg, "ca.pem")
	if err := errors.Join(os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700),
		os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600),
		os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nchannel = \""+srv.URL+"/channel.json\"\nca = \""+ca+"\"\nkey = \""+hex.EncodeToString(pub)+"\"\n"), 0o600)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_DATA_HOME", data)
	in, err := newInstaller()
	if err != nil || in.channel != srv.URL+"/channel.json" || len(in.keys) != 1 || in.client.Transport == nil {
		t.Fatalf("newInstaller = %+v, %v; want the table's channel, key and roots", in, err)
	}
	in.rows = []pins.Pin{{Name: "fake-cli", Release: pins.Release{Version: "0"}}} // the row is only the pin's name: the channel says what is installed
	prov := provider.Provider{Name: "fake", Binary: "fake", Install: provider.Install{Method: "binary", Pin: "fake-cli"}}
	now, day := time.Now().Unix(), int64(24*3600)
	pin := func(version, path string, body []byte) map[string]map[string]channel.Pin { // path may be a URL of its own
		sum := sha256.Sum256(body)
		set(path, body)
		return map[string]map[string]channel.Pin{"fake-cli": {runtime.GOARCH: {Version: version, URL: strings.TrimPrefix(srv.URL+path, srv.URL+"http"), SHA256: hex.EncodeToString(sum[:]), Released: now - 7*day}}}
	}
	publish := func(m channel.Manifest, signer ed25519.PrivateKey, edit func([]byte) []byte) {
		body, _ := json.Marshal(m)
		raw, _ := channel.Sign(body, []ed25519.PrivateKey{signer})
		move("/channel.json", "")
		set("/channel.json", edit(raw))
	}
	same := func(b []byte) []byte { return b }
	corrupt := func(b []byte) []byte { // the signature with its first character another base64 letter
		i := bytes.Index(b, []byte(`"sig":"`)) + 7
		b[i] = 'A' + (b[i]-'A'+1)%26
		return b
	}
	pad := func(b []byte) []byte { return append(b, bytes.Repeat([]byte(" "), channel.MaxBytes)...) }
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	honest, bad := []byte("#!/bin/sh\necho honest\n"), []byte("#!/bin/sh\necho bad\n")
	good := channel.Manifest{Serial: now - 120, Expires: now - 120 + 13*day, Pins: pin("1.0.0", "/honest", honest)}
	variant := func(serial int64, path string) channel.Manifest {
		return channel.Manifest{Serial: serial, Expires: serial + 13*day, Pins: pin("1.0.1", path, bad), Previous: good.Pins}
	}
	steps := []struct {
		name    string
		serve   func()
		to      string
		cooloff time.Duration
		want    string // the version current afterwards
		serial  int64  // the serial kept afterwards
		refusal string
	}{
		{"a valid manifest installs", func() { publish(good, key, same) }, "1.0.0", 0, "1.0.0", now - 120, ""},
		{"a wrong key", func() { publish(variant(now-60, "/wrong-key"), wrong, same) }, "1.0.1", 0, "1.0.0", now - 120, "no valid signature"},
		{"a corrupt signature", func() { publish(variant(now-60, "/corrupt"), key, corrupt) }, "1.0.1", 0, "1.0.0", now - 120, "no valid signature"},
		{"a lower serial", func() { publish(variant(now-120-day, "/lower"), key, same) }, "1.0.1", 0, "1.0.0", now - 120, "serial lower"},
		{"a serial a day ahead", func() { publish(variant(now+25*3600, "/ahead"), key, same) }, "1.0.1", 0, "1.0.0", now - 120, "a day ahead"},
		{"channel.json past 64 KiB", func() { publish(variant(now-60, "/big"), key, pad) }, "1.0.1", 0, "1.0.0", now - 120, "over the size cap"},
		{"channel.json redirected", func() {
			publish(variant(now-60, "/elsewhere"), key, same)
			set("/elsewhere", served["/channel.json"])
			move("/channel.json", "/elsewhere")
		}, "1.0.1", 0, "1.0.0", now - 120, "HTTP 302"},
		{"an artifact digest that does not match", func() { publish(variant(now-60, "/tampered"), key, same); set("/tampered", []byte("other")) }, "1.0.1", 0, "1.0.0", now - 60, "sha256"},
		{"an artifact URL that redirects to a listener that is not https", func() {
			publish(variant(now-50, "/moved-off"), key, same)
			move("/moved-off", plain.URL+"/plain")
			set("/plain", bad)
		}, "1.0.1", 0, "1.0.0", now - 50, "transport failure"},
		{"an artifact URL that is not https", func() { publish(variant(now-40, "http://127.0.0.1/plain"), key, same) }, "1.0.1", 0, "1.0.0", now - 50, "https"},
		{"--to a version in neither pins nor previous", func() { publish(variant(now-30, "/neither"), key, same) }, "9.9.9", 0, "1.0.0", now - 30, "neither pins nor previous"},
		{"within the user's cool-off the previous one stays", func() {}, "", 30 * 24 * time.Hour, "1.0.0", now - 30, ""},
		{"a valid successor installs through a redirect on the same server", func() {
			publish(variant(now-20, "/moved"), key, same)
			move("/moved", "/artifact")
			set("/artifact", bad)
		}, "1.0.1", 0, "1.0.1", now - 20, ""},
		{"within the cool-off with no previous one", func() {
			publish(channel.Manifest{Serial: now - 10, Expires: now - 10 + 13*day, Pins: pin("1.0.2", "/alone", honest)}, key, same)
		}, "", 30 * 24 * time.Hour, "1.0.1", now - 10, "cool-off lets in"},
	}
	layers := filepath.Join(data, "workcell", "layers", "fake")
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			s.serve()
			in.cooloff = s.cooloff
			ctx := context.Background()
			_, err := in.update(ctx, prov, func() (*channel.Manifest, error) { return in.manifest(ctx) }, s.to, false)
			if (err == nil) != (s.refusal == "") || err != nil && !strings.Contains(err.Error(), s.refusal) {
				t.Errorf("update = %v; want refusal %q", err, s.refusal)
			}
			serial, _ := os.ReadFile(filepath.Join(data, "workcell", "channel.serial"))
			if cur := marker(layers, "current"); !strings.HasPrefix(cur, s.want+"-") || strings.TrimSpace(string(serial)) != strconv.FormatInt(s.serial, 10) {
				t.Errorf("current %q, serial %q; want version %s and serial %d", cur, serial, s.want, s.serial)
			}
		})
	}
	if mu.Lock(); seen["/artifact"] != 1 || seen["/plain"] != 0 || seen["/elsewhere"] != 0 || seen["/channel.json"] == 0 {
		t.Errorf("requests %v; want one to the artifact's redirect target on the same https server and none to the others", seen)
	}
}
