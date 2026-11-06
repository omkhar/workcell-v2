// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/bump"
	"github.com/omkhar/workcell/v2/internal/channel"
	"github.com/omkhar/workcell/v2/internal/pins"
)

func TestChannelFile(t *testing.T) {
	keyPEM := func(k any) string {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	pub1, k1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, k2, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := map[string]string{"k1.pem": keyPEM(k1), "k2.pem": keyPEM(k2), "ec.pem": keyPEM(ec), "junk.pem": "not pem"}
	pubs := map[string]ed25519.PublicKey{"k1.pem": pub1, "k2.pem": pub2}
	row := func(url, sum string, released time.Time) pins.Pin {
		p := pin("tool", pins.Guest, "1.0.0")
		p.Artifacts = map[string]pins.Artifact{"amd64": {URL: url, SHA256: sum}}
		p.Released = released
		return p
	}
	ok, early := row("https://example.test/tool", strings.Repeat("a", 64), now.Add(-time.Hour)), now.Add(-time.Hour)
	for _, c := range []struct {
		name string
		row  pins.Pin
		args []string
		code int
	}{
		{"one key", ok, []string{"k1.pem"}, 0},
		{"two keys, the second alone trusted", ok, []string{"k1.pem", "k2.pem"}, 0},
		{"http url, signed but not verifiable", row("http://example.test/tool", ok.Artifacts["amd64"].SHA256, early), []string{"k1.pem"}, 2},
		{"digest not lowercase hex", row(ok.Artifacts["amd64"].URL, strings.Repeat("A", 64), early), []string{"k1.pem"}, 2},
		{"key file that is not PEM", ok, []string{"junk.pem"}, 2},
		{"key file that is not ed25519", ok, []string{"k1.pem", "ec.pem"}, 2},
		{"row without a release time", row(ok.Artifacts["amd64"].URL, ok.Artifacts["amd64"].SHA256, time.Time{}), []string{"k1.pem"}, 2},
		{"no key file", ok, nil, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			rows, kd, od := t.TempDir(), t.TempDir(), t.TempDir()
			for dir, files := range map[string]map[string]string{rows: {"tool.json": string(bump.Row(c.row))}, kd: keys} {
				for name, body := range files {
					_ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600) // a failed write fails the row below
				}
			}
			rowsBefore, keysBefore := snapshot(t, rows), snapshot(t, kd)
			args := []string{"-channel", filepath.Join(od, "channel.json")}
			for _, a := range c.args {
				args = append(args, filepath.Join(kd, a))
			}
			var out, stderr bytes.Buffer
			code := run(context.Background(), args, func(string) string { return "" }, bump.Tool{Pins: rows, Now: now, Out: &out}, &stderr)
			if code != c.code || !maps.Equal(snapshot(t, rows), rowsBefore) || !maps.Equal(snapshot(t, kd), keysBefore) {
				t.Fatalf("exit %d, stderr %q", code, stderr.String())
			}
			written := snapshot(t, od)
			if c.code != 0 {
				if len(written) != 0 || out.Len() != 0 {
					t.Fatalf("wrote %v, printed %q", written, out.String())
				}
				return
			}
			last := pubs[c.args[len(c.args)-1]]
			m, err := channel.Verify([]byte(written["channel.json"]), []channel.Key{{Public: last, NotAfter: now.Add(time.Hour)}}, now, 0)
			if err != nil || len(written) != 1 || m.Pins["tool"]["amd64"].URL != ok.Artifacts["amd64"].URL {
				t.Fatalf("verify %v, files %v", err, written)
			}
			for _, a := range c.args {
				if id := (channel.Key{Public: pubs[a]}).ID(); !strings.Contains(out.String(), id) || !strings.HasPrefix(out.String(), "channel serial 1795176000 keys ") {
					t.Errorf("output %q lacks %s", out.String(), id)
				}
			}
		})
	}
}
