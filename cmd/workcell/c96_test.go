// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// C96 (I14 with B9): the self-rollback must not leave a withdrawn image current. This file belongs at cmd/workcell/c96_test.go.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/channel"
	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/provider"
)

// TestC96WithdrawnImageIsNotCurrentAfterSelfRollback: this start's apply installed B over A, and the guest's first frame is an Exit with an error, so fail sets B
// aside and points current back at A, reading no manifest; the next start's apply skips B's pin, because B is marked failed. Finding arm: the kept manifest
// withdraws A, and after apply A must not be current (B installed again, or the return to A refused). Control arm: A not withdrawn, current = A is B10's self-rollback.
func TestC96WithdrawnImageIsNotCurrentAfterSelfRollback(t *testing.T) {
	p := must(provider.All())[0] // fail finds the provider by its binary among the built-in ones
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sum := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
	a, b := "1.0.0-"+sum("a")+".ext4", "1.0.1-"+sum("b")+".ext4"
	run := func(t *testing.T, withdrawn []string) (cur, said string) {
		dir := t.TempDir()
		layers := filepath.Join(dir, "layers", p.Name)
		now := time.Now().Unix()
		m := channel.Manifest{Serial: now - 60, Expires: now - 60 + 13*24*3600, Withdrawn: withdrawn, Pins: map[string]map[string]channel.Pin{p.Install.Pin: {runtime.GOARCH: {Version: "1.0.1", URL: "https://127.0.0.1:1/b", SHA256: sum("b")}}}}
		body, _ := json.Marshal(m)
		raw, err := channel.Sign(body, []ed25519.PrivateKey{key})
		// what an apply that installed B over A leaves: both images, current B, previous A, the serial of the manifest it verified; and the day's check kept that manifest again
		err = errors.Join(err, os.MkdirAll(layers, 0o700), os.WriteFile(filepath.Join(layers, a), nil, 0o600), os.WriteFile(filepath.Join(layers, b), nil, 0o600), writeMarker(layers, "current", b), writeMarker(layers, "previous", a))
		if err = errors.Join(err, writeMarker(dir, "channel.serial", strconv.FormatInt(m.Serial, 10)), writeMarker(dir, "channel.next", string(raw))); err != nil {
			t.Fatal(err)
		}
		in := installer{dir: dir, rows: []pins.Pin{{Name: p.Install.Pin, Release: pins.Release{Version: "0"}}}, client: &http.Client{}, channel: "https://127.0.0.1:1/channel.json", keys: []channel.Key{{Public: pub, NotAfter: time.Unix(1<<40, 0)}}, fresh: []string{b + "\n" + a}}
		var out bytes.Buffer
		in.fail(p.Binary, &out) // the attacker's one act: the forged Exit frame, as run reports it
		said = "after fail current=" + marker(layers, "current") + " failed=" + marker(layers, "failed") + "; "
		in.apply([]provider.Provider{p}, &out)
		return marker(layers, "current"), said + out.String()
	}
	t.Run("control: A not withdrawn, the self-rollback leaves A current", func(t *testing.T) {
		if cur, said := run(t, nil); cur != a {
			t.Errorf("current %q, %s; want A %q", cur, said, a)
		}
	})
	t.Run("finding: A withdrawn, A must not be current", func(t *testing.T) {
		if cur, said := run(t, []string{sum("a")}); cur == a {
			t.Errorf("current is A %q, the withdrawn image, %s; want B %q current again, or the return to A refused with a line that says so", cur, said, b)
		}
	})
}
