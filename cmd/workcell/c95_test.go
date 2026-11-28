// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// C95 (I14): a channel.serial store that is present but holds no number must not count as floor 0. This file belongs at cmd/workcell/c95_test.go.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/channel"
)

// TestC95DamagedSerialStoreRefusesOlderManifest: against an intact floor a signed manifest with a lower serial is refused (control); against a store that is present but holds "", "x" or "\n" it must be refused too, the store left as it was (finding); with no store at all the newer manifest verifies (control).
func TestC95DamagedSerialStoreRefusesOlderManifest(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	in := installer{dir: t.TempDir(), keys: []channel.Key{{Public: pub, NotAfter: now.Add(time.Hour)}}}
	sign := func(serial int64) []byte {
		body, _ := json.Marshal(channel.Manifest{Serial: serial, Expires: serial + 13*24*3600})
		raw, err := channel.Sign(body, []ed25519.PrivateKey{key})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	newer, older, store := sign(now.Unix()-60), sign(now.Unix()-3600), filepath.Join(in.dir, "channel.serial")
	if _, err := in.verify(newer, now); err != nil {
		t.Fatalf("control: the newer manifest with no store yet: %v; want accepted", err)
	}
	if _, err := in.verify(older, now); err == nil {
		t.Fatal("control: the older manifest against the intact store was accepted; want refused as a lower serial")
	}
	for _, damaged := range []string{"", "x", "\n"} {
		if err := os.WriteFile(store, []byte(damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := in.verify(older, now)
		if after, _ := os.ReadFile(store); err == nil || string(after) != damaged {
			t.Errorf("finding: store holding %q: verify(older) = %v, store now %q; want an error and the store untouched", damaged, err, after)
		}
	}
	os.Remove(store)
	if _, err := in.verify(newer, now); err != nil {
		t.Errorf("control: the newer manifest with the store absent: %v; want accepted", err)
	}
}
