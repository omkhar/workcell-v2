// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package guest

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteTrust(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"
	old := "-----BEGIN CERTIFICATE-----\nAwQF\n-----END CERTIFICATE-----"
	cases := []struct{ name, bundle, want string }{
		{"create", "", ca},
		{"append", old, old + "\n" + ca},
		{"present", old + "\n" + ca, old + "\n" + ca},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "certs")
			if tc.bundle != "" {
				os.MkdirAll(dir, 0o755)
				os.WriteFile(filepath.Join(dir, bundleFile), []byte(tc.bundle), 0o644)
			}
			for range 2 { // the same CA twice is written once
				if err := WriteTrust(dir, []byte(ca), time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			bundle, _ := os.ReadFile(filepath.Join(dir, bundleFile))
			alone, _ := os.ReadFile(filepath.Join(dir, caFile))
			jks, _ := os.ReadFile(filepath.Join(dir, jksFile))
			if string(bundle) != tc.want || string(alone) != ca {
				t.Errorf("bundle %q and CA file %q, want %q and %q", bundle, alone, tc.want, ca)
			}
			if n := len(certificates([]byte(tc.want))); len(jks) < 12 || binary.BigEndian.Uint32(jks) != 0xFEEDFEED || binary.BigEndian.Uint32(jks[8:]) != uint32(n) {
				t.Errorf("keystore %x does not hold %d entries", jks[:min(len(jks), 12)], n)
			}
		})
	}
}

func TestTrustEnvNamesTheFiles(t *testing.T) {
	for _, kv := range TrustEnv("/d") {
		if !strings.Contains(kv, "/d/") || strings.Count(kv, "=") == 0 {
			t.Errorf("%q does not name a file under /d", kv)
		}
	}
}
