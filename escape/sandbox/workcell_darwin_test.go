// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A fresh copy of a Go binary, signed, carries the virtualization
// entitlement and still runs. The copy is this test binary.
func TestSign(t *testing.T) {
	if err := hostReady(); err != nil {
		t.Skip(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "workcell")
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := sign(context.Background(), dir, bin); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("codesign", "-d", "--entitlements", "-", "--xml", bin).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "<key>com.apple.security.virtualization</key><true/>") {
		t.Fatalf("codesign -d: %v: %s", err, out)
	}
	if out, err := exec.Command(bin, "-test.run", "^$").CombinedOutput(); err != nil {
		t.Fatalf("the signed copy does not run: %v: %s", err, out)
	}
}

// With this Mac's setup steered passes the product's argv through as it
// is; a resolver the setup does not name is refused (SPEC T8).
func TestSteered(t *testing.T) {
	argv := []string{"workcell", "run"}
	got, err := steered("", "127.5.3.53", nil, argv, 0)
	if err != nil || len(got) != 2 || got[0] != argv[0] || got[1] != argv[1] {
		t.Fatalf("steered = %v, %v; want %v", got, err, argv)
	}
	for _, bad := range []string{"127.5.3.54", "127.0.0.1"} {
		if _, err := steered("", bad, nil, argv, 0); err == nil {
			t.Fatalf("steered to %s: no error", bad)
		}
	}
}
