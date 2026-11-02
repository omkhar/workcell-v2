// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func uniqueName(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

// userSearchList returns the paths on the user keychain search list.
func userSearchList(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command(securityPath, "list-keychains", "-d", "user").Output()
	if err != nil {
		t.Skipf("cannot read the keychain search list: %v", err)
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		if p := strings.Trim(strings.TrimSpace(line), `"`); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// This test changes the global user search list, so it must not run in parallel.
func TestResolveKeychainReadsGenericPassword(t *testing.T) {
	service, account := uniqueName(t, "workcell-test-svc-"), uniqueName(t, "acct-")
	const value = "sk-keychain-test"

	// A new keychain is unlocked, so the test needs no prompt in any session.
	path := filepath.Join(t.TempDir(), "workcell-test.keychain-db")
	if out, err := exec.Command(securityPath, "create-keychain", "-p", "pw", path).CombinedOutput(); err != nil {
		t.Skipf("cannot create a keychain: %v: %s", err, out)
	}
	original := userSearchList(t)
	t.Cleanup(func() {
		exec.Command(securityPath, append([]string{"list-keychains", "-d", "user", "-s"}, original...)...).Run()
		exec.Command(securityPath, "delete-keychain", path).Run()
	})
	front := append([]string{"list-keychains", "-d", "user", "-s", path}, original...)
	if out, err := exec.Command(securityPath, front...).CombinedOutput(); err != nil {
		t.Skipf("cannot change the keychain search list: %v: %s", err, out)
	}

	// -A lets any program read the item, so the read cannot raise a prompt.
	add := exec.Command(securityPath, "add-generic-password", "-s", service, "-a", account, "-w", value, "-A", path)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add-generic-password: %v: %s", err, out)
	}

	got, err := Resolve(context.Background(), "keychain:"+service+"/"+account)
	if err != nil || !bytes.Equal(got, []byte(value)) {
		t.Fatalf("Resolve = %d bytes, %v; want %d bytes", len(got), err, len(value))
	}
	Zero(got)
}

func TestResolveKeychainMissingItemFailsClosed(t *testing.T) {
	source := "keychain:" + uniqueName(t, "workcell-absent-") + "/" + uniqueName(t, "acct-")
	if got, err := Resolve(context.Background(), source); err == nil || got != nil {
		t.Fatalf("Resolve = %d bytes, %v; want a refusal", len(got), err)
	}
}
