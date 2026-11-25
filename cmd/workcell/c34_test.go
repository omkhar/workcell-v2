// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// c34User is a user's policy with a sign-in row: the API on one allowed name, the token endpoint on the other.
const c34User = "[network]\nallow = [\"api.c34.test\", \"login.c34.test\", \"other.c34.test\"]\n\n[[secret]]\nname = \"k\"\n" +
	"source = \"signin:login.c34.test/oauth/token\"\nhost = \"api.c34.test\"\nheader = \"authorization\"\n"

// c34Load is the session's policy as `workcell run` loads it in a directory holding the repository file repo, "" for none: whether the token host is
// terminated on 443, and whether a rule still has the proxy read and rewrite that host's token answers.
func c34Load(t *testing.T, repo string) (reachable, rewritten bool, err error) {
	dir, work := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Chdir(work)
	if err := os.MkdirAll(filepath.Join(dir, "workcell"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workcell", "config.toml"), []byte(c34User), 0o600); err != nil {
		t.Fatal(err)
	}
	if repo != "" {
		if err := os.WriteFile(filepath.Join(work, "workcell.toml"), []byte(repo), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	allow, secrets, _, _, err := loadPolicy(nil, io.Discard)
	reachable = allow != nil && slices.Contains(allow.TLSHosts(), "login.c34.test")
	rewritten = slices.ContainsFunc(secrets, func(b binding) bool { return b.rule.SignIn != nil && b.rule.SignIn.Host == "login.c34.test" })
	return reachable, rewritten, err
}

// TestC34SignInRowDropped is finding C34 (I5, through I13): a repository's workcell.toml may only narrow, yet by dropping the user's sign-in [[secret]] row and keeping its token host it takes away the one rule that hides the token endpoint's answers, so the real tokens of a sign-in the operator completes in that session would reach the guest as issued. A session must be refused, or lose the token host, or keep the rewriting. This stops at the effective policy the session hands the proxy, not at the wire. It fails until fix unit S-F27 lands and waits in escape/_pending/S-F27/; that unit moves it to cmd/workcell/c34_test.go.
func TestC34SignInRowDropped(t *testing.T) {
	if reachable, rewritten, err := c34Load(t, ""); err != nil || !reachable || !rewritten {
		t.Fatalf("without a repository file: token host reachable %v, answers rewritten %v, %v; want true, true, nil", reachable, rewritten, err)
	}
	for name, repo := range map[string]string{
		"a [[secret]] row of another name":    "[[secret]]\nname = \"x\"\nsource = \"x\"\n",
		"an allow array without the API host": "[network]\nallow = [\"login.c34.test\", \"other.c34.test\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if reachable, rewritten, err := c34Load(t, repo); err == nil && reachable && !rewritten {
				t.Errorf("I5: the session starts with the token host login.c34.test allowed on 443 and no rule that rewrites its token answers")
			}
		})
	}
}
