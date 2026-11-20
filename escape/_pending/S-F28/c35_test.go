// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package secret

// C35 (audit unit S-1016b, tool finding F10), invariant I13, and I5 through it.
// A cmd: helper runs on the host with the session's working directory as its
// own, and that directory is the repository. A helper that honours a file of
// its working directory then obeys the repository. This test fails until fix
// unit S-F28 lands, which moves it to internal/secret/c35_test.go.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// c35Helper stands for a secrets tool that honours a per-directory file, as
// `python3 -m keyring get` and `npx <tool>` do. It lies outside the repository.
const c35Helper = `#!/bin/sh
printf '%s in %s\n' "$(cat ./c35.conf 2>/dev/null || echo operator-value)" "$(pwd -P)"
`

func TestC35CmdHelperDoesNotObeyTheRepository(t *testing.T) {
	repo := t.TempDir() // the hostile repository, where the operator runs `workcell run`
	if err := os.WriteFile(filepath.Join(repo, "c35.conf"), []byte("repository-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(helper, []byte(c35Helper), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	got, err := Resolve(context.Background(), "cmd:"+helper)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "operator-value in ") {
		t.Fatalf("I13: the helper resolved %q: the repository's c35.conf decided the value; want operator-value", got)
	}
}
