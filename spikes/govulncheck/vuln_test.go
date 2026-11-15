// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package govulncheck is a one-run spike for S-1012 (SPEC S10): the cloud session cannot reach the
// vulnerability database, so the hosted gate runs govulncheck here and prints its output with -v.
// It never fails the gate (W8). The orchestrator deletes it before the unit is delivered.
package govulncheck

import (
	"os/exec"
	"testing"
)

func TestGovulncheck(t *testing.T) {
	cmd := exec.Command("go", "run", "golang.org/x/vuln/cmd/govulncheck@latest", "-show", "verbose", "./...")
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	t.Logf("GOVULNCHECK-BEGIN err=%v\n%s\nGOVULNCHECK-END", err, out)
}
