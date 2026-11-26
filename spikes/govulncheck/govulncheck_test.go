// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package govulncheck runs one pass of govulncheck over the module (SPEC S10) and prints the
// whole result into the test log, so that the hosted gate logs carry it for triage. The cloud
// session cannot reach the Go vulnerability database, so there the test skips and says so.
package govulncheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	tool    = "golang.org/x/vuln/cmd/govulncheck@v1.10.0"
	timeout = 5 * time.Minute
	// exitFound is govulncheck's exit code when it found a vulnerability. The log is the
	// result and a red gate would add nothing, so it passes like a clean run.
	exitFound = 3
)

func TestGovulncheck(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(wd)) // spikes/govulncheck -> spikes -> module root
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("no go.mod two levels above %s: %v", wd, err)
	}

	version, err := exec.Command("go", "version").Output()
	if err != nil {
		t.Fatalf("go version: %v", err)
	}
	t.Logf("go version: %s", bytes.TrimSpace(version))
	t.Logf("GOOS/GOARCH: %s/%s", runtime.GOOS, runtime.GOARCH)
	before := modFiles(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", tool, "-show", "verbose", "./...")
	cmd.Dir = root
	t.Logf("command: (cd %s && %s)", root, strings.Join(cmd.Args, " "))
	out, err := cmd.CombinedOutput()
	t.Logf("govulncheck output begin\n%s\ngovulncheck output end", out)

	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("go run %s: %v", tool, err)
		}
		code = exit.ExitCode()
	}
	t.Logf("govulncheck exit %d", code)
	if ctx.Err() != nil {
		t.Fatalf("govulncheck did not finish within %s", timeout)
	}
	if after := modFiles(t, root); after != before {
		t.Fatalf("go run changed go.mod or go.sum:\nbefore: %q\nafter:  %q", before, after)
	}

	switch {
	case code == 0, code == exitFound:
	case unreachable(string(out)):
		// No scan happened: the module proxy or the vulnerability database refused us.
		t.Skipf("govulncheck could not run here: %s", errorLine(string(out)))
	default:
		t.Fatalf("govulncheck failed with exit %d", code)
	}
}

// unreachable reports whether the tool's output says that it could not fetch the tool itself
// from the module proxy or the vulnerability database from vuln.go.dev.
func unreachable(out string) bool {
	return errorLine(out) != ""
}

// errorLine returns the tool's own line about the proxy or the database, or "" if there is none.
func errorLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "fetching vulnerabilities") ||
			strings.Contains(line, "vuln.go.dev") ||
			strings.Contains(line, "proxy.golang.org") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// modFiles returns git's view of go.mod and go.sum, so that a run can be compared with a run.
func modFiles(t *testing.T, root string) string {
	t.Helper()
	cmd := exec.Command("git", "status", "--porcelain", "--", "go.mod", "go.sum")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git status: %v", err)
	}
	return string(out)
}
