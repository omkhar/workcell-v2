// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package govulncheck runs govulncheck over the whole module and writes what it says to the test log
// (SPEC S10). It is a measurement for the audit, never a gate: a finding does not fail the test, and
// when the tool cannot be built or the vulnerability database cannot be reached, the test logs the
// output and skips. It starts only processes of its own: go, and the scanner go builds.
package govulncheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	scanner      = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"
	childTimeout = 5 * time.Minute
)

// target is one GOOS/GOARCH pair to scan. The scanner reads the pair from its environment.
type target struct{ goos, goarch string }

func TestGovulncheck(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// go run pkg@version would pick the toolchain from x/vuln's own go.mod, which is older than this
	// module's, and the scanner it built could not load these packages. So build the scanner once,
	// with the toolchain this module selects, and run that binary.
	version, _ := run(t, root, nil, "go", "version")
	toolchain, code := run(t, root, nil, "go", "env", "GOVERSION")
	toolchain = strings.TrimSpace(toolchain)
	if code != 0 || !strings.HasPrefix(toolchain, "go") {
		t.Skipf("cannot tell which toolchain the module selects: %q", toolchain)
	}
	gobin := t.TempDir()
	if _, code := run(t, root, []string{"GOTOOLCHAIN=" + toolchain, "GOBIN=" + gobin}, "go", "install", scanner); code != 0 {
		t.Skip("the scanner could not be built here; its output is in the log")
	}
	bin := filepath.Join(gobin, "govulncheck")

	targets := []target{{runtime.GOOS, runtime.GOARCH}}
	if cross := (target{"darwin", "arm64"}); cross != targets[0] {
		targets = append(targets, cross)
	}
	measured := 0
	for _, tg := range targets {
		env := []string{"GOTOOLCHAIN=" + toolchain, "GOOS=" + tg.goos, "GOARCH=" + tg.goarch}
		t.Logf("--- %s/%s with %s", tg.goos, tg.goarch, strings.TrimSpace(version))
		_, code := run(t, root, env, bin, "-show", "verbose", "./...")
		switch code {
		case 0:
			t.Logf("%s/%s: no vulnerability found", tg.goos, tg.goarch)
			measured++
		case 3:
			t.Logf("%s/%s: govulncheck reported findings; triage them under S4", tg.goos, tg.goarch)
			measured++
		default:
			t.Logf("%s/%s: not measured (exit %d); the reason is in the output above", tg.goos, tg.goarch, code)
		}
	}
	if measured == 0 {
		t.Skip("govulncheck measured nothing here; the output is in the log")
	}
}

// run starts argv in dir with extra added to the environment, logs the argv, the additions and the
// complete combined output, and returns that output with the exit code. -1 means the child did not
// run or did not exit by itself.
func run(t *testing.T, dir string, extra []string, argv ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), childTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extra...)
	t.Logf("$ %s", strings.Join(slices.Concat(extra, argv), " "))
	out, err := cmd.CombinedOutput()
	code := 0
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit) && ctx.Err() == nil:
		code = exit.ExitCode()
	default:
		code = -1
		out = append(out, fmt.Sprintf("\n%s: %v\n", argv[0], err)...)
		if ctx.Err() != nil {
			out = append(out, fmt.Sprintf("%s: gave up after %v\n", argv[0], childTimeout)...)
		}
	}
	t.Logf("%s\n(exit %d)", out, code)
	return string(out), code
}
