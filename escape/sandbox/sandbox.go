// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package sandbox runs the escape payload inside a sandbox: the product under
// test (workcell) or a plain container with open networking (control, SPEC T2).
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
)

// ErrNotImplemented is returned by an adapter that cannot do the operation yet.
// The runner reports it as "not-implemented", which is never a pass.
var ErrNotImplemented = errors.New("not implemented")

// Limits on what the runner keeps of the payload's output. Everything beyond is
// dropped: the bytes come from the guest and are hostile (SPEC I12).
const (
	MaxStdout = 4096
	MaxStderr = 1024
)

// Output is what one payload run produced, as far as the runner keeps it.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
	// Total is every byte the host took in from the guest on both streams,
	// kept or dropped. A host that keeps taking is one the guest can flood.
	Total int64
}

// Config is the sandbox a test wants. The caps are what the product's
// [resources] table states; zero leaves the adapter's default. The control
// adapter applies no cap and shows the workspace at its host path.
type Config struct {
	Payload   string // host path of the static payload binary
	Workspace string // host directory exported into the guest as its workspace; "" exports nothing
	CPUs      int
	MemoryMiB int
	DiskMiB   int
}

// Sandbox is one sandbox holding the payload. A test gets a fresh one.
type Sandbox interface {
	// Start creates the sandbox and places the payload binary inside it. It
	// returns the path at which the guest sees cfg.Workspace, "" if none.
	Start(ctx context.Context, cfg Config) (guestWorkspace string, err error)
	// Exec runs the payload inside the sandbox, as root in the guest, with the
	// arguments. A non-zero exit status is reported in Output, not as an error.
	Exec(ctx context.Context, args ...string) (Output, error)
	// Stop tears the sandbox down.
	Stop() error
}

// Names lists the adapters, in the order shown to a user.
var Names = []string{"control", "workcell"}

// New returns a fresh adapter by name.
func New(name string) (Sandbox, error) {
	switch name {
	case "control":
		return newControl()
	case "workcell":
		return &workcell{}, nil
	}
	return nil, fmt.Errorf("unknown sandbox %q; want one of %v", name, Names)
}

// BuildPayload compiles the payload for a Linux guest of the host's
// architecture, static, into dir, and returns its path.
func BuildPayload(ctx context.Context, dir string) (string, error) {
	out := filepath.Join(dir, "payload")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out,
		"github.com/omkhar/workcell/v2/escape/cmd/payload")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build payload: %v: %s", err, b)
	}
	return out, nil
}

// bounded keeps the first limit bytes written, drops the rest, and counts
// them all in total.
type bounded struct {
	limit int
	buf   []byte
	total *atomic.Int64 // shared by both streams, which are read concurrently
}

func (b *bounded) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p[:min(len(p), b.limit-len(b.buf))]...)
	b.total.Add(int64(len(p)))
	return len(p), nil
}
