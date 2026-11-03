// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package sandbox runs the escape payload inside a sandbox: the product under
// test (workcell) or a plain container with open networking (control, SPEC T2).
package sandbox

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// Allow names the hosts the session policy allows. Each resolves, for
	// the session, to the test host's own address, where the judge's canaries
	// listen (SPEC T8). The control adapter has no policy and ignores it.
	Allow []string
	// Deny names hosts the policy does not allow. Each resolves for the
	// session like an allowed name does, so that a policy the guest widened
	// would reach a canary under it. The control adapter ignores it.
	Deny []string
	// Secret is a credential bound to one allowed name; nil for none.
	Secret *Secret
}

// Secret is one [[secret]] table entry as a test wants it: Value is bound to
// Host and goes in Header. The guest is to see the credential only as a
// placeholder, in the environment variable Env, and only a terminated
// connection to Host is to carry Value (SPEC A4, I5, I6). The control adapter
// does what a naive sandbox does and stages Value itself.
type Secret struct {
	Name, Value, Host, Header, Env string
}

// UpdateConfig is one run of the product's update client as a judge wants
// it: `workcell update` against a channel and an upstream the judge serves on
// the test host (SPEC T8). The real adapter passes every field to the product
// as a parameter, through its CLI or its config, as the product's keys, clock
// and last serial are parameters (SPEC A11); nothing here is a test hook.
type UpdateConfig struct {
	// Channel is the https URL of channel.json: the `[update] channel` the
	// client consults. It names the test host's loopback address, never a name.
	Channel string
	// CA is the PEM certificate that signed the certificates of the channel
	// and upstream servers. The client is to trust it, and only it, for the run.
	CA []byte
	// Key is the one channel key the client is to trust: its key table holds
	// this entry, with a NotAfter in the future, and no other.
	Key ed25519.PublicKey
	// Name is the pin the client is to install, keyed in the manifest by name
	// and then by runtime.GOARCH. Version is `--to <version>`.
	Name, Version string
}

// Sandbox is one sandbox holding the payload. A test gets a fresh one.
type Sandbox interface {
	// Start creates the sandbox and places the payload binary inside it. It
	// returns the path at which the guest sees cfg.Workspace, "" if none.
	Start(ctx context.Context, cfg Config) (guestWorkspace string, err error)
	// Exec runs the payload inside the sandbox, as root in the guest, with the
	// arguments. A non-zero exit status is reported in Output, not as an error.
	Exec(ctx context.Context, args ...string) (Output, error)
	// Pull brings the guest's workspace back to the host, into the directory
	// dest, as the product's pull does. The guest wrote the tree it brings;
	// a sandbox that executes or obeys any of it breaks SPEC I8.
	Pull(ctx context.Context, dest string) error
	// Stop tears the sandbox down.
	Stop() error
	Observe
}

// Observe is the host side of a session as a judge sees it: the record the
// product keeps of the session, the helpers that serve it, and the channel
// the guest reaches. Everything here is read on the host; what the guest says
// is never evidence.
type Observe interface {
	// Audit returns the host path of the file holding the session's record
	// and the records in it, oldest first, one per element, as the product's
	// log verb prints them.
	Audit(ctx context.Context) (path string, records []string, err error)
	// Verify runs the product's check of the session's record, as its verify
	// verb does, and returns nil only when the record is intact.
	Verify(ctx context.Context) error
	// Helper returns the host pid of the session's named helper: "proxy",
	// "resolver", "broker", or "supervisor" for the host end of the channel.
	// Two names may share one process.
	Helper(ctx context.Context, name string) (pid int, err error)
	// Channel describes the host-guest channel as the guest reaches it.
	Channel(ctx context.Context) (Channel, error)
	// Update runs the product's update client once on the host, as
	// `workcell update` does, with what u names, and returns the bytes of
	// the artifact installed for u.Name afterwards, nil when none is. The
	// state the client keeps between runs, the last serial seen and the
	// installed artifact, is the session's: empty at Start, kept across
	// calls. The client's own exit status is not an error: a refusal exits
	// however it likes and leaves the install as it was. An error means the
	// client could not be run or its install could not be read.
	Update(ctx context.Context, u UpdateConfig) (installed []byte, err error)
	// Bench runs the product's start benchmark once on the host, as
	// `workcell bench start` does, with the artifacts this session's runs
	// use, and returns what it printed and its exit status (SPEC P1). The
	// product's own exit status is not an error; an error means it could
	// not be run.
	Bench(ctx context.Context) (Output, error)
}

// Channel is the host end of the host-guest channel, as the guest dials it:
// Addr is "unix:<path>", "tcp:<host:port>" or "vsock:<cid>:<port>"; Hello is
// one well-formed frame the host answers on a fresh connection, and Reply is
// a prefix of its answer. A probe sends Hello before and after its hostile
// traffic, so that a channel it never reached cannot pass (SPEC I12).
type Channel struct {
	Addr         string
	Hello, Reply []byte
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

// bounded keeps the first limit bytes written and drops the rest.
type bounded struct {
	limit int
	buf   []byte
}

func (b *bounded) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p[:min(len(p), b.limit-len(b.buf))]...)
	return len(p), nil
}
