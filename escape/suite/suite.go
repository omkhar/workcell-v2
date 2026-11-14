// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package suite declares the escape tests. Each test names the invariant it
// proves, a probe that runs as root inside the guest (in the payload binary)
// and the judgement made on the host. A test is added by one entry in All.
package suite

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// Result is what a probe reports. Status is a short token such as "connected";
// Detail is one line of printable ASCII. Both are bounded and sanitised by
// Format, so that any Result crosses the guest boundary as a single line.
type Result struct {
	Status string
	Detail string
}

const (
	maxStatus = 32
	maxDetail = 256
	prefix    = "escape-result "
	// MaxLine bounds one formatted result, newline included.
	MaxLine = len(prefix) + maxStatus + 1 + maxDetail + 1
)

// Probe runs inside the guest with the arguments the host chose.
type Probe func(args []string) Result

// Run executes the test's probe inside the sandbox with the arguments.
type Run func(args ...string) (Result, error)

// Session is one running sandbox, as the host knows it.
type Session struct {
	Run Run
	// Exec runs the test's probe as Run does, but gives back the run itself,
	// exit status and streams unparsed, under ctx: the evidence for a judge that
	// holds the host end of a run to account (SPEC I12). A status the host could
	// not run the command under is a result here, not an error.
	Exec func(ctx context.Context, args ...string) (sandbox.Output, error)
	// Workspace is the host directory exported into the guest, "" for none.
	// Its parent is the test's alone and removed afterwards, so a judge may
	// plant files beside it.
	Workspace string
	Guest     string // where the guest sees Workspace
	// Allow and Secret are the session's policy as the runner made it from
	// Want: the allowed names, and the credential bound to the first, with
	// its real value, which the guest must never hold.
	Allow  []string
	Deny   []string // names that resolve for the session but no policy allows
	Secret sandbox.Secret
	// Payload is the host path of the payload binary: the probe, and the
	// helper a judge runs through sudo for what needs root on the test host.
	Payload string
	// Pull brings the guest's workspace back to the host directory dest, as
	// the product's pull does.
	Pull func(dest string) error
	// Another starts a second session with the same Want and its own export,
	// and, when update is not nil, that [update] table in its own
	// configuration (sandbox.Config.Update). The runner stops it with the first.
	Another func(update *sandbox.UpdateConfig) (Session, error)
	// Observe is the host side of the session: its record, its helpers and
	// its channel.
	sandbox.Observe
}

// Judge runs on the host. It may start canaries (on loopback only, SPEC T8),
// run the probe through s.Run, and says whether the invariant held.
type Judge func(ctx context.Context, s Session) (pass bool, detail string, err error)

// Want is the sandbox a test needs: an export, whether it is the user's tree
// served live rather than a clone (`--mount`, SPEC A5), the caps the adapter
// is to state (zero: the adapter's default), the names the policy allows and
// the names it does not, the resolver the host side of the session is to use
// (the judge's, sandbox.Config.Resolver), whether a fresh secret is bound to
// the first allowed name, and narrowed to one method and path (NewSecret),
// and the repo-local policy the hostile repository brings (a workcell.toml
// the runner plants in the export before the session starts, PlantPolicy).
type Want struct {
	Workspace bool
	Mount     bool
	CPUs      int
	MemoryMiB int
	DiskMiB   int
	Allow     []string
	Deny      []string
	Resolver  string
	Isolated  bool // the host side in a network of its own (sandbox.Config.Isolated)
	Secret    bool
	Header    string // the header the secret is bound to, when not x-api-key (NewSecret)
	Narrow    bool
	Source    string   // the secret's source in the product's words, such as a sign-in flow (sandbox.Secret.Source)
	Repos     []string // the repositories a git token is scoped to (sandbox.Secret.Repos)
	Policy    string
	Shape     string
	// Command is a provider the session runs by name, as `workcell run
	// <Command>` does, in place of the loader that carries the payload in; the
	// judge installs a layer whose binary is the payload (sandbox.Config.Command).
	Command string
}

// Test is one escape test.
type Test struct {
	ID    string // the invariant, such as "I4"
	Name  string // unique, lower case, the payload's argument
	Probe Probe
	Host  Judge
	Want  Want
	// Bound is the runner's limit on the whole test, start to stop, when
	// the test needs more than the runner's default; zero is that default.
	Bound time.Duration
}

// Lookup finds a test by name.
func Lookup(name string) (Test, bool) {
	for _, t := range All {
		if t.Name == name {
			return t, true
		}
	}
	return Test{}, false
}

// Select returns the tests whose invariant ID, or whose name, is in only, a
// comma-separated list, or every test when only is empty. An entry with no
// test is an error, so that an enforced invariant can never pass by having
// nothing to run.
func Select(only string) ([]Test, error) {
	if strings.TrimSpace(only) == "" {
		return All, nil
	}
	var out []Test
	for id := range strings.SplitSeq(only, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		n := 0
		for _, t := range All {
			if t.ID == id || t.Name == id {
				out = append(out, t)
				n++
			}
		}
		if n == 0 {
			return nil, fmt.Errorf("no test for invariant or name %q", id)
		}
	}
	return out, nil
}

// Format encodes a result as the one line the payload prints. It is total:
// any Result becomes a line that ParseResult accepts.
func Format(r Result) []byte {
	status := clean(r.Status, maxStatus, isToken, '-')
	if status == "" {
		status = "error"
	}
	return []byte(prefix + status + " " + clean(r.Detail, maxDetail, isPrint, '?') + "\n")
}

// ParseResult decodes the payload's stdout. The bytes are hostile: the whole
// output must be exactly one formatted line, and nothing else.
func ParseResult(b []byte) (Result, error) {
	if len(b) > MaxLine {
		return Result{}, fmt.Errorf("payload output is %d bytes, limit %d", len(b), MaxLine)
	}
	line, ok := bytes.CutPrefix(b, []byte(prefix))
	if !ok {
		return Result{}, fmt.Errorf("payload output does not start with %q", prefix)
	}
	line, ok = bytes.CutSuffix(line, []byte("\n"))
	if !ok || bytes.IndexByte(line, '\n') >= 0 {
		return Result{}, fmt.Errorf("payload output is not exactly one line")
	}
	status, detail, ok := bytes.Cut(line, []byte(" "))
	if !ok || len(status) == 0 || len(status) > maxStatus || !all(status, isToken) {
		return Result{}, fmt.Errorf("payload output has a bad status")
	}
	if len(detail) > maxDetail || !all(detail, isPrint) {
		return Result{}, fmt.Errorf("payload output has a bad detail")
	}
	return Result{Status: string(status), Detail: string(detail)}, nil
}

func isToken(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' }
func isPrint(c byte) bool { return c >= ' ' && c <= '~' }

func all(b []byte, ok func(byte) bool) bool {
	for _, c := range b {
		if !ok(c) {
			return false
		}
	}
	return true
}

func clean(s string, n int, ok func(byte) bool, sub byte) string {
	b := []byte(s)
	if len(b) > n {
		b = b[:n]
	}
	for i, c := range b {
		if !ok(c) {
			b[i] = sub
		}
	}
	return string(b)
}
