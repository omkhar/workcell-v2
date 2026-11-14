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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	// Mount serves Workspace live (`--mount`, SPEC A5) instead of a clone; control shows it live either way.
	Mount     bool
	CPUs      int
	MemoryMiB int
	DiskMiB   int
	// Allow names the hosts the session policy allows. Each resolves to the
	// test host's own address, where the judge's canaries listen (SPEC T8).
	// The control adapter has no policy and ignores it.
	Allow []string
	// Deny names hosts the policy does not allow, resolved like an allowed
	// name, so that a policy the guest widened would reach a canary under it.
	Deny []string
	// Resolver is the IPv4 address of a DNS server on the test host, port 53,
	// the host side of the session resolves every name with; "" leaves the
	// adapter's own. The judge runs it (SPEC I4). Control gives it to the guest.
	Resolver string
	// Isolated, on Linux, runs the host side in a network namespace of its own
	// with one address the product's vetting accepts and no way out, so that a
	// canary bound through Bind there is reached through the product's forward
	// path and nothing leaves the test host (SPEC T8, S12). It needs Resolver.
	Isolated bool
	// Roots is the host path of a PEM bundle the host side trusts in an
	// upstream, as an operator's SSL_CERT_FILE: the suite's own authority,
	// which signed every canary. "" leaves the host's own.
	Roots string
	// Secret is a credential bound to one allowed name; nil for none.
	Secret *Secret
	// Update is the [update] table the session's own configuration carries
	// (Channel, CA and Key; Version plays no part), so that each session start
	// makes the product's daily channel check; nil for no table. Control
	// installs from the channel at every start, checking nothing.
	Update *UpdateConfig
	// Command, when set, is a provider the operator runs by name, `workcell
	// run <Command> <args>`, in place of the loader shell that carries the
	// payload in through stdin: the test has installed a layer (Install)
	// whose binary is the payload, and stdin stays open and empty, so that
	// the guest's first frame is the command's own. Control runs the name
	// from the prefix its Install fills.
	Command string
}

// Secret is one [[secret]] table entry as a test wants it: Value is bound to
// Host and goes in Header. The guest is to see it only as a placeholder in
// the variable Env, and only a terminated connection to Host is to carry
// Value (SPEC A4, I5, I6). Method and Path narrow the binding to requests of
// that method under that path prefix; Repos, to the repositories it names
// (`owner/name`) on Host, as a git credential is scoped. Source, when set,
// names the row's source in the product's words instead of a file holding
// Value, then empty: `signin:<host><path>` has the host obtain the credential
// from a sign-in flow, the guest seeing its tokens only as placeholders, the
// access one in Env. Control stages Value itself, as a naive sandbox does,
// and nothing for a sign-in row: the guest talks to the endpoint itself.
type Secret struct {
	Name, Value, Host, Header, Env, Method, Path, Source string
	Repos                                                []string
}

// UpdateConfig is the product's update client as a judge wants it, against a
// channel and an upstream the judge serves on the test host (SPEC T8). The
// real adapter passes every field as a parameter the user could give (SPEC
// A11); nothing here is a test hook.
type UpdateConfig struct {
	// Channel is the https URL of channel.json, `[update] channel`, naming the test host's loopback address.
	Channel string
	// CA is the PEM certificate that signed the channel's and upstream's certificates: the only one trusted.
	CA []byte
	// Key is the one channel key the client trusts, with a NotAfter in the future.
	Key ed25519.PublicKey
	// Name is the pin to install, keyed in the manifest by name then runtime.GOARCH; Version is `--to <version>`.
	Name, Version string
}

// Layer is one provider layer a judge wants installed on the host, as
// `workcell update <agent>` installs it: the provider, the release, and the
// artifact the row's digest names, in a shape a real upstream serves (a bare
// executable, or a tar, plain or gzip, with the binary at its root or under
// bin/). The judge serves URL on its loopback under the suite's authority
// (T8): the artifact, or other bytes to see a digest mismatch refused. With
// no Artifact, URL is a real pin's and Digest its hex SHA-256, fetched from
// upstream by the host's own network and trust (B8).
type Layer struct {
	Agent, Version, URL string
	Artifact            []byte
	Digest              string
}

// Sandbox is one sandbox holding the payload. A test gets a fresh one.
type Sandbox interface {
	// Start creates the sandbox and places the payload binary inside it. It
	// returns the path at which the guest sees cfg.Workspace, "" if none.
	Start(ctx context.Context, cfg Config) (guestWorkspace string, err error)
	// Exec runs the payload inside the sandbox, as root in the guest, with the
	// arguments. A non-zero exit status is reported in Output, not as an error.
	Exec(ctx context.Context, args ...string) (Output, error)
	// Pull brings the guest's workspace back to the host directory dest, as
	// the product's pull does. A sandbox that executes or obeys any of what
	// the guest wrote breaks SPEC I8.
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
	// Audit returns the host path of the session's record file and the
	// records in it, oldest first, as the product's log verb prints them.
	Audit(ctx context.Context) (path string, records []string, err error)
	// Verify runs the product's verify verb on the record; nil only if intact.
	Verify(ctx context.Context) error
	// Helper returns the host pid of the session's named helper: "proxy",
	// "resolver", "broker", or "supervisor" for the host end of the channel;
	// names may share one process (SPEC A9). A helper lives only as long as a
	// run does, so a judge asks during an Exec. One the product lacks is ErrNotImplemented.
	Helper(ctx context.Context, name string) (pid int, err error)
	// Channel describes the host-guest channel as the guest reaches it.
	Channel(ctx context.Context) (Channel, error)
	// Bind opens a listener ("tcp4") or a packet socket ("udp4") at addr on
	// the host side of the session, where the product reaches the test host:
	// the host's own network, or the session's own when isolated; "host" as
	// the host of addr is the test host's address there. A port that needs
	// root fails with EACCES, and the judge binds it as root.
	Bind(ctx context.Context, network, addr string) (net.Listener, net.PacketConn, error)
	// Relay describes the host end of the network relay: where the init opens
	// one stream per relayed connection, behind the 20-byte header of ADR-003
	// (version, proto, port, 16-byte address). A probe may dial it afresh.
	Relay(ctx context.Context) (Channel, error)
	// Update runs the product's update client once on the host, as `workcell
	// update` does with what u names, and returns Installed for u.Name. What
	// the client keeps between runs (last serial, the install) is the
	// session's: empty at Start, kept across calls. A refusal is not an error
	// and leaves the install as it was; an error means the client could not
	// be run or its install could not be read.
	Update(ctx context.Context, u UpdateConfig) (installed []byte, err error)
	// Installed returns the bytes of the artifact installed for the pin name
	// (UpdateConfig.Name), read on the host from the current layer; nil when none is.
	Installed(ctx context.Context, name string) ([]byte, error)
	// Install has the host install l for every session of this process, as
	// `workcell update --to <version> <agent>` does from a row naming l.URL
	// and the digest, and returns the host path of the layer's image, "" when
	// the adapter keeps none. A refusal is an error.
	Install(ctx context.Context, l Layer) (image string, err error)
	// Bench runs `workcell bench start` once on the host with this session's
	// artifacts and returns what it printed and its exit status (SPEC P1).
	Bench(ctx context.Context) (Output, error)
}

// Channel is the host end of the host-guest channel, or of the relay, as the
// guest's init is connected to it and a fresh connection dials it: Addr is
// "unix:<path>" or "vsock:<cid>:<port>". The host answers no guest frame;
// what a hostile frame did shows in the run's exit status and streams (I12).
type Channel struct {
	Addr string
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

// HostAddr is the test host's own first non-loopback IPv4 address: what a
// guest with a network of its own sees as the host.
func HostAddr() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				return ipn.IP.String(), nil
			}
		}
	}
	return "", errors.New("the host has no non-loopback IPv4 address for a canary")
}

// LoopbackHolds says whether ip is an address of the host's loopback
// interface, where a Mac holds the suite's canary addresses (SPEC T8).
func LoopbackHolds(ip string) error {
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	want := net.ParseIP(ip)
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && i.Flags&net.FlagLoopback != 0 && ipn.IP.Equal(want) {
				return nil
			}
		}
	}
	return fmt.Errorf("%s is not an address of the host's loopback interface, which its setup must hold", ip)
}

// bindHere binds network/addr in this process's own network, "host" in
// addr standing for HostAddr: what Bind does for a session that is not
// isolated.
func bindHere(network, addr string) (net.Listener, net.PacketConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	if host == "host" {
		if host, err = HostAddr(); err != nil {
			return nil, nil, err
		}
		addr = net.JoinHostPort(host, port)
	}
	if strings.HasPrefix(network, "udp") {
		pc, err := net.ListenPacket(network, addr)
		return nil, pc, err
	}
	ln, err := net.Listen(network, addr)
	return ln, nil, err
}

// bounded keeps the first limit bytes written and drops the rest. More than
// one goroutine may write: the command's pipe and the control channel.
type bounded struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p[:min(len(p), b.limit-len(b.buf))]...)
	return len(p), nil
}

func (b *bounded) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf
}
