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
	// Mount serves Workspace itself, live, so that the guest's writes land in
	// the host's tree at once (`--mount`, SPEC A5); false exports a
	// copy-on-write clone of it. The control adapter shows the workspace
	// live at its host path in either case, as a naive sandbox does.
	Mount     bool
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
	// Resolver is the IPv4 address of a DNS server on the test host, port
	// 53, that the host side of the session is to ask for every name it
	// resolves on the guest's behalf, as its /etc/resolv.conf resolver; ""
	// leaves the adapter's own. The judge runs that server and so says what
	// an allowed name resolves to (SPEC I4). In the control adapter the
	// guest dials for itself, so there it is the guest's resolver.
	Resolver string
	// Isolated, on Linux, runs the host side of the session in a network
	// namespace of its own, which holds one address the product's vetting
	// accepts and no way out, so that a canary bound through Bind there is
	// reached through the product's forward path and nothing can leave the
	// test host (SPEC T8, S12). It needs Resolver. The control adapter has
	// one network, the host's, and ignores it.
	Isolated bool
	// Roots is the host path of a PEM bundle holding the authorities the
	// host side of the session is to trust in an upstream server, as an
	// operator's trust store (SSL_CERT_FILE) would: the suite's own, which
	// signed every canary's certificate. "" leaves the host's own. The
	// control adapter has no host side and ignores it.
	Roots string
	// Secret is a credential bound to one allowed name; nil for none.
	Secret *Secret
}

// Secret is one [[secret]] table entry as a test wants it: Value is bound to
// Host and goes in Header. The guest is to see the credential only as a
// placeholder, in the environment variable Env, and only a terminated
// connection to Host is to carry Value (SPEC A4, I5, I6). Method and Path,
// when set, narrow the binding to requests of that method under that path
// prefix; Repos, when set, to the repositories it names (`owner/name`)
// on Host, as a git credential is scoped. The control adapter does what a
// naive sandbox does and stages Value itself, wherever the guest asks for it. Source, when set, names
// the row's source in the product's own words instead of a file holding
// Value, which is then empty: `signin:<host><path>` has the host obtain
// the credential from a sign-in flow at that token endpoint, so that the
// guest is to see the tokens the endpoint issues only as placeholders, the
// access one in Env. The control adapter stages nothing for such a row:
// the guest talks to the endpoint itself and gets what it issues.
type Secret struct {
	Name, Value, Host, Header, Env, Method, Path, Source string
	Repos                                                []string
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

// Layer is one provider layer a judge wants installed on the host, as
// `workcell update <agent>` installs it: the provider, the release, and the
// tar (plain or gzip) holding bin/<binary> that the judge serves at URL, on
// the test host's loopback over https under the suite's authority (T8).
type Layer struct {
	Agent, Version, URL string
	Artifact            []byte
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
	// Two names may share one process, and all may be the one process that
	// owns the session (SPEC A9). A helper lives only as long as a run of
	// the session does, so a judge asks while one of its Exec calls is in
	// flight. A helper the product does not have yet is ErrNotImplemented.
	Helper(ctx context.Context, name string) (pid int, err error)
	// Channel describes the host-guest channel as the guest reaches it.
	Channel(ctx context.Context) (Channel, error)
	// Bind opens a listener ("tcp4") or a packet socket ("udp4") at addr on
	// the host side of the session, where the product reaches the test
	// host: in the host's own network, or in the session's own when it is
	// isolated. "host" as the host of addr stands for the test host's
	// address there. A port that needs root fails with EACCES in the host's
	// own network, and the judge binds it as root itself.
	Bind(ctx context.Context, network, addr string) (net.Listener, net.PacketConn, error)
	// Relay describes the host end of the network relay as the guest reaches
	// it: where the init opens one stream per relayed connection, behind the
	// 20-byte header of ADR-003 (version, proto, port, 16-byte address). A
	// probe may dial it afresh and speak the header itself.
	Relay(ctx context.Context) (Channel, error)
	// Update runs the product's update client once on the host, as
	// `workcell update` does, with what u names, and returns the bytes of
	// the artifact installed for u.Name afterwards, nil when none is. The
	// state the client keeps between runs, the last serial seen and the
	// installed artifact, is the session's: empty at Start, kept across
	// calls. The client's own exit status is not an error: a refusal exits
	// however it likes and leaves the install as it was. An error means the
	// client could not be run or its install could not be read.
	Update(ctx context.Context, u UpdateConfig) (installed []byte, err error)
	// Install has the host install l for every session of this process, as
	// `workcell update --to <version> <agent>` does from a row naming l.URL
	// and the artifact's digest, and returns the host path of the image
	// holding the layer, "" when the adapter keeps none. A refusal is an error.
	Install(ctx context.Context, l Layer) (image string, err error)
	// Bench runs the product's start benchmark once on the host, as
	// `workcell bench start` does, with the artifacts this session's runs
	// use, and returns what it printed and its exit status (SPEC P1). The
	// product's own exit status is not an error; an error means it could
	// not be run.
	Bench(ctx context.Context) (Output, error)
}

// Channel is the host end of the host-guest channel, or of the relay, as
// the guest's init is connected to it and as a fresh connection dials it:
// Addr is "unix:<path>" or "vsock:<cid>:<port>". The host answers no guest
// frame; what a hostile frame did shows in the run's own exit status and
// streams (SPEC I12).
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
