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

// Limits on what the runner keeps of the payload's output; the rest is dropped (I12).
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

// Config is the sandbox a test wants. The caps are the product's [resources];
// zero leaves the adapter's default. Control applies no cap.
type Config struct {
	Payload   string // host path of the static payload binary
	Workspace string // host directory exported into the guest as its workspace; "" exports nothing
	// Mount serves Workspace live (`--mount`, SPEC A5) instead of a clone; control shows it live either way.
	Mount     bool
	CPUs      int
	MemoryMiB int
	DiskMiB   int
	// Allow names the hosts the session policy allows, each resolving to the
	// test host's own address, where the judge's canaries listen (SPEC T8);
	// Deny names hosts it does not, resolved the same way. Control has no policy.
	Allow []string
	Deny  []string
	// Resolver is the IPv4 address of a DNS server on the test host, port 53,
	// the host side resolves every name with; "" leaves the adapter's own.
	Resolver string
	// Isolated, on Linux, runs the host side in a network namespace of its own
	// with one address and no way out, so nothing leaves the test host (T8, S12). It needs Resolver.
	Isolated bool
	// Roots is a PEM bundle the host side trusts upstream, as SSL_CERT_FILE: the suite's own authority.
	Roots string
	// Secret is a credential bound to one allowed name; nil for none.
	Secret *Secret
	// Update is the [update] table the session's configuration carries (Channel,
	// CA and Key), so each start makes the daily channel check; nil for none.
	Update *UpdateConfig
	// Command, when set, is a provider run by name, `workcell run <Command>
	// <args>`, in place of the loader that carries the payload in: the test
	// has installed a layer whose binary is the payload (Install), and stdin
	// stays open and empty, so the guest's first frame is the command's own.
	Command string
}

// Secret is one [[secret]] entry: Value, bound to Host, goes in Header; the
// guest sees only a placeholder in Env (A4, I5, I6). Method and Path narrow
// the binding, Repos scopes it to `owner/name` repositories as a git
// credential is. Source, when set, names the product's own source instead of
// a file holding Value: `signin:<host><path>` is a sign-in flow. Control
// stages Value itself, and nothing for a sign-in row.
type Secret struct {
	Name, Value, Host, Header, Env, Method, Path, Source string
	Repos                                                []string
}

// UpdateConfig is the product's update client against a channel and an
// upstream the judge serves (T8); every field is a parameter a user could give (A11).
type UpdateConfig struct {
	Channel string            // the https URL of channel.json, `[update] channel`
	CA      []byte            // the PEM certificate that signed the channel's and upstream's: the only one trusted
	Key     ed25519.PublicKey // the one channel key the client trusts
	// Name is the pin to install, keyed in the manifest by name then runtime.GOARCH; Version is `--to <version>`.
	Name, Version string
}

// Layer is one provider layer installed as `workcell update <agent>` does:
// the artifact the row's digest names, in a shape a real upstream serves
// (a bare executable, or a tar with the binary at its root or under bin/),
// at a URL the judge serves (T8). With no Artifact, URL is a real pin's and
// Digest its hex SHA-256, fetched by the host's own network and trust (B8).
type Layer struct {
	Agent, Version, URL string
	Artifact            []byte
	Digest              string
}

// Sandbox is one sandbox holding the payload. A test gets a fresh one.
type Sandbox interface {
	// Start creates the sandbox with the payload in it and returns where the guest sees cfg.Workspace, "" if none.
	Start(ctx context.Context, cfg Config) (guestWorkspace string, err error)
	// Exec runs the payload as root in the guest; a non-zero exit is a result, not an error.
	Exec(ctx context.Context, args ...string) (Output, error)
	// Pull brings the guest's workspace back to dest, as the product's pull does (I8).
	Pull(ctx context.Context, dest string) error
	// Stop tears the sandbox down.
	Stop() error
	Observe
}

// Observe is the host side of a session as a judge sees it: its record, its
// helpers and its channel. Everything here is read on the host.
type Observe interface {
	// Audit returns the host path of the session's record file and its records, oldest first.
	Audit(ctx context.Context) (path string, records []string, err error)
	// Verify runs the product's verify verb on the record; nil only if intact.
	Verify(ctx context.Context) error
	// Helper returns the host pid of the session's "proxy", "resolver", "broker"
	// or "supervisor", which may share one process (A9), during an Exec. One the product lacks is ErrNotImplemented.
	Helper(ctx context.Context, name string) (pid int, err error)
	// Channel describes the host-guest channel as the guest reaches it.
	Channel(ctx context.Context) (Channel, error)
	// Bind opens a listener ("tcp4") or packet socket ("udp4") at addr where the
	// product reaches the test host, "host" standing for its address there. A
	// port that needs root fails with EACCES, and the judge binds it as root.
	Bind(ctx context.Context, network, addr string) (net.Listener, net.PacketConn, error)
	// Relay describes the host end of the network relay, one stream per relayed connection behind the header of ADR-003.
	Relay(ctx context.Context) (Channel, error)
	// Update runs the product's update client once, as `workcell update` does
	// with u, and returns Installed for u.Name. What the client keeps between
	// runs is the session's. A refusal is not an error; a client that could not run is.
	Update(ctx context.Context, u UpdateConfig) (installed []byte, err error)
	// Installed returns the artifact installed for the pin name, read on the host from the current layer; nil when none is.
	Installed(ctx context.Context, name string) ([]byte, error)
	// Install has the host install l for every session of this process, as
	// `workcell update --to <version> <agent>` does, and returns the host path
	// of the layer's image, "" when the adapter keeps none. A refusal is an error.
	Install(ctx context.Context, l Layer) (image string, err error)
	// Bench runs `workcell bench start` once with this session's artifacts (P1).
	Bench(ctx context.Context) (Output, error)
}

// Channel is the host end of the host-guest channel, or of the relay, as the
// init is connected to it: "unix:<path>" or "vsock:<cid>:<port>". The host
// answers no guest frame; what a hostile one did shows in the run (I12).
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

// BuildPayload compiles the static Linux payload for the host's architecture into dir.
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

// HostAddr is the test host's first non-loopback IPv4 address.
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

// LoopbackHolds says whether ip is an address of the host's loopback interface (T8).
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

// bindHere binds network/addr in this process's own network, "host" standing for HostAddr.
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

// bounded keeps the first limit bytes written and drops the rest; several goroutines may write.
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
