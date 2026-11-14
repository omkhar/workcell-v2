// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || darwin

package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The adapter on a host with a hypervisor the product drives: Firecracker on Linux, Virtualization.framework on macOS. What differs per OS lives in
// workcell_linux.go and workcell_darwin.go; the session itself is the same.
const (
	maxDownload = 256 << 20 // more than any pinned download; a runaway body stops here
	module      = "github.com/omkhar/workcell/v2"
)

// loader runs inside the guest: it takes the payload from stdin and runs it with the test's arguments.
const loader = `cat >/tmp/p && chmod 755 /tmp/p && exec /tmp/p "$@"`

// RootBind binds network/addr as root on the test host, by a helper that hands the socket back over a unix socket (rootBindArgv), in the session's own network
// when ns is set, "host" and "neighbour" in addr standing for the test host's addresses there (placed). A socket handed over dead is bound again.
func RootBind(network, addr, payload string, ns int) (net.Listener, net.PacketConn, error) {
	addr, err := placed(addr, ns != 0)
	if err != nil {
		return nil, nil, err
	}
	where := fmt.Sprintf("bind %s %s as root", network, addr)
	for try := 1; ; try++ {
		f, err := handedOver(rootBindArgv(network, addr, "", payload, ns), network, where)
		if err != nil {
			return nil, nil, err
		}
		// Dead: 0 bytes and no error, where a live socket says EAGAIN (udp) or ENOTCONN (a listener).
		if n, _, rerr := syscall.Recvfrom(int(f.Fd()), make([]byte, 1), syscall.MSG_DONTWAIT|syscall.MSG_PEEK); n != 0 || rerr != nil {
			defer f.Close()
			if strings.HasPrefix(network, "udp") {
				pc, err := net.FilePacketConn(f)
				return nil, pc, err
			}
			l, err := net.FileListener(f)
			return l, nil, err
		}
		f.Close()
		if try == 3 {
			return nil, nil, fmt.Errorf("%s: the socket handed over was dead, %d times: its sender exited before it was taken", where, try)
		}
	}
}

// handedOver runs argv with its last word replaced by a unix socket of its own and takes the descriptor sent there, polling: on macOS a socket queued on a
// connection not yet accepted is dead once its sender exits (U-701).
func handedOver(argv []string, network, where string) (*os.File, error) {
	dir, err := os.MkdirTemp("", "escape-bind-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "fd")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	argv[len(argv)-1] = path
	cmd := exec.Command(argv[0], argv[1:]...)
	out := &bounded{limit: MaxStderr}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	defer cmd.Wait()
	raw, _ := ln.SyscallConn()
	nfd, cerr := -1, error(syscall.EAGAIN)
	raw.Control(func(fd uintptr) {
		for start := time.Now(); cerr == syscall.EAGAIN && time.Since(start) < 2*time.Second; {
			nfd, _, cerr = syscall.Accept(int(fd))
		}
	})
	if cerr != nil {
		cmd.Wait()
		return nil, fmt.Errorf("%s: no descriptor came back: %v: %s", where, cerr, bytes.TrimSpace(out.bytes()))
	}
	c := os.NewFile(uintptr(nfd), "fd")
	defer c.Close()
	oob := make([]byte, 64)
	_, oobn, _, _, err := syscall.Recvmsg(nfd, make([]byte, 1), oob, 0)
	for start := time.Now(); err == syscall.EAGAIN && time.Since(start) < 2*time.Second; { // taken before the sender wrote
		_, oobn, _, _, err = syscall.Recvmsg(nfd, make([]byte, 1), oob, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: read the descriptor: %w", where, err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	var fds []int
	if err == nil && len(msgs) == 1 {
		fds, err = syscall.ParseUnixRights(&msgs[0])
	}
	if err != nil || len(fds) != 1 {
		return nil, fmt.Errorf("%s: the descriptor: %v (%d messages, %d descriptors)", where, err, len(msgs), len(fds))
	}
	return os.NewFile(uintptr(fds[0]), network), nil
}

// prepared is what Prepare made, once per process, for every session.
var prepared struct {
	bin  string // the workcell binary
	xdg  string // XDG_DATA_HOME holding workcell/{vmlinux,initrd.cpio,root.ext4} and, on Linux, firecracker
	repo string // the module's directory, for a build the product's rows are swapped in (Install)
}

// workcell is one session of the product: a directory holding its policy, its secret and its cwd, the payload and the caps. A VM lives only as long as one Exec
// or one Pull.
type workcell struct {
	dir     string
	bin     string // the product with the suite's row compiled in, once Install ran; "" is prepared.bin
	payload string
	cfg     Config
	mu      sync.Mutex
	run     *exec.Cmd // the product, while one run of it is in flight
	ns      *holder   // the session's own network namespace, when isolated
}

// prepareWorkcell fetches, builds and assembles under dir, in parallel, what `workcell run` looks for.
func prepareWorkcell(ctx context.Context, dir string) error {
	if err := hostReady(); err != nil {
		return fmt.Errorf("workcell adapter: %w", err)
	}
	root, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", module).Output()
	if err != nil {
		return fmt.Errorf("workcell adapter: find the module: %w", err)
	}
	repo := strings.TrimSpace(string(root))
	xdg := filepath.Join(dir, "xdg")
	data := filepath.Join(xdg, "workcell")
	tmp := filepath.Join(dir, "build")
	if err := errors.Join(os.MkdirAll(data, 0o755), os.MkdirAll(tmp, 0o755)); err != nil {
		return err
	}
	start := time.Now()
	fmt.Fprintln(os.Stderr, "escape: preparing the workcell sandbox: the pinned downloads, three builds and the guest image, once")
	err = parallel(
		func() error { return hypervisor(ctx, data) },
		func() error {
			k, err := fetch(ctx, vmlinuxURL, vmlinuxSum)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(data, "vmlinux"), k, 0o644)
		},
		func() error {
			init := filepath.Join(tmp, "init")
			if err := goBuild(ctx, repo, init, module+"/cmd/workcell-init", "", "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+guestArch); err != nil {
				return err
			}
			b, err := os.ReadFile(init)
			if err != nil {
				return err
			}
			var cpio bytes.Buffer
			if err := errors.Join(cpioEntry(&cpio, "init", 0o100755, b), cpioEntry(&cpio, "TRAILER!!!", 0, nil)); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(data, "initrd.cpio"), cpio.Bytes(), 0o644)
		},
		func() error {
			mkimage := filepath.Join(tmp, "mkimage")
			if err := hostBuild(ctx, repo, mkimage, module+"/cmd/mkimage", ""); err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx, mkimage, "-pin", filepath.Join(repo, "pins", "debian.json"), "-arch", guestArch, "-o", filepath.Join(data, "root.ext4"))
			cmd.Dir = tmp
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("mkimage: %v: %s", err, bytes.TrimSpace(out))
			}
			return nil
		},
		func() error {
			bin := filepath.Join(tmp, "workcell")
			if err := hostBuild(ctx, repo, bin, module+"/cmd/workcell", ""); err != nil {
				return err
			}
			return sign(ctx, tmp, bin)
		},
	)
	if err != nil {
		return fmt.Errorf("workcell adapter: %w", err)
	}
	prepared.bin, prepared.xdg, prepared.repo = filepath.Join(tmp, "workcell"), xdg, repo
	fmt.Fprintf(os.Stderr, "escape: workcell sandbox ready in %s\n", time.Since(start).Round(time.Second))
	return nil
}

// parallel runs every function at once and returns every error.
func parallel(fns ...func() error) error {
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, f := range fns {
		wg.Go(func() { errs[i] = f() })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// fetch downloads url and returns its bytes only if their SHA-256 is sum.
func fetch(ctx context.Context, url, sum string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("download %s: sha256 %x, want %s", url, got, sum)
	}
	return b, nil
}

// goBuild compiles pkg of the module at repo into out with env added to the environment, under the build overlay file named when one is.
func goBuild(ctx context.Context, repo, out, pkg, overlay string, env ...string) error {
	args := []string{"build", "-trimpath", "-o", out}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	cmd := exec.CommandContext(ctx, "go", append(args, pkg)...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %v: %s", pkg, err, bytes.TrimSpace(b))
	}
	return nil
}

func (w *workcell) Start(_ context.Context, cfg Config) (string, error) {
	if prepared.bin == "" {
		return "", errors.New("workcell: Prepare did not run")
	}
	if why := unsupported(cfg); why != "" {
		return "", fmt.Errorf("workcell: the CLI cannot give a session %s yet: %w", why, ErrNotImplemented)
	}
	if _, err := os.Stat(cfg.Payload); err != nil {
		return "", fmt.Errorf("workcell: payload: %w", err)
	}
	dir, err := os.MkdirTemp("", "escape-workcell-")
	if err != nil {
		return "", err
	}
	// The secret's value, where only the host reads it: a file of the session's own, mode 0600, beside the policy and outside any export. A row with a source
	// of its own (a sign-in flow) has no value to write.
	source := filepath.Join(dir, "secret")
	if cfg.Secret != nil && cfg.Secret.Source == "" {
		if err := os.WriteFile(source, []byte(cfg.Secret.Value), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("workcell: write the secret: %w", err)
		}
	}
	policy, err := policyTOML(cfg, source)
	if err == nil && cfg.Update != nil { // the [update] table, after the policy: every run of the session reads it
		var table []byte
		if table, err = updateTable(dir, *cfg.Update); err == nil {
			policy = append(policy, table...)
		}
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("workcell: %w", err)
	}
	// The session's policy, where `workcell run` reads it with XDG_CONFIG_HOME at the session's config directory: <dir>/config/workcell/config.toml.
	file := filepath.Join(dir, "config", policyFile)
	if err := errors.Join(os.MkdirAll(filepath.Dir(file), 0o755), os.Mkdir(filepath.Join(dir, "cwd"), 0o755)); err == nil {
		err = os.WriteFile(file, policy, 0o644)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("workcell: write the policy: %w", err)
	}
	w.dir, w.payload, w.cfg = dir, cfg.Payload, cfg
	if cfg.Isolated {
		if w.ns, err = isolate(dir, cfg.Payload); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("workcell: %w", err)
		}
	}
	if cfg.Workspace != "" {
		return "/workspace", nil // where `workcell run` shows a copy of its working directory
	}
	return "", nil
}

// Exec is one `workcell run`: a fresh VM boots, the guest's shell takes the payload from stdin and runs it, and the VM goes away. Every exit status is a
// result, 125 and 126 included. With a Command, the product runs that name from the layer the test installed, on a stdin nothing writes, held open: no Stdin
// frame, nothing for the guest to acknowledge before the command speaks.
func (w *workcell) Exec(ctx context.Context, args ...string) (Output, error) {
	if w.dir == "" {
		return Output{}, errors.New("workcell: Exec before Start")
	}
	if w.cfg.Command != "" {
		r, wr, err := os.Pipe()
		if err != nil {
			return Output{}, err
		}
		defer r.Close()
		defer wr.Close()
		return w.cli(ctx, r, runCommand(w.cfg, append([]string{w.cfg.Command}, args...)...)...)
	}
	payload, err := os.Open(w.payload)
	if err != nil {
		return Output{}, fmt.Errorf("workcell: payload: %w", err)
	}
	defer payload.Close()
	return w.cli(ctx, payload, runArgs(w.cfg, loader, args...)...)
}

// Pull is one `workcell pull <dest>` in the export; a non-zero exit is a refusal, an error holding the product's stderr.
func (w *workcell) Pull(ctx context.Context, dest string) error {
	if w.dir == "" {
		return errors.New("workcell: Pull before Start")
	}
	if w.cfg.Workspace == "" {
		return errors.New("workcell: the session has no workspace to pull")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	out, err := w.cli(ctx, nil, "pull", dest)
	if err != nil {
		return err
	}
	if out.Exit != 0 {
		return fmt.Errorf("workcell pull: exit %d: %s", out.Exit, bytes.TrimSpace(out.Stderr))
	}
	return nil
}

// Bench is one `workcell bench start` with the session's artifacts (P1).
func (w *workcell) Bench(ctx context.Context) (Output, error) {
	if w.dir == "" {
		return Output{}, errors.New("workcell: Bench before Start")
	}
	return w.cli(ctx, nil, "bench", "start")
}

// cli runs the product once with the prepared artifacts, the session's policy and trust store, in its export, stdin from in, both streams bounded, steered when
// the session names a resolver. An exit status is a result, not an error. On cancel the product gets SIGTERM and a little while; then its group is killed.
func (w *workcell) cli(ctx context.Context, in io.Reader, args ...string) (Output, error) {
	env := append(os.Environ(), "XDG_DATA_HOME="+prepared.xdg, "XDG_CONFIG_HOME="+filepath.Join(w.dir, "config"))
	if w.cfg.Roots != "" {
		env = append(env, "SSL_CERT_FILE="+w.cfg.Roots) // the operator's trust store, which Go reads for the system roots
	}
	argv := append([]string{cmp.Or(w.bin, prepared.bin)}, args...)
	if w.cfg.Resolver != "" {
		var err error
		ns := 0
		if w.ns != nil {
			ns = w.ns.pid
		}
		if argv, err = steered(w.dir, w.cfg.Resolver, env, argv, ns); err != nil {
			return Output{}, fmt.Errorf("workcell %s: %w", args[0], err)
		}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = filepath.Join(w.dir, "cwd")
	if w.cfg.Workspace != "" {
		cmd.Dir = w.cfg.Workspace
	}
	cmd.Env = env
	cmd.Stdin = in
	stdout, stderr := &bounded{limit: MaxStdout}, &bounded{limit: MaxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	finish := func() {}
	if w.cfg.Head {
		head, fin, err := headPipe(stdout)
		if err != nil {
			return Output{}, err
		}
		cmd.Stdout, finish = head, fin
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // the product and what it forks, in a group of their own
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		return Output{}, fmt.Errorf("workcell %s: %w", args[0], err)
	}
	w.mu.Lock()
	w.run = cmd
	w.mu.Unlock()
	err := cmd.Wait()
	finish()
	w.mu.Lock()
	w.run = nil
	w.mu.Unlock()
	if ctx.Err() != nil && cmd.Process != nil {
		// The kill Go sent after WaitDelay reached only cmd.Process, which under steering is sudo: what is left of the group, a product that ignored the
		// SIGTERM and its hypervisor, goes now. They run as the suite's user, so that needs no sudo.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out := Output{Stdout: stdout.bytes(), Stderr: stderr.bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return out, fmt.Errorf("workcell %s: %w", args[0], ctx.Err())
	case errors.As(err, &exit):
		out.Exit = exit.ExitCode()
	default:
		return out, fmt.Errorf("workcell %s: %w", args[0], err)
	}
	return out, nil
}

// A session of the suite is several of the product's, one per `workcell run` (A2), each with sessions/<id>/audit.log under the data directory, one JSON line
// per record; the suite's record is theirs, in order, the file itself.

// sessions lists the product's sessions of this one with a record, oldest first: an id begins with the session's UTC start time.
func (w *workcell) sessions() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(prepared.xdg, "workcell", "sessions"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("workcell: sessions: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if _, err := os.Stat(record(e.Name())); e.IsDir() && err == nil {
			ids = append(ids, e.Name())
		}
	}
	return ids, nil
}

// record is the host path of the product's record of the session id.
func record(id string) string {
	return filepath.Join(prepared.xdg, "workcell", "sessions", id, "audit.log")
}

// Audit reads every record of the product's sessions of this one, oldest first, and returns the newest file's path. With no session yet it runs one that does
// nothing in the guest, under the session's own policy and caps.
func (w *workcell) Audit(ctx context.Context) (string, []string, error) {
	if w.dir == "" {
		return "", nil, errors.New("workcell: Audit before Start")
	}
	ids, err := w.sessions()
	if err != nil {
		return "", nil, err
	}
	if len(ids) == 0 {
		out, err := w.cli(ctx, nil, runArgs(w.cfg, "exit 0")...)
		if err != nil {
			return "", nil, err
		}
		if out.Exit != 0 {
			return "", nil, fmt.Errorf("workcell run (for the record's start): exit %d: %s", out.Exit, bytes.TrimSpace(out.Stderr))
		}
		if ids, err = w.sessions(); err != nil {
			return "", nil, err
		}
		if len(ids) == 0 {
			return "", nil, errors.New("workcell: the run left no session with a record")
		}
	}
	var path string
	var records []string
	for _, id := range ids {
		path = record(id)
		b, err := os.ReadFile(path)
		if err != nil {
			return path, nil, fmt.Errorf("workcell: record of session %s: %w", id, err)
		}
		if len(b) > 0 {
			records = append(records, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")...)
		}
	}
	return path, records, nil
}

// Verify runs `workcell verify <id>` for every session of this one: nil only when each exits 0; no session at all is an error, since nothing is not intact.
func (w *workcell) Verify(ctx context.Context) error {
	if w.dir == "" {
		return errors.New("workcell: Verify before Start")
	}
	ids, err := w.sessions()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return errors.New("workcell: no session to verify")
	}
	for _, id := range ids {
		out, err := w.cli(ctx, nil, "verify", id)
		if err != nil {
			return err
		}
		if out.Exit != 0 {
			line, _, _ := strings.Cut(strings.TrimSpace(string(out.Stderr)), "\n")
			return fmt.Errorf("workcell verify %s: exit %d: %s", id, out.Exit, line)
		}
	}
	return nil
}

// Bind opens a socket where the product reaches the test host: the session's own namespace, else the host's network.
func (w *workcell) Bind(_ context.Context, network, addr string) (net.Listener, net.PacketConn, error) {
	if w.ns != nil {
		return w.ns.bind(network, addr)
	}
	return bindHere(network, addr)
}

// Helper names the process whose death I11 is about: the proxy, the resolver and the broker are the one `workcell run` that owns the VM (A9), found below the
// run in flight (productProcess), given a moment to appear.
func (w *workcell) Helper(ctx context.Context, name string) (int, error) {
	switch name {
	case "proxy", "resolver", "broker", "supervisor":
	default:
		return 0, fmt.Errorf("workcell: no helper %q", name)
	}
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		w.mu.Lock()
		run := w.run
		w.mu.Unlock()
		if run != nil {
			if pid, ok := productProcess(run.Process.Pid, cmp.Or(w.bin, prepared.bin)); ok {
				return pid, nil
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return 0, errors.New("workcell: no run of the product is in flight: a helper lives only as long as one")
		}
	}
}

// rows maps a provider to its pin row, as the product's install table does.
var rows = map[string]string{"claude": "claude-code", "codex": "codex", "copilot": "copilot-cli"}

// Install builds the product once more with the row l needs in place of the file under pins/, by a build overlay (A11), has it run `workcell update --to
// <version> <agent>`, and names the image `current` then points at. Runs use that binary.
func (w *workcell) Install(ctx context.Context, l Layer) (string, error) {
	name, ok := rows[l.Agent]
	if w.dir == "" || !ok {
		return "", fmt.Errorf("workcell: Install before Start, or no pin row for agent %q", l.Agent)
	}
	sum := l.Digest
	if l.Artifact != nil {
		sum = fmt.Sprintf("%x", sha256.Sum256(l.Artifact))
	}
	row := fmt.Sprintf(`{"Name":%q,"Class":"guest","Version":%q,"Artifacts":{%q:{"URL":%q,"SHA256":%q}}}`, name, l.Version, runtime.GOARCH, l.URL, sum)
	dir := filepath.Join(w.dir, "overlay")
	file, bin := filepath.Join(dir, name+".json"), filepath.Join(dir, "workcell")
	swap := fmt.Sprintf(`{"Replace":{%q:%q}}`, filepath.Join(prepared.repo, "pins", name+".json"), file)
	err := errors.Join(os.MkdirAll(dir, 0o755), os.WriteFile(file, []byte(row), 0o644), os.WriteFile(file+".overlay", []byte(swap), 0o644))
	if err == nil {
		err = hostBuild(ctx, prepared.repo, bin, module+"/cmd/workcell", file+".overlay")
	}
	if err == nil {
		err = sign(ctx, dir, bin)
	}
	if err != nil {
		return "", fmt.Errorf("workcell: build with the row %s: %w", name, err)
	}
	w.bin = bin
	// The update is the host's own, never steered: a served artifact is trusted through the suite's roots, an upstream's through the host's.
	host := &workcell{dir: w.dir, bin: bin}
	if l.Artifact != nil {
		host.cfg.Roots = w.cfg.Roots
	}
	out, err := host.cli(ctx, nil, "update", "--to", l.Version, l.Agent)
	if err == nil && out.Exit != 0 {
		err = fmt.Errorf("exit %d: %s", out.Exit, bytes.TrimSpace(out.Stderr))
	}
	layers := filepath.Join(prepared.xdg, "workcell", "layers", l.Agent)
	var current []byte
	if err == nil {
		current, err = os.ReadFile(filepath.Join(layers, "current"))
	}
	if err != nil {
		return "", fmt.Errorf("workcell update %s: %w", l.Agent, err)
	}
	return filepath.Join(layers, strings.TrimSpace(string(current))), nil
}

// updateTable is the [update] table of u as a user would write it: the channel, a CA file under dir, and u.Key in hex (A11).
func updateTable(dir string, u UpdateConfig) ([]byte, error) {
	ca := filepath.Join(dir, "ca.pem")
	table := []byte("[update]\n")
	var err error
	for _, kv := range []struct{ key, value string }{{"channel", u.Channel}, {"ca", ca}, {"key", hex.EncodeToString(u.Key)}} {
		if table, err = quoted(append(table, kv.key+" = "...), "update "+kv.key, kv.value); err != nil {
			return nil, err
		}
		table = append(table, '\n')
	}
	return table, os.WriteFile(ca, u.CA, 0o644)
}

// Update runs the plain product once as a user with an [update] table would, under a configuration of its own holding the table alone; what it installed is the
// answer (Installed).
func (w *workcell) Update(ctx context.Context, u UpdateConfig) ([]byte, error) {
	agent := agentOf(u.Name)
	if w.dir == "" || agent == "" {
		return nil, fmt.Errorf("workcell: Update before Start, or no pin row named %q", u.Name)
	}
	host := &workcell{dir: filepath.Join(w.dir, "update"), bin: prepared.bin}
	file := filepath.Join(host.dir, "config", policyFile)
	err := errors.Join(os.MkdirAll(filepath.Dir(file), 0o755), os.MkdirAll(filepath.Join(host.dir, "cwd"), 0o755))
	var table []byte
	if err == nil {
		table, err = updateTable(host.dir, u)
	}
	if err == nil {
		err = os.WriteFile(file, table, 0o644)
	}
	if err != nil {
		return nil, fmt.Errorf("workcell: write the update table: %w", err)
	}
	out, err := host.cli(ctx, nil, "update", "--to", u.Version, agent)
	if err != nil {
		return nil, err
	}
	if out.Exit != 0 {
		fmt.Fprintf(os.Stderr, "escape: workcell update --to %s %s: exit %d: %s\n", u.Version, agent, out.Exit, bytes.TrimSpace(out.Stderr))
	}
	return w.Installed(ctx, u.Name)
}

// agentOf is the provider whose pin row is name, "" for none.
func agentOf(name string) string {
	for a, n := range rows {
		if n == name {
			return a
		}
	}
	return ""
}

// Installed reads the artifact for the pin name from the image `current` names; nil when no layer is current.
func (w *workcell) Installed(ctx context.Context, name string) ([]byte, error) {
	agent := agentOf(name)
	if agent == "" {
		return nil, fmt.Errorf("workcell: no pin row named %q", name)
	}
	layers := filepath.Join(prepared.xdg, "workcell", "layers", agent)
	current, err := os.ReadFile(filepath.Join(layers, "current"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// debugfs reads the image without a mount; it exits 0 whatever happened, and says on stderr what it could not do.
	image := filepath.Join(layers, filepath.Base(strings.TrimSpace(string(current))))
	cmd := exec.CommandContext(ctx, "debugfs", "-R", "cat bin/"+agent, image)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err == nil && len(b) == 0 {
		err = fmt.Errorf("%s", bytes.TrimSpace(stderr.Bytes()))
	}
	if err != nil {
		return nil, fmt.Errorf("workcell: read bin/%s of the layer image %s: %w", agent, image, err)
	}
	return b, nil
}

// Stop removes the session's directory, every session image the product kept (no `workcell rm` exists yet), every layer and what the update client keeps
// between runs, so that the next test finds only its own.
func (w *workcell) Stop() error {
	if w.dir == "" {
		return nil
	}
	if w.ns != nil {
		w.ns.stop()
	}
	if w.cfg.Resolver != "" {
		settle() // the host's resolver cache, where it has one, outlives the session
	}
	errs := []error{os.RemoveAll(w.dir)}
	for _, kept := range []string{"sessions", "layers", "channel.serial", "channel.day", "channel.next"} {
		errs = append(errs, os.RemoveAll(filepath.Join(prepared.xdg, "workcell", kept)))
	}
	return errors.Join(errs...)
}
