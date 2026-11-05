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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The adapter on a host with a hypervisor the product drives: KVM through
// Firecracker on Linux, Virtualization.framework on macOS. What differs per
// OS, the guest's architecture, the pinned kernel, the hypervisor binary if
// any, how a host binary is built and whether it must be signed, lives in
// workcell_linux.go and workcell_darwin.go; the session itself is the same.
const (
	maxDownload = 256 << 20 // more than any pinned download; a runaway body stops here
	module      = "github.com/omkhar/workcell/v2"
)

// loader runs inside the guest: it takes the payload from stdin, since the
// guest sees nothing of the host, and runs it with the test's arguments.
const loader = `cat >/tmp/p && chmod 755 /tmp/p && exec /tmp/p "$@"`

// prepared is what Prepare made, once per process, for every session.
var prepared struct {
	bin  string // the workcell binary
	xdg  string // XDG_DATA_HOME holding workcell/{vmlinux,initrd.cpio,root.ext4} and, on Linux, firecracker
	repo string // the module's directory, for a build the product's rows are swapped in (Install)
}

// workcell is one session of the product: a directory holding its policy,
// its secret and, as an empty subdirectory, its cwd when the test exports
// nothing, so that the product exports none of the rest; the payload it
// carries in; and the caps each of its VMs gets. A VM lives only as long
// as one Exec or one Pull.
type workcell struct {
	dir     string
	bin     string // the product with the suite's row compiled in, once Install ran; "" is prepared.bin
	payload string
	cfg     Config
	mu      sync.Mutex
	run     *exec.Cmd // the product, while one run of it is in flight
	ns      *holder   // the session's own network namespace, when isolated
	seen    []string  // the product's sessions of this one, oldest first, as sessions found them
}

// prepareWorkcell fetches, builds and assembles under dir what `workcell run`
// looks for, in parallel: the pinned downloads, the init packed as an
// initrd, the root image from the pinned Debian, and the binary itself,
// signed where the OS wants that.
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

// goBuild compiles pkg of the module at repo into out with env added to the
// environment, under the build overlay file named when one is.
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
	// The secret's value, where only the host reads it: a file of the
	// session's own, mode 0600, beside the policy and outside any export.
	// A row with a source of its own (a sign-in flow) has no value to write.
	source := filepath.Join(dir, "secret")
	if cfg.Secret != nil && cfg.Secret.Source == "" {
		if err := os.WriteFile(source, []byte(cfg.Secret.Value), 0o600); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("workcell: write the secret: %w", err)
		}
	}
	policy, err := policyTOML(cfg, source)
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("workcell: %w", err)
	}
	// The session's policy, where `workcell run` reads it with XDG_CONFIG_HOME
	// at the session's config directory: <dir>/config/workcell/config.toml.
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

// Exec is one `workcell run`: a fresh VM boots, the guest's shell takes the
// payload from stdin and runs it with the arguments, and the VM goes away.
// Every exit status is a result, 125 (no session) and 126 (the guest could
// not run it) included: the runner treats a non-zero one as the probe not
// having run, and an I12 judge reads it as the host's answer to the guest.
func (w *workcell) Exec(ctx context.Context, args ...string) (Output, error) {
	if w.dir == "" {
		return Output{}, errors.New("workcell: Exec before Start")
	}
	payload, err := os.Open(w.payload)
	if err != nil {
		return Output{}, fmt.Errorf("workcell: payload: %w", err)
	}
	defer payload.Close()
	return w.cli(ctx, payload, runArgs(w.cfg, loader, args...)...)
}

// Pull is one `workcell pull <dest>` in the export: the product takes the
// newest session that ran there, boots a guest with its image and writes
// the work tree the guest streams into dest. A non-zero exit is a refusal,
// returned as an error holding the product's stderr; the judge reads it.
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
	out, err := w.cli(ctx, nil, pullArgs(dest)...)
	if err != nil {
		return err
	}
	if out.Exit != 0 {
		return fmt.Errorf("workcell pull: exit %d: %s", out.Exit, bytes.TrimSpace(out.Stderr))
	}
	return nil
}

// Bench is one `workcell bench start` with the session's artifacts: the
// product boots its guest once to warm up and twenty timed times, by itself,
// and prints the one line of SPEC P1. Nothing runs in any of those guests.
func (w *workcell) Bench(ctx context.Context) (Output, error) {
	if w.dir == "" {
		return Output{}, errors.New("workcell: Bench before Start")
	}
	return w.cli(ctx, nil, "bench", "start")
}

// cli runs the product once with the prepared artifacts, the session's
// policy and its trust store, in the session's export when it has one,
// stdin from in, both streams bounded, and, when the session names a
// resolver, under a /etc/resolv.conf of the session's own (steered). An exit status is
// reported in Output, not as an error. On cancel the product gets SIGTERM,
// which it forwards, and a little while to take its VM down; then its
// process group is killed.
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
	w.mu.Lock()
	w.run = nil
	w.mu.Unlock()
	if ctx.Err() != nil && cmd.Process != nil {
		// The kill Go sent after WaitDelay reached only cmd.Process, which
		// under steering is sudo: what is left of the group, a product that
		// ignored the SIGTERM and its hypervisor, goes now. They run as the
		// suite's user, so that needs no sudo.
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

// A session of the suite, Start to Stop, is several of the product's: one
// per `workcell run` (SPEC A2), each with a directory of its own under the
// data directory's sessions/, holding its record as audit.log, one JSON
// line per record. The record of the suite's session is theirs, in order.
// The judges edit the file at the path Audit returns and have the guest
// go for it, so the path is the product's own file, never a copy.

// sessions lists the product's sessions of this one, oldest first: those
// seen before keep their order, and any new one, found under the data
// directory on the host, comes after them by the age of its record. Only a
// session with a record counts.
func (w *workcell) sessions() ([]string, error) {
	dir := filepath.Join(prepared.xdg, "workcell", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("workcell: sessions: %w", err)
	}
	type found struct {
		id   string
		when time.Time
	}
	var fresh []found
	for _, e := range entries {
		if !e.IsDir() || slices.Contains(w.seen, e.Name()) {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, e.Name(), "audit.log"))
		if err != nil {
			continue
		}
		fresh = append(fresh, found{e.Name(), fi.ModTime()})
	}
	slices.SortFunc(fresh, func(a, b found) int { return cmp.Or(a.when.Compare(b.when), strings.Compare(a.id, b.id)) })
	for _, f := range fresh {
		w.seen = append(w.seen, f.id)
	}
	return w.seen, nil
}

// record is the host path of the product's record of the session id.
func record(id string) string {
	return filepath.Join(prepared.xdg, "workcell", "sessions", id, "audit.log")
}

// Audit reads every record of the product's sessions of this one, oldest
// first, from the files the product keeps, and returns the newest file's
// path, as `workcell log` with no id would take it. A record begins with a
// run, so with no session yet Audit runs one that does nothing in the
// guest, under the session's own policy and caps: its start and end are
// the record's first lines, as the control sandbox's are.
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
		if len(b) == 0 {
			continue
		}
		for line := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
			records = append(records, line)
		}
	}
	return path, records, nil
}

// Verify runs `workcell verify <id>` for every session of this one and
// returns nil only when the product accepts each: its exit 0. Any other
// exit is the product's refusal, with its one line of stderr. A session
// whose record was never read is verified all the same; none at all is an
// error, since nothing is not intact.
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

// Bind opens a socket where the product reaches the test host: in the
// session's own namespace when it has one, else in the host's network.
func (w *workcell) Bind(_ context.Context, network, addr string) (net.Listener, net.PacketConn, error) {
	if w.ns != nil {
		return w.ns.bind(network, addr)
	}
	return bindHere(network, addr)
}

// Helper names the process whose death I11 is about. The product has no
// helper process of its own: the proxy, the resolver and the broker are one
// supervisor process, the `workcell run` that owns the session's VM (SPEC
// A9), so each name resolves to it, and any of them dying is that process
// dying. The process lives only as long as a run, so a judge asks during
// one, and the adapter finds the product below the run it started
// (productProcess), giving it a moment to appear.
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

// Install builds the product once more with the row l needs in place of
// the file under pins/ that would hold it, a build overlay, so that the
// tree is untouched and the product has no hook (SPEC A11); has it run
// `workcell update --to <version> <agent>` with the session's trust store;
// and names the image `current` then points at. The runs use that binary.
func (w *workcell) Install(ctx context.Context, l Layer) (string, error) {
	name, ok := rows[l.Agent]
	if w.dir == "" || !ok {
		return "", fmt.Errorf("workcell: Install before Start, or no pin row for agent %q", l.Agent)
	}
	row := fmt.Sprintf(`{"Name":%q,"Class":"guest","Version":%q,"Artifacts":{%q:{"URL":%q,"SHA256":"%x"}}}`, name, l.Version, runtime.GOARCH, l.URL, sha256.Sum256(l.Artifact))
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
	out, err := w.cli(ctx, nil, "update", "--to", l.Version, l.Agent)
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

// Stop removes the session's directory, every session image the product
// kept, since no `workcell rm` exists yet and tests run one at a time, and
// every layer installed: the next test's pull must find only its own runs,
// and its sessions boot with no layer.
func (w *workcell) Stop() error {
	if w.dir == "" {
		return nil
	}
	if w.ns != nil {
		w.ns.stop()
	}
	data := filepath.Join(prepared.xdg, "workcell")
	return errors.Join(os.RemoveAll(w.dir), os.RemoveAll(filepath.Join(data, "sessions")), os.RemoveAll(filepath.Join(data, "layers")))
}
