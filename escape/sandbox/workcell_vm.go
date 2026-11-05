// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	bin string // the workcell binary
	xdg string // XDG_DATA_HOME holding workcell/{vmlinux,initrd.cpio,root.ext4} and, on Linux, firecracker
}

// workcell is one session of the product: a directory for its cwd when the
// test exports nothing, the payload it carries in and the caps each of its
// VMs gets. A VM lives only as long as one Exec or one Pull.
type workcell struct {
	dir     string
	payload string
	cfg     Config
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
			if err := guestBuild(ctx, repo, init, module+"/cmd/workcell-init"); err != nil {
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
			if err := hostBuild(ctx, repo, mkimage, module+"/cmd/mkimage"); err != nil {
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
			if err := hostBuild(ctx, repo, bin, module+"/cmd/workcell"); err != nil {
				return err
			}
			return sign(ctx, tmp, bin)
		},
	)
	if err != nil {
		return fmt.Errorf("workcell adapter: %w", err)
	}
	prepared.bin, prepared.xdg = filepath.Join(tmp, "workcell"), xdg
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

// guestBuild compiles pkg of the module at repo into out for the guest:
// static Linux of the guest's architecture, as the product's own build does.
func guestBuild(ctx context.Context, repo, out, pkg string) error {
	return goBuild(ctx, repo, out, pkg, "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+guestArch)
}

// goBuild compiles pkg of the module at repo into out with env added to the
// environment.
func goBuild(ctx context.Context, repo, out, pkg string, env ...string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, pkg)
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
	policy, err := policyTOML(cfg)
	if err != nil {
		return "", fmt.Errorf("workcell: %w", err)
	}
	dir, err := os.MkdirTemp("", "escape-workcell-")
	if err != nil {
		return "", err
	}
	// The session's policy, where `workcell run` reads it with XDG_CONFIG_HOME
	// at the session's config directory: <dir>/config/workcell/config.toml.
	file := filepath.Join(dir, "config", policyFile)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err == nil {
		err = os.WriteFile(file, policy, 0o644)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("workcell: write the policy: %w", err)
	}
	w.dir, w.payload, w.cfg = dir, cfg.Payload, cfg
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

// cli runs the product once with the prepared artifacts and the session's
// policy, in the session's export when it has one, stdin from in, both
// streams bounded, and, when the session names a resolver, under a
// /etc/resolv.conf of the session's own (steered). An exit status is
// reported in Output, not as an error. On cancel the product gets SIGTERM,
// which it forwards, and a little while to take its VM down.
func (w *workcell) cli(ctx context.Context, in io.Reader, args ...string) (Output, error) {
	env := append(os.Environ(), "XDG_DATA_HOME="+prepared.xdg, "XDG_CONFIG_HOME="+filepath.Join(w.dir, "config"))
	argv := append([]string{prepared.bin}, args...)
	if w.cfg.Resolver != "" {
		var err error
		if argv, err = steered(w.dir, w.cfg.Resolver, env, argv); err != nil {
			return Output{}, fmt.Errorf("workcell %s: %w", args[0], err)
		}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = w.dir
	if w.cfg.Workspace != "" {
		cmd.Dir = w.cfg.Workspace
	}
	cmd.Env = env
	cmd.Stdin = in
	stdout, stderr := &bounded{limit: MaxStdout}, &bounded{limit: MaxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
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

// Stop removes the session's directory and every session image the product
// kept, since no `workcell rm` exists yet and tests run one at a time: the
// next test's pull must find only its own runs.
func (w *workcell) Stop() error {
	if w.dir == "" {
		return nil
	}
	return errors.Join(os.RemoveAll(w.dir), os.RemoveAll(filepath.Join(prepared.xdg, "workcell", "sessions")))
}
