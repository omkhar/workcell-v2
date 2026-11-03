// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The pinned guest artifacts. The product's own hosted test uses these.
const (
	firecrackerURL = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	firecrackerSum = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	firecrackerBin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	vmlinuxURL     = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	vmlinuxSum     = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
	maxDownload    = 256 << 20 // more than any of them; a runaway body stops here
	module         = "github.com/omkhar/workcell/v2"
)

// loader runs inside the guest: it takes the payload from stdin, since the
// guest sees nothing of the host, and runs it with the test's arguments.
const loader = `cat >/tmp/p && chmod 755 /tmp/p && exec /tmp/p "$@"`

// prepared is what Prepare made, once per process, for every session.
var prepared struct {
	bin string // the workcell binary
	xdg string // XDG_DATA_HOME holding workcell/{firecracker,vmlinux,initrd.cpio,root.ext4}
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
// looks for, in parallel: the two pinned downloads, the init packed as an
// initrd, the root image from the pinned Debian, and the binary itself.
func prepareWorkcell(ctx context.Context, dir string) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("workcell adapter: the pinned guest is x86_64, this host is %s", runtime.GOARCH)
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
	fmt.Fprintln(os.Stderr, "escape: preparing the workcell sandbox: two pinned downloads, three builds and the guest image, once")
	err = parallel(
		func() error {
			tgz, err := fetch(ctx, firecrackerURL, firecrackerSum)
			if err != nil {
				return err
			}
			bin, err := tarMember(tgz, firecrackerBin)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(data, "firecracker"), bin, 0o755)
		},
		func() error {
			k, err := fetch(ctx, vmlinuxURL, vmlinuxSum)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(data, "vmlinux"), k, 0o644)
		},
		func() error {
			init := filepath.Join(tmp, "init")
			if err := goBuild(ctx, repo, init, module+"/cmd/workcell-init"); err != nil {
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
			if err := goBuild(ctx, repo, mkimage, module+"/cmd/mkimage"); err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx, mkimage, "-pin", filepath.Join(repo, "pins", "debian.json"), "-arch", "amd64", "-o", filepath.Join(data, "root.ext4"))
			cmd.Dir = tmp
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("mkimage: %v: %s", err, bytes.TrimSpace(out))
			}
			return nil
		},
		func() error {
			return goBuild(ctx, repo, filepath.Join(tmp, "workcell"), module+"/cmd/workcell")
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

// tarMember returns the named member of a gzipped tar archive.
func tarMember(tgz []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("archive has no %s: %w", name, err)
		}
		if h.Name == name {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

// goBuild compiles pkg of the module at repo into out, static, for the guest's
// and the host's Linux, as the product's own build does.
func goBuild(ctx context.Context, repo, out, pkg string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, pkg)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
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

// cli runs the product once with the prepared artifacts, in the session's
// export when it has one, stdin from in, both streams bounded. An exit
// status is reported in Output, not as an error. On cancel the product gets
// SIGTERM, which it forwards, and a little while to take its VM down.
func (w *workcell) cli(ctx context.Context, in io.Reader, args ...string) (Output, error) {
	cmd := exec.CommandContext(ctx, prepared.bin, args...)
	cmd.Dir = w.dir
	if w.cfg.Workspace != "" {
		cmd.Dir = w.cfg.Workspace
	}
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+prepared.xdg)
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
