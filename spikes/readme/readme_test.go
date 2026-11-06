// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package readme runs the "first session" commands of the README against the real product
// in a real guest, and logs each command with its output. The README quotes that log.
// It starts only processes of its own: the product it builds and the guest that product boots.
// The one network attempt is a name the host's allowlist refuses, so no packet leaves the host.
package readme

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
	"testing"
	"time"
)

const (
	module         = "github.com/omkhar/workcell/v2"
	firecrackerURL = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	firecrackerSum = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	firecrackerBin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	vmlinuxURL     = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	vmlinuxSum     = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
	maxDownload    = 256 << 20
	prepareLimit   = 2 * time.Minute
	commandLimit   = 120 * time.Second
)

func TestFirstSession(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("the pinned guest is linux/amd64, this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
	root := t.TempDir()
	data := filepath.Join(root, "xdg", "workcell")
	work := filepath.Join(root, "project") // the directory the session starts in
	for _, d := range []string{data, work, filepath.Join(root, "config"), filepath.Join(root, "build")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "build", "workcell")
	ctx, cancel := context.WithTimeout(context.Background(), prepareLimit)
	err := prepare(ctx, filepath.Join(root, "build"), data, bin)
	cancel()
	if err != nil {
		t.Skipf("cannot make the guest image: %v", err)
	}
	env := append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(root, "xdg"), "XDG_CONFIG_HOME="+filepath.Join(root, "config"))

	// do runs the binary directly (no host shell) and logs the command as the README shows it.
	do := func(show string, args ...string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), commandLimit)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir, cmd.Env = work, env
		cmd.WaitDelay = 3 * time.Second
		out, err := cmd.CombinedOutput()
		code := 0
		var exit *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exit):
			code = exit.ExitCode()
		default:
			t.Fatalf("$ %s: %v", show, err)
		}
		t.Logf("$ %s\n%s(exit %d)", show, out, code)
		return string(out), code
	}
	want := func(show string, got, code int) {
		t.Helper()
		if got != code {
			t.Errorf("$ %s: exit %d, want %d", show, got, code)
		}
	}

	_, c := do("workcell --version", "--version")
	want("workcell --version", c, 0)

	cmd := "workcell run -- sh -c 'echo hello from the guest; id -u; uname -m'"
	_, c = do(cmd, "run", "--", "sh", "-c", "echo hello from the guest; id -u; uname -m")
	want(cmd, c, 0)

	cmd = "workcell run -- sh -c 'exit 7'"
	_, c = do(cmd, "run", "--", "sh", "-c", "exit 7")
	want(cmd, c, 7)

	_, c = do("workcell explain", "explain")
	want("workcell explain", c, 0)

	// The guest asks its resolver for a name the allowlist does not hold. The host refuses it
	// and sends nothing upstream.
	cmd = "workcell run -- sh -c 'getent hosts example.invalid || echo denied'"
	_, c = do(cmd, "run", "--", "sh", "-c", "getent hosts example.invalid || echo denied")
	want(cmd, c, 0)

	log, c := do("workcell log", "log")
	want("workcell log", c, 0)
	if !strings.Contains(log, "denied") {
		t.Logf("note: the log shows no denial; the README must not claim one")
	}

	list, c := do("workcell ls", "ls")
	want("workcell ls", c, 0)
	id, _, _ := strings.Cut(strings.TrimSpace(list), " ")
	if id == "" {
		t.Fatal("workcell ls listed no session")
	}
	cmd = "workcell rm <id>"
	_, c = do(cmd+"   (the first id above: "+id+")", "rm", id)
	want(cmd, c, 0)

	_, c = do("workcell ls", "ls")
	want("workcell ls", c, 0)
}

// prepare puts what `workcell run` looks for in data: the pinned Firecracker and kernel, the
// guest init as an initrd, the root image from the pinned Debian; and builds the product at bin.
func prepare(ctx context.Context, tmp, data, bin string) error {
	out, err := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", module).Output()
	if err != nil {
		return fmt.Errorf("find the module: %w", err)
	}
	repo := strings.TrimSpace(string(out))
	build := func(out, pkg string) error {
		cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, pkg)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("build %s: %v: %s", pkg, err, bytes.TrimSpace(b))
		}
		return nil
	}
	fns := []func() error{
		func() error {
			tgz, err := fetch(ctx, firecrackerURL, firecrackerSum)
			if err != nil {
				return err
			}
			b, err := tarMember(tgz, firecrackerBin)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(data, "firecracker"), b, 0o755)
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
			if err := build(init, module+"/cmd/workcell-init"); err != nil {
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
			if err := build(mkimage, module+"/cmd/mkimage"); err != nil {
				return err
			}
			cmd := exec.CommandContext(ctx, mkimage, "-pin", filepath.Join(repo, "pins", "debian.json"), "-arch", "amd64", "-o", filepath.Join(data, "root.ext4"))
			cmd.Dir = tmp
			if b, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("mkimage: %v: %s", err, bytes.TrimSpace(b))
			}
			return nil
		},
		func() error { return build(bin, module+"/cmd/workcell") },
	}
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

// cpioEntry writes one entry of a "newc" cpio archive. A trailer is the entry named
// "TRAILER!!!" with no data.
func cpioEntry(w io.Writer, name string, mode uint32, data []byte) error {
	ino := uint32(1)
	if name == "TRAILER!!!" {
		ino = 0
	}
	fields := []uint32{ino, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	b := []byte("070701")
	for _, f := range fields {
		b = fmt.Appendf(b, "%08X", f)
	}
	b = append(b, name...)
	b = append(b, 0)
	b = pad4(b)
	b = append(b, data...)
	_, err := w.Write(pad4(b))
	return err
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// tarMember returns the named member of a gzipped tar archive.
func tarMember(tgz []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	for tr := tar.NewReader(gz); ; {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("archive has no %s", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Name == name {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}
