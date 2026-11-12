// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package install runs scripts/install.sh against a local server (T8) and times P2: install,
// guest files and the first session. It starts only processes of its own: the script, the
// product it builds and the guest that product boots. Nothing here comes from a release.
package install

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
	"net/http/httptest"
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
	versionVar     = "github.com/omkhar/workcell/v2/internal/version.Version"
	firecrackerURL = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	firecrackerSum = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	firecrackerBin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	vmlinuxURL     = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	vmlinuxSum     = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
	maxDownload    = 256 << 20
	p2Target       = 60 * time.Second
)

// moduleRoot walks up from the working directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// script finds proposed/scripts/install.sh, so that a waiting proposal is what is tested, else
// scripts/install.sh (once the maintainer has adopted the proposal and removed it from proposed/).
func script(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	for _, p := range []string{"proposed/scripts/install.sh", "scripts/install.sh"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			return filepath.Join(root, p)
		}
	}
	t.Fatal("neither scripts/install.sh nor proposed/scripts/install.sh exists")
	return ""
}

// hostAsset is the release asset the script picks on this host.
func hostAsset(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64", "linux/arm64":
		return "workcell-linux-" + runtime.GOARCH
	case "darwin/arm64":
		return "workcell-darwin-arm64"
	}
	t.Skipf("the installer supports no %s/%s", runtime.GOOS, runtime.GOARCH)
	return ""
}

// install runs the script against a server for dist, with a clean environment: no proxy variables
// and nothing from the developer's home. It returns the output, the exit code, the install
// directory and the TMPDIR the script used.
func install(t *testing.T, dist string) (out string, code int, dir, tmp string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code, tmp = run(t, dist, root, "", dir)
	return out, code, dir, tmp
}

// run runs the script in workdir (the current directory if empty) with INSTALL_DIR set to
// installDir, which may be relative. It makes a TMPDIR under root and returns it.
func run(t *testing.T, dist, root, workdir, installDir string) (out string, code int, tmp string) {
	t.Helper()
	srv := httptest.NewServer(http.FileServer(http.Dir(dist)))
	defer srv.Close()
	tmp = filepath.Join(root, "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script(t))
	cmd.Dir = workdir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "TMPDIR=" + tmp, "INSTALL_URL=" + srv.URL, "INSTALL_DIR=" + installDir}
	cmd.WaitDelay = 3 * time.Second
	b, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	t.Logf("$ install.sh   (exit %d)\n%s", code, b)
	return string(b), code, tmp
}

// dist writes a fake release directory: a small executable for this host and, unless sums is
// "missing", a SHA256SUMS whose digest is right or, for "wrong", wrong. For "broken" the
// digest is right but the executable fails.
func dist(t *testing.T, sums string) string {
	t.Helper()
	asset, d := hostAsset(t), t.TempDir()
	body := []byte("#!/bin/sh\necho workcell test\n")
	if sums == "broken" {
		body = []byte("#!/bin/sh\nexit 3\n")
	}
	if err := os.WriteFile(filepath.Join(d, asset), body, 0o755); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	digest := hex.EncodeToString(h[:])
	if sums == "wrong" {
		digest = strings.Repeat("0", 64)
	}
	if sums != "missing" {
		if err := os.WriteFile(filepath.Join(d, "SHA256SUMS"), []byte(digest+"  "+asset+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func empty(t *testing.T, what, d string) {
	t.Helper()
	left, err := os.ReadDir(d)
	if err != nil || len(left) != 0 {
		t.Errorf("%s %s is not empty: %v %v", what, d, left, err)
	}
}

func TestInstallRefusesWrongChecksum(t *testing.T) {
	out, code, dir, tmp := install(t, dist(t, "wrong"))
	if code == 0 || !strings.Contains(out, "checksum") {
		t.Errorf("exit %d, output %q: want a refusal that mentions the checksum", code, out)
	}
	empty(t, "install directory", dir)
	empty(t, "TMPDIR", tmp)
}

func TestInstallRefusesMissingSums(t *testing.T) {
	out, code, dir, tmp := install(t, dist(t, "missing"))
	if code == 0 || !strings.Contains(out, "SHA256SUMS") {
		t.Errorf("exit %d, output %q: want a refusal that names SHA256SUMS", code, out)
	}
	empty(t, "install directory", dir)
	empty(t, "TMPDIR", tmp)
}

func TestInstallVerified(t *testing.T) {
	out, code, dir, tmp := install(t, dist(t, "good"))
	if code != 0 || !strings.Contains(out, "workcell test") {
		t.Errorf("exit %d, output %q: want success and the --version line", code, out)
	}
	if fi, err := os.Stat(filepath.Join(dir, "workcell")); err != nil || fi.Mode() != 0o755 {
		t.Errorf("%s/workcell: %v %v, want mode 0755", dir, fi, err)
	}
	empty(t, "TMPDIR", tmp)
}

// TestInstallRelativeDir: a relative INSTALL_DIR is relative to where the script was started.
func TestInstallRelativeDir(t *testing.T) {
	root, tmpRoot := t.TempDir(), t.TempDir()
	out, code, tmp := run(t, dist(t, "good"), tmpRoot, root, "bin")
	if code != 0 || !strings.Contains(out, "workcell test") {
		t.Errorf("exit %d, output %q: want success and the --version line", code, out)
	}
	if fi, err := os.Stat(filepath.Join(root, "bin", "workcell")); err != nil || fi.Mode() != 0o755 {
		t.Errorf("%s/bin/workcell: %v %v, want mode 0755", root, fi, err)
	}
	empty(t, "TMPDIR", tmp)
}

// TestInstallKeepsOldOnBrokenAsset: a checked asset that does not run leaves the old binary as it was.
func TestInstallKeepsOldOnBrokenAsset(t *testing.T) {
	old := []byte("#!/bin/sh\necho old\n")
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workcell"), old, 0o755); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	out, code, tmp := run(t, dist(t, "broken"), root, "", dir)
	if code == 0 || !strings.Contains(out, "does not run") {
		t.Errorf("exit %d, output %q: want a refusal that says the binary does not run", code, out)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "workcell")); err != nil || !bytes.Equal(got, old) {
		t.Errorf("%s/workcell: %q %v, want it unchanged", dir, got, err)
	}
	if left, err := os.ReadDir(dir); err != nil || len(left) != 1 {
		t.Errorf("install directory %s: %v %v, want only workcell", dir, left, err)
	}
	empty(t, "TMPDIR", tmp)
}

// TestInstallToFirstSession measures P2: install to the first running session. The binary comes
// from the local server, not from a release. Phase 2 stands in for the update client until the
// channel lands (B-826d); the build of the binary itself is not part of the timing.
func TestInstallToFirstSession(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("the pinned guest is linux/amd64, this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
	repo, root := moduleRoot(t), t.TempDir()
	d, bin, work := filepath.Join(root, "dist"), filepath.Join(root, "bin"), filepath.Join(root, "project")
	xdg, config := filepath.Join(root, "xdg"), filepath.Join(root, "config")
	for _, p := range []string{d, bin, work, config, filepath.Join(xdg, "workcell"), filepath.Join(root, "build")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X "+versionVar+"=nightly", "-o", filepath.Join(d, "workcell-linux-amd64"), "./cmd/workcell")
	build.Dir, build.Env = repo, append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/workcell: %v: %s", err, b)
	}
	b, err := os.ReadFile(filepath.Join(d, "workcell-linux-amd64"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	if err := os.WriteFile(filepath.Join(d, "SHA256SUMS"), []byte(hex.EncodeToString(h[:])+"  workcell-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	srv := httptest.NewServer(http.FileServer(http.Dir(d)))
	defer srv.Close()
	cmd := exec.Command("sh", script(t))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "TMPDIR=" + root, "INSTALL_URL=" + srv.URL, "INSTALL_DIR=" + bin}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh: %v: %s", err, out)
	}
	t.Logf("P2 install %.1f", time.Since(start).Seconds())

	mid := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	err = prepare(ctx, repo, filepath.Join(root, "build"), filepath.Join(xdg, "workcell"))
	cancel()
	if err != nil {
		t.Fatalf("cannot make the guest files: %v", err)
	}
	t.Logf("P2 guest files %.1f", time.Since(mid).Seconds())

	mid = time.Now()
	env := append(os.Environ(), "XDG_DATA_HOME="+xdg, "XDG_CONFIG_HOME="+config)
	do := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, filepath.Join(bin, "workcell"), args...)
		c.Dir, c.Env, c.WaitDelay = work, env, 3*time.Second
		out, err := c.CombinedOutput()
		t.Logf("$ workcell %s\n%s", strings.Join(args, " "), out)
		if err != nil {
			t.Errorf("workcell %s: %v", strings.Join(args, " "), err)
		}
		return string(out)
	}
	do("run", "--", "true")
	first := time.Since(mid)
	t.Logf("P2 first session %.1f", first.Seconds())
	total := time.Since(start)
	t.Logf("P2 install to first session %.1f s (target 60)", total.Seconds())
	if total > p2Target {
		t.Errorf("P2: %v from install to first session, target %v", total, p2Target)
	}
	for _, line := range strings.Split(do("ls"), "\n") {
		if id, _, _ := strings.Cut(strings.TrimSpace(line), " "); id != "" {
			do("rm", id)
		}
	}
}

// prepare puts what `workcell run` looks for in data: the pinned Firecracker and kernel, the
// guest init as an initrd, and the root image from the pinned Debian. Copied from spikes/readme.
func prepare(ctx context.Context, repo, tmp, data string) error {
	const module = "github.com/omkhar/workcell/v2"
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
