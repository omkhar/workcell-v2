// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package mount

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"strconv"
	"strings"
	"testing"
	"time"
)

// The pinned inputs: Firecracker and kernel A as internal/vmm/firecracker's tests and
// spikes/netpath, kernel B (FUSE_FS=y) as spikes/fcch.
const (
	fcURL      = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	fcSHA256   = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	fcMember   = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	kernelAURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
	kernelASHA = "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
	kernelBURL = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	kernelBSHA = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
)

// needKVM skips where no guest can boot.
func needKVM(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("the pinned Firecracker and kernel are linux/amd64 builds")
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
}

// shortDir is a fresh directory whose vsock socket paths fit sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(dir) > 80 {
		var err error
		if dir, err = os.MkdirTemp("", "wc"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	return dir
}

// download fetches url into dir/name and compares its SHA-256 with want.
func download(dir, url, name, want string) (string, error) {
	path := filepath.Join(dir, name)
	c := http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path, nil
}

// untar writes the one regular member of a gzipped tar to out, executable.
func untar(archive, member, out string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s in %s: %w", member, archive, err)
		}
		if h.Name != member || h.Typeflag != tar.TypeReg {
			continue
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, tr)
		return errors.Join(err, w.Close())
	}
}

// guestInitramfs builds ./cmd/guest for the guest and writes it as /init of an
// uncompressed newc cpio in dir.
func guestInitramfs(dir string) (string, error) {
	bin := filepath.Join(dir, "guest")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/guest")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./cmd/guest: %v\n%s", err, o)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "initramfs.cpio")
	return path, os.WriteFile(path, append(newc("init", 0o100755, b), newc("TRAILER!!!", 0, nil)...), 0o644)
}

// newc returns one entry of a "newc" cpio archive: the 110-byte header, the
// name and its NUL padded to 4, then the data padded to 4.
func newc(name string, mode uint32, data []byte) []byte {
	var b bytes.Buffer
	fields := []uint32{1, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	b.WriteString("070701")
	for _, f := range fields { // ino mode uid gid nlink mtime filesize devmajor devminor rdevmajor rdevminor namesize check
		fmt.Fprintf(&b, "%08X", f)
	}
	b.WriteString(name)
	b.WriteByte(0)
	b.Write(make([]byte, -b.Len()&3))
	b.Write(data)
	b.Write(make([]byte, -b.Len()&3))
	return b.Bytes()
}

// procs returns the pids whose /proc/<pid>/<file> (NULs shown as blanks) matches.
func procs(file string, match func(string) bool) (pids []string) {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/" + file)
		if err == nil && match(strings.ReplaceAll(strings.TrimRight(string(b), "\x00\n"), "\x00", " ")) {
			pids = append(pids, e.Name())
		}
	}
	return pids
}
