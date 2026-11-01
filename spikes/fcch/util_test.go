// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fcch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

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

// initramfs is an uncompressed cpio holding one executable, /init.
func initramfs(init []byte) []byte {
	return slices.Concat(newc("init", 0o100755, init), newc("TRAILER!!!", 0, nil))
}

// api is a client for Firecracker's HTTP API on a unix socket.
type api struct{ c *http.Client }

func newAPI(sock string) *api {
	return &api{&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}}
}

// put sends a JSON body and wants 204 No Content.
func (a *api) put(path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("PUT %s: %s: %s", path, resp.Status, msg)
	}
	return nil
}

// parseHello splits the guest's line "hello <token> k=v ..." into its fields.
func parseHello(line string) (token string, kv map[string]string) {
	kv = map[string]string{}
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "hello" {
		return "", kv
	}
	for _, p := range f[2:] {
		if k, v, ok := strings.Cut(p, "="); ok {
			kv[k] = v
		}
	}
	if c, err := url.QueryUnescape(kv["cmdline"]); err == nil && c != "" {
		kv["cmdline"] = c
	}
	return f[1], kv
}

// sumFor finds the SHA-256 that a SHA256SUMS file lists for name.
func sumFor(sums, name string) (string, bool) {
	for _, l := range strings.Split(sums, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.TrimPrefix(f[1], "./") == name {
			return f[0], true
		}
	}
	return "", false
}

// scanProc returns the pids whose /proc/<pid>/<file> (NULs shown as blanks) matches.
func scanProc(file string, match func(string) bool) (pids []string) {
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

// download fetches url into dir/name and logs the SHA-256 before it compares it.
func download(t *testing.T, dir, url, name, want string) (string, error) {
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	t.Logf("fcch sha256 %s=%s", name, got)
	if got != want {
		return "", fmt.Errorf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path, nil
}

// untar writes the regular files of a gzipped tar that keep(name) maps to a
// local path under dir. Everything else, links included, is skipped.
func untar(archive, dir string, keep func(string) (string, bool)) error {
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
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel, ok := keep(h.Name)
		if h.Typeflag != tar.TypeReg || !ok {
			continue
		}
		out := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, tr)
		if err := errors.Join(err, w.Close()); err != nil {
			return err
		}
	}
}

func goBuild(t *testing.T, out, pkg string, env ...string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, module+pkg)
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s %v: %v\n%s", pkg, env, err, b)
	}
}

func elfFacts(t *testing.T, path string) (interp, needed string) {
	t.Helper()
	f, err := elf.Open(path)
	must(t, err)
	defer f.Close()
	interp = "none"
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			b, err := io.ReadAll(p.Open())
			must(t, err)
			interp = strings.TrimRight(string(b), "\x00")
		}
	}
	libs, err := f.ImportedLibraries()
	must(t, err)
	if len(libs) == 0 {
		return interp, "none"
	}
	return interp, strings.Join(libs, ",")
}

func size(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// firstLine is the first line of a tool's output, with blanks turned to underscores.
func firstLine(out []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.ReplaceAll(l, " ", "_")
}

func stats(v []int64) string {
	s := slices.Sorted(slices.Values(v))
	return fmt.Sprintf("n=%d p50=%d min=%d max=%d", len(s), s[len(s)/2], s[0], s[len(s)-1])
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
