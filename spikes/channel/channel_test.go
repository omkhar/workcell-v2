// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// TestDailyChannel below (B-826) measures B9 and B10 on a real VM, against a channel the test serves on its own loopback
// (T8): the daily check never delays a session start, it runs once a day and the next start applies what it kept, a layer
// whose binary cannot run is rolled back and not installed again, and a held channel makes no request. It starts only
// processes of its own: the product it builds and the guests that product boots. Nothing here comes from a release.

package channel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	product "github.com/omkhar/workcell/v2/internal/channel"
)

const (
	firecrackerURL = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	firecrackerSum = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	firecrackerBin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	vmlinuxURL     = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	vmlinuxSum     = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
	maxDownload    = 256 << 20
	day            = 24 * 60 * 60
	p50Limit       = 2500 * time.Millisecond // a start with the channel unreachable or hanging must stay this fast
)

// TestDailyChannel runs the product as a user with an [update] table would, in a data and config directory of
// its own: (a) `bench start` with no table, with an unreachable channel and with one that hangs; (b) three session
// starts under a manifest that pins a release whose binary cannot run; (c) that binary's failure and what follows
// it; (d) a held channel. One "B9" line per measurement.
func TestDailyChannel(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skipf("the pinned guest is linux/amd64, this is %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
	repo, root := moduleRoot(t), t.TempDir()
	xdg, cfg, work, build := filepath.Join(root, "xdg"), filepath.Join(root, "config"), filepath.Join(root, "project"), filepath.Join(root, "build")
	data, bin := filepath.Join(xdg, "workcell"), filepath.Join(root, "workcell")
	for _, p := range []string{data, filepath.Join(cfg, "workcell"), work, build} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/workcell")
	cmd.Dir, cmd.Env = repo, append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/workcell: %v: %s", err, b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	err := prepare(ctx, repo, build, data)
	cancel()
	if err != nil {
		t.Fatalf("cannot make the guest files: %v", err)
	}

	// The channel: a loopback TLS server whose certificate the table's ca names, signing with a key made here.
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	served, seen := map[string][]byte{}, map[string]int{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen[r.URL.Path]++
		if b, ok := served[r.URL.Path]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	set := func(path string, b []byte) { mu.Lock(); served[path] = b; mu.Unlock() }
	gets := func(path string) int { mu.Lock(); defer mu.Unlock(); return seen[path] }
	total := func() (n int) {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range seen {
			n += c
		}
		return n
	}
	ca := filepath.Join(cfg, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := func(channel string) { // "" for no [update] table at all
		table := ""
		if channel != "" {
			table = "[update]\nchannel = \"" + channel + "\"\nca = \"" + ca + "\"\nkey = \"" + hex.EncodeToString(pub) + "\"\n"
		}
		if err := os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte(table), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newDay := func() { os.Remove(filepath.Join(data, "channel.day")) }
	env := append(os.Environ(), "XDG_DATA_HOME="+xdg, "XDG_CONFIG_HOME="+cfg)
	run := func(args ...string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		c := exec.CommandContext(ctx, bin, args...)
		c.Dir, c.Env, c.WaitDelay = work, env, 3*time.Second
		out, err := c.CombinedOutput()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("workcell %s: %v", strings.Join(args, " "), err)
		}
		t.Logf("$ workcell %s   (exit %d)\n%s", strings.Join(args, " "), code, out)
		return string(out), code
	}
	layers := filepath.Join(data, "layers", "claude")
	marker := func(which string) string {
		b, _ := os.ReadFile(filepath.Join(layers, which))
		return strings.TrimSpace(string(b))
	}
	until := func(ok func() bool) bool {
		for i := 0; i < 500 && !ok(); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		return ok()
	}

	// (a) bench start, with the check against nothing, a closed port and a listener that accepts and never answers.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hang.Close()
	var hung []net.Conn
	go func() {
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			hung = append(hung, c)
			mu.Unlock()
		}
	}()
	p50 := regexp.MustCompile(`p50=(\d+)ms`)
	cases := []struct{ name, channel string }{
		{"no [update] table", ""},
		{"channel unreachable (closed port)", "https://" + closedAddr + "/channel.json"},
		{"channel hangs (accepts, never answers)", "https://" + hang.Addr().String() + "/channel.json"},
	}
	for pass := 1; pass <= 2; pass++ { // twice, the second pass in reverse order: the runner's noise and the channel's cost tell apart
		if pass == 2 {
			slices.Reverse(cases)
		}
		for _, c := range cases {
			config(c.channel)
			newDay()
			out, code := run("bench", "start")
			m := p50.FindStringSubmatch(out)
			ms := -1
			if m != nil {
				ms, _ = strconv.Atoi(m[1])
			}
			t.Logf("B9 bench start, pass %d, %s: %s", pass, c.name, strings.TrimSpace(out))
			if code != 0 || ms < 0 || time.Duration(ms)*time.Millisecond > p50Limit {
				t.Errorf("bench start with %s (pass %d): exit %d, p50 %d ms; want 0 and at most %v", c.name, pass, code, ms, p50Limit)
			}
		}
	}
	mu.Lock()
	t.Logf("B9 the hanging listener took %d connection(s) from the bench", len(hung))
	mu.Unlock()

	// (b) the daily check: install 1.0.0 by the verb, publish 1.0.1 whose binary cannot run, start three sessions.
	honest, broken := []byte("#!/bin/sh\necho ok 1.0.0\n"), []byte("#!/nonexistent/interpreter\n")
	now := time.Now().Unix()
	pin := func(version string, body []byte) map[string]map[string]product.Pin {
		sum := sha256.Sum256(body)
		set("/"+version, body)
		return map[string]map[string]product.Pin{"claude-code": {"amd64": {Version: version, URL: srv.URL + "/" + version, SHA256: hex.EncodeToString(sum[:]), Released: now - 7*day}}}
	}
	publish := func(m product.Manifest) {
		body, _ := json.Marshal(m)
		raw, err := product.Sign(body, []ed25519.PrivateKey{key})
		if err != nil {
			t.Fatal(err)
		}
		set("/channel.json", raw)
	}
	image := func(version string, body []byte) string {
		sum := sha256.Sum256(body)
		return version + "-" + hex.EncodeToString(sum[:]) + ".ext4"
	}
	publish(product.Manifest{Serial: now - 60, Expires: now - 60 + 13*day, Pins: pin("1.0.0", honest)})
	config(srv.URL + "/channel.json")
	if _, code := run("update", "--to", "1.0.0", "claude"); code != 0 || marker("current") != image("1.0.0", honest) {
		t.Fatalf("update --to 1.0.0: exit %d, current %q", code, marker("current"))
	}
	publish(product.Manifest{Serial: now, Expires: now + 13*day, Pins: pin("1.0.1", broken), Previous: pin("1.0.0", honest)})
	newDay()
	before := gets("/channel.json")
	next := filepath.Join(data, "channel.next")
	if _, code := run("run", "--", "true"); code != 0 {
		t.Errorf("the first start of the day: exit %d", code)
	}
	kept := until(func() bool { _, err := os.Stat(next); return err == nil && gets("/channel.json") == before+1 })
	t.Logf("B9 daily, first start: channel.json fetched %d time(s), channel.next kept %v", gets("/channel.json")-before, kept)
	if !kept {
		t.Error("after the first start the channel did not see one GET of channel.json with channel.next kept")
	}
	if _, code := run("run", "--", "true"); code != 0 || marker("current") != image("1.0.1", broken) || gets("/channel.json") != before+1 {
		t.Errorf("the second start: exit %d, current %q, channel.json fetched %d time(s); want 1.0.1 installed and no new fetch", code, marker("current"), gets("/channel.json")-before)
	}
	t.Logf("B9 daily, second start: current %s, channel.json fetched %d time(s)", marker("current"), gets("/channel.json")-before)
	if _, code := run("run", "--", "true"); code != 0 || gets("/channel.json") != before+1 {
		t.Errorf("the third start: exit %d, channel.json fetched %d time(s); want no new fetch the same day", code, gets("/channel.json")-before)
	}
	t.Logf("B9 daily, third start: channel.json fetched %d time(s) over three starts", gets("/channel.json")-before)

	// (c) the binary that cannot run: the layer is set aside and the one before it is current, and the next day's
	// check does not install it again.
	out, code := run("run", "--", "claude")
	_, err = os.Stat(filepath.Join(layers, image("1.0.1", broken)))
	t.Logf("B9 failed layer: exit %d, current %q, previous %q, failed %q, 1.0.1 image present %v", code, marker("current"), marker("previous"), marker("failed"), err == nil)
	if code != 126 || marker("current") != image("1.0.0", honest) || marker("previous") != "" || marker("failed") != image("1.0.1", broken) || err == nil {
		t.Errorf("after the binary could not run: exit %d, current %q, previous %q, failed %q, image err %v; want 126, 1.0.0, none, the 1.0.1 image, removed (%s)", code, marker("current"), marker("previous"), marker("failed"), err, out)
	}
	if out, code := run("run", "--", "claude"); code != 0 || !strings.Contains(out, "ok 1.0.0") {
		t.Errorf("after the rollback: exit %d, %q; want 0 and ok 1.0.0", code, out)
	}
	newDay()
	before, before101 := gets("/channel.json"), gets("/1.0.1")
	run("run", "--", "true")
	until(func() bool { _, err := os.Stat(next); return err == nil })
	run("run", "--", "true")
	t.Logf("B9 new day with the failed mark: current %q, channel.json fetched %d time(s), the 1.0.1 artifact %d time(s)", marker("current"), gets("/channel.json")-before, gets("/1.0.1")-before101)
	if marker("current") != image("1.0.0", honest) || gets("/channel.json") != before+1 || gets("/1.0.1") != before101 {
		t.Errorf("a new day with 1.0.1 marked failed: current %q, channel.json fetched %d, the artifact %d; want 1.0.0, 1, 0", marker("current"), gets("/channel.json")-before, gets("/1.0.1")-before101)
	}

	// (d) a held channel makes no request at all.
	config("hold")
	newDay()
	all := total()
	run("run", "--", "true")
	time.Sleep(time.Second) // a check that should not start would have reached the server by now
	t.Logf("B9 hold: %d request(s) from a start on a new day", total()-all)
	if total() != all {
		t.Errorf("channel = \"hold\": %d request(s); want none", total()-all)
	}
}

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
