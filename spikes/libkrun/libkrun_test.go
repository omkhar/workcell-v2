// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package libkrun is the U-100 spike: boot libkrun on Linux from Go without
// cgo, and measure it. Findings are in notes.md.
package libkrun

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Upstream inputs, pinned by the digest of the bytes this spike first downloaded.
const (
	krunVersion = "1.19.7"
	krunURL     = "https://static.crates.io/crates/libkrun/libkrun-" + krunVersion + ".crate"
	krunSHA256  = "1610d0669ba96a8de6aee2b3ca1e7436933c77836aca6a2920930907046f4aaa"
	fwURL       = "https://github.com/containers/libkrunfw/releases/download/v5.6.2/libkrunfw-x86_64.tgz"
	fwSHA256    = "016c32ddb2a28aa300382cab33352d63a41a901eb36ee8d1ca24b389791c8b91"
	fwMember    = "lib/x86_64-linux-gnu/libkrunfw.so.5.6.2"

	module    = "github.com/omkhar/workcell/v2/spikes/libkrun/cmd/"
	vcpus     = 2
	memMiB    = 1024
	samples   = 20
	bootLimit = 60 * time.Second
)

type spike struct {
	t                         *testing.T
	tmp, lib, root, work, log string
	probe                     string
	env                       []string
}

type bootResult struct {
	line                  string // what the guest sent over vsock
	exit                  int
	bootMS, totalMS, tdMS int64
}

// errNoFirmware is krun_start_enter returning -ENOENT: libkrunfw.so.5 was not found.
var errNoFirmware = errors.New("start_enter=-2")

func TestLibkrun(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("libkrun spike runs on linux/amd64 only")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	}
	_ = f.Close()
	start := time.Now()
	tmp := t.TempDir()
	s := &spike{t: t, tmp: tmp, lib: filepath.Join(tmp, "lib"), root: filepath.Join(tmp, "root"),
		work: filepath.Join(tmp, "work"), log: filepath.Join(tmp, "console.txt")}
	for _, d := range []string{s.lib, s.work, filepath.Join(tmp, "src")} {
		must(t, os.MkdirAll(d, 0o755))
	}
	for _, d := range []string{"proc", "sys", "dev", "tmp", "etc", "sbin", "work"} {
		must(t, os.MkdirAll(filepath.Join(s.root, d), 0o755))
	}

	phase := time.Now()
	krunSrc := s.download(krunURL, "libkrun-"+krunVersion+".crate", krunSHA256)
	fwTgz := s.download(fwURL, "libkrunfw-x86_64.tgz", fwSHA256)
	downloadS := time.Since(phase).Seconds()
	must(t, untar(krunSrc, filepath.Join(tmp, "src"), func(name string) (string, bool) {
		rest, ok := strings.CutPrefix(name, "libkrun-"+krunVersion+"/")
		return rest, ok && filepath.IsLocal(rest)
	}))
	must(t, untar(fwTgz, s.lib, func(name string) (string, bool) { return "libkrunfw.so.5", name == fwMember }))

	phase = time.Now()
	src := filepath.Join(tmp, "src")
	cargo := exec.Command("cargo", "build", "--release", "--locked")
	cargo.Dir = src
	cargo.Env = append(os.Environ(), "CARGO_PROFILE_RELEASE_LTO=false", "CARGO_INCREMENTAL=0")
	if out, err := cargo.CombinedOutput(); err != nil {
		t.Fatalf("cargo build: %v\n%s", err, tail(string(out), 40))
	}
	buildS := time.Since(phase).Seconds()
	must(t, copyFile(filepath.Join(src, "target/release/libkrun.so"), filepath.Join(s.lib, "libkrun.so")))
	rust, _ := exec.Command("rustc", "--version").Output()

	phase = time.Now()
	guest := filepath.Join(s.root, "guest")
	nocgo, cgo := filepath.Join(tmp, "child-nocgo"), filepath.Join(tmp, "child-cgo")
	goBuild(t, guest, "guest", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	goBuild(t, nocgo, "krunchild", "CGO_ENABLED=0")
	goBuild(t, cgo, "krunchild", "CGO_ENABLED=1")
	must(t, copyFile(guest, filepath.Join(s.root, "sbin/init")))
	gobuildS := time.Since(phase).Seconds()

	t.Logf("libkrun size guest_bytes=%d child_nocgo_bytes=%d child_cgo_bytes=%d libkrun_so_bytes=%d libkrunfw_so_bytes=%d libkrunfw_tgz_bytes=%d libkrun_src_bytes=%d",
		size(guest), size(nocgo), size(cgo), size(filepath.Join(s.lib, "libkrun.so")),
		size(filepath.Join(s.lib, "libkrunfw.so.5")), size(fwTgz), size(krunSrc))
	for _, b := range [][2]string{{"child_nocgo", nocgo}, {"child_cgo", cgo}, {"guest", guest}} {
		interp, needed := elfFacts(t, b[1])
		t.Logf("libkrun elf %s interp=%s needed=%s", b[0], interp, needed)
	}

	// The host loopback probe: a listener the guest should not be able to reach.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer probe.Close()
	go func() {
		for {
			c, err := probe.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	s.probe = probe.Addr().String()

	// Boot A: libkrun's defaults, implicit vsock with TSI.
	needsLD := false
	a, err := s.boot(nocgo, true, false)
	if errors.Is(err, errNoFirmware) {
		needsLD = true
		s.env = []string{"LD_LIBRARY_PATH=" + s.lib}
		a, err = s.boot(nocgo, true, false)
	}
	if err != nil {
		t.Fatalf("boot A: %v\nconsole:\n%s", err, s.console())
	}
	// Boot B: no TSI, so vsock is only the port map. It is also the warm-up.
	b, err := s.boot(nocgo, false, false)
	if err != nil {
		t.Fatalf("boot B: %v\nconsole:\n%s", err, s.console())
	}
	cgoBoot := "ok"
	if _, err := s.boot(cgo, false, false); err != nil {
		cgoBoot = "fail"
		t.Logf("libkrun cgo child error: %v\nconsole:\n%s", err, s.console())
	}

	var boots, totals []int64
	for i := range samples {
		r, err := s.boot(nocgo, false, false)
		if err != nil {
			t.Fatalf("sample %d: %v\nconsole:\n%s", i, err, s.console())
		}
		t.Logf("libkrun sample=%d boot_ms=%d total_ms=%d teardown_ms=%d", i, r.bootMS, r.totalMS, r.tdMS)
		boots, totals = append(boots, r.bootMS), append(totals, r.totalMS)
	}
	t.Logf("libkrun boot_ms %s", stats(boots))
	t.Logf("libkrun total_ms %s", stats(totals))

	// Boot C: no built-in init, the Go guest is PID 1.
	pid1, pid1MS := "fail", int64(-1)
	must(t, copyFile(guest, filepath.Join(s.root, "init.krun")))
	if c, err := s.boot(nocgo, false, true); err != nil {
		t.Logf("libkrun pid1 error: %v\nconsole:\n%s", err, s.console())
	} else {
		pid1, pid1MS = "ok", c.bootMS
	}

	t.Logf("libkrun facts needs_ld_library_path=%t tsi_default_loopback=%s tsi_off_loopback=%s guest_exit_7_host_exit=%d pid1_direct=%s pid1_boot_ms=%d cgo_child_boot=%s vcpus=%d mem_mib=%d lto=false rust=%s download_s=%.1f build_s=%.1f gobuild_s=%.1f test_s=%.1f",
		needsLD, loopback(a.line), loopback(b.line), a.exit, pid1, pid1MS, cgoBoot, vcpus, memMiB,
		strings.ReplaceAll(strings.TrimSpace(string(rust)), " ", "_"), downloadS, buildS, gobuildS, time.Since(start).Seconds())
	if a.exit != 7 {
		t.Errorf("guest exited 7, the VMM exited %d", a.exit)
	}
}

// boot starts one VM through child and does the vsock echo with it. An error
// means the guest did not complete the exchange.
func (s *spike) boot(child string, hijack, pid1 bool) (bootResult, error) {
	var r bootResult
	token := rand.Text()
	_ = os.Remove(filepath.Join(s.work, "from-guest.txt"))
	if err := os.WriteFile(filepath.Join(s.work, "from-host.txt"), []byte(token+"\n"), 0o644); err != nil {
		return r, err
	}
	if err := os.WriteFile(filepath.Join(s.work, "probe.txt"), []byte(s.probe+"\n"), 0o644); err != nil {
		return r, err
	}
	sock := filepath.Join(s.tmp, "vs.sock")
	_ = os.Remove(sock)
	_ = os.Remove(s.log)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return r, err
	}
	defer ln.Close()

	cmd := exec.Command(child, "-lib", s.lib, "-root", s.root, "-work", s.work, "-sock", sock, "-port", "5000",
		"-console", s.log, "-cpus", strconv.Itoa(vcpus), "-mem", strconv.Itoa(memMiB),
		"-hijack="+strconv.FormatBool(hijack), "-pid1="+strconv.FormatBool(pid1))
	cmd.Env = append(os.Environ(), s.env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return r, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		return r, err
	}
	var lines []string
	outDone := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		close(outDone)
	}()
	exited := make(chan time.Time, 1)
	go func() { _ = cmd.Wait(); exited <- time.Now() }()
	kill := func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-exited
	}

	type echo struct {
		line        string
		first, done time.Time
		err         error
	}
	got := make(chan echo, 1)
	go func() {
		var e echo
		defer func() { got <- e }()
		_ = ln.SetDeadline(time.Now().Add(bootLimit))
		c, err := ln.Accept()
		if e.err = err; err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(bootLimit))
		br := bufio.NewReader(c)
		if _, e.err = br.Peek(1); e.err != nil {
			return
		}
		e.first = time.Now()
		if e.line, e.err = br.ReadString('\n'); e.err != nil {
			return
		}
		if _, e.err = io.WriteString(c, e.line); e.err != nil {
			return
		}
		_, e.err = io.Copy(io.Discard, br)
		e.done = time.Now()
	}()

	var e echo
	var end time.Time
	timer := time.NewTimer(bootLimit)
	defer timer.Stop()
	select {
	case e = <-got:
	case end = <-exited:
		_ = ln.Close()
		e = <-got
	case <-timer.C:
		kill()
		return r, fmt.Errorf("no exchange within %v; stderr: %s", bootLimit, tail(stderr.String(), 20))
	}
	if end.IsZero() {
		select {
		case end = <-exited:
		case <-timer.C:
			kill()
			return r, fmt.Errorf("VMM did not exit within %v of the exchange", bootLimit)
		}
	}
	<-outDone
	r.exit = cmd.ProcessState.ExitCode()
	enterNS := int64(0)
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "enter_unix_ns="); ok {
			enterNS, _ = strconv.ParseInt(v, 10, 64)
		}
		if l == errNoFirmware.Error() {
			return r, errNoFirmware
		}
		if strings.HasPrefix(l, "start_enter=") {
			return r, fmt.Errorf("krun_start_enter returned: %s; stderr: %s", l, tail(stderr.String(), 20))
		}
	}
	if e.err != nil {
		return r, fmt.Errorf("vsock exchange: %v (exit %d); stderr: %s", e.err, r.exit, tail(stderr.String(), 20))
	}
	r.line = strings.TrimSpace(e.line)
	back, err := os.ReadFile(filepath.Join(s.work, "from-guest.txt"))
	if err != nil {
		return r, fmt.Errorf("guest wrote nothing back: %v", err)
	}
	if want := "hello " + token + " "; !strings.HasPrefix(r.line, want) || strings.TrimSpace(string(back)) != r.line {
		return r, fmt.Errorf("guest sent %q and wrote back %q, want prefix %q", r.line, back, want)
	}
	r.bootMS = e.first.Sub(time.Unix(0, enterNS)).Milliseconds()
	r.totalMS = e.first.Sub(t0).Milliseconds()
	r.tdMS = end.Sub(e.done).Milliseconds()
	return r, nil
}

func (s *spike) download(url, name, want string) string {
	s.t.Helper()
	path := filepath.Join(s.tmp, name)
	c := http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	must(s.t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(path)
	must(s.t, err)
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	must(s.t, errors.Join(err, f.Close()))
	got := hex.EncodeToString(h.Sum(nil))
	s.t.Logf("libkrun sha256 %s=%s", name, got)
	if got != want {
		s.t.Fatalf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path
}

func (s *spike) console() string {
	b, _ := os.ReadFile(s.log)
	return tail(string(b), 40)
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

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o755)
}

func size(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

func loopback(line string) string {
	if strings.HasSuffix(line, "loopback=ok") {
		return "ok"
	}
	return "err"
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
