// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64

package macos

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Rows (c) and (d): libkrun through purego, and vfkit, a prebuilt VMM on vz.
const (
	krunkitURL = "https://github.com/libkrun/krunkit/releases/download/v1.3.2/krunkit-podman-unsigned-1.3.2.tgz"
	krunkitSHA = "de9ab62dd90461cd1df1e37b78e780690d75490f4bab1674cbb4a1f75b90c227"
	vfkitURL   = "https://github.com/crc-org/vfkit/releases/download/v0.6.4/vfkit"
	vfkitSHA   = "0ed83fc8ca7aa708598835480dba1362406aa7cd1dab3b27464eb76327d9652d"
	cmdline    = "console=hvc0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=blk"
)

// krunRow sets up libkrun (extract, sign the dylibs, build, rpath, sign the
// child) and measures krun-blk. Every failure is logged, never fatal.
func (e *env) krunRow(t *testing.T) {
	tgz, err := cached(t, krunkitURL, "krunkit-podman-unsigned-1.3.2.tgz", krunkitSHA)
	if err != nil {
		t.Logf("macos fail krun-blk download: %v", err)
		return
	}
	root := filepath.Join(filepath.Dir(tgz), "krunkit-1.3.2") // fresh files: signing changes them
	lib := filepath.Join(root, "lib")
	unsigned, child := filepath.Join(e.tmp, "krunchild-unsigned"), filepath.Join(e.tmp, "krunchild")
	steps := [][]string{{"install_name_tool", "-add_rpath", lib, unsigned}}
	for _, f := range []string{"libkrun.dylib", "libepoxy.0.dylib", "libvirglrenderer.1.dylib", "libMoltenVK.dylib"} {
		steps = append(steps, []string{"codesign", "-s", "-", "-f", filepath.Join(lib, f)})
	}
	krunkit := filepath.Join(root, "bin/krunkit")
	steps = append(steps, []string{"install_name_tool", "-add_rpath", lib, krunkit}, []string{"codesign", "-s", "-", "-f", krunkit})
	err = errors.Join(os.RemoveAll(root), untar(tgz, root))
	goBuild(t, unsigned, "krunchild", "CGO_ENABLED=0")
	for _, s := range steps {
		if err != nil {
			break
		}
		if out, e := run(time.Minute, s[0], s[1:]...); e != nil {
			err = fmt.Errorf("%v: %v: %s", s, e, out)
		}
	}
	if err != nil {
		t.Logf("macos fail krun-blk setup: %v", err)
		return
	}
	ver, _ := run(30*time.Second, krunkit, "--version")
	libs, _ := run(time.Minute, "otool", "-L", filepath.Join(lib, "libkrun.dylib"))
	libver := "unknown"
	if _, v, ok := strings.Cut(libs, "@rpath/libkrun.dylib (compatibility version 1.0.0, current version "); ok {
		libver, _, _ = strings.Cut(v, ")")
	}
	rpaths, _ := run(time.Minute, "otool", "-l", filepath.Join(lib, "libkrun.dylib"))
	t.Logf("macos krun versions krunkit=%s libkrun=%s libkrun_lc_rpath=%s krunkit_boots=efi-only",
		firstLine(ver), libver, lcRpaths(rpaths))

	k := &krun{lib: lib}
	// Unsigned (the linker's ad hoc signature, no entitlements), then signed.
	dir := filepath.Join(e.tmp, "ku")
	_, _ = e.prepare(dir, "blk")
	out, _ := run(time.Minute, unsigned, k.args(e, dir)...)
	_ = os.RemoveAll(dir)
	unsignedErr := strings.TrimSpace(strings.ReplaceAll(out, "\n", " | "))
	b, err := os.ReadFile(unsigned)
	if err == nil {
		err = os.WriteFile(child, b, 0o755)
	}
	if err == nil {
		if out, e := run(time.Minute, "codesign", "-s", "-", "-f", "--entitlements", "hv.entitlements", child); e != nil {
			err = fmt.Errorf("codesign: %v: %s", e, out)
		}
	}
	ent, _ := run(time.Minute, "codesign", "-d", "--entitlements", "-", child)
	t.Logf("macos sign krunchild entitlements=%s unsigned_err=%q unsigned_sig=%q signed_sig=%q libkrun_sig=%q",
		entitlements(ent), unsignedErr, signature(unsigned), signature(child), signature(filepath.Join(lib, "libkrun.dylib")))
	if err != nil {
		t.Logf("macos fail krun-blk sign: %v", err)
		return
	}
	k.child = child
	for _, b := range [][2]string{{"krunchild", child}, {"libkrun.dylib", filepath.Join(lib, "libkrun.dylib")},
		{"libepoxy.0.dylib", filepath.Join(lib, "libepoxy.0.dylib")}, {"libvirglrenderer.1.dylib", filepath.Join(lib, "libvirglrenderer.1.dylib")},
		{"libMoltenVK.dylib", filepath.Join(lib, "libMoltenVK.dylib")}, {"KRUN_EFI.silent.fd", filepath.Join(root, "share/krunkit/KRUN_EFI.silent.fd")}} {
		all, foreign := links(b[1])
		t.Logf("macos links %s=%s %s_foreign=%s %s_bytes=%d", b[0], all, b[0], foreign, b[0], size(b[1]))
	}
	e.sockMeasure(t, "krun-blk", k)
}

// vfkitRow fetches the signed vfkit release and measures vfkit-blk.
func (e *env) vfkitRow(t *testing.T) {
	path, err := cached(t, vfkitURL, "vfkit-v0.6.4", vfkitSHA)
	if err == nil {
		err = os.Chmod(path, 0o755)
	}
	if err != nil {
		t.Logf("macos fail vfkit-blk: %v", err)
		return
	}
	ver, _ := run(30*time.Second, path, "--version")
	ent, _ := run(time.Minute, "codesign", "-d", "--entitlements", "-", path)
	all, foreign := links(path)
	t.Logf("macos sign vfkit entitlements=%s sig=%q", entitlements(ent), signature(path))
	t.Logf("macos links vfkit=%s vfkit_foreign=%s vfkit_bytes=%d version=%s", all, foreign, size(path), firstLine(ver))
	v := vfkit{bin: path}
	t.Logf("macos vfkit command=%q", strings.Join(append([]string{"vfkit"}, v.args(e, "<dir>")...), " "))
	e.sockMeasure(t, "vfkit-blk", v)
}

// launcher is a VMM whose guest reaches the host on a unix socket (fcch's pattern).
type launcher interface {
	cmd(e *env, dir string) *exec.Cmd
	sock(dir string) string
}

type krun struct{ lib, child string }

func (k *krun) args(e *env, dir string) []string {
	return []string{"-lib", k.lib, "-kernel", e.kernel["A"], "-initrd", e.initrd, "-cmdline", cmdline,
		"-img", filepath.Join(dir, "share.img"), "-sock", k.sock(dir), "-console", filepath.Join(dir, "console.txt"),
		"-cpus", strconv.Itoa(vcpus), "-mem", strconv.Itoa(memMiB)}
}
func (k *krun) cmd(e *env, dir string) *exec.Cmd { return exec.Command(k.child, k.args(e, dir)...) }
func (k *krun) sock(dir string) string           { return filepath.Join(dir, "k.sock") }

type vfkit struct{ bin string }

func (v vfkit) args(e *env, dir string) []string {
	return []string{"--cpus", strconv.Itoa(vcpus), "--memory", strconv.Itoa(memMiB),
		"--bootloader", fmt.Sprintf("linux,kernel=%s,initrd=%s,cmdline=%q", e.kernel["A"], e.initrd, cmdline),
		"--device", "virtio-blk,path=" + filepath.Join(dir, "share.img"),
		"--device", "virtio-vsock,port=5000,socketURL=" + v.sock(dir),
		"--device", "virtio-serial,logFilePath=" + filepath.Join(dir, "console.txt"), "--restful-uri", "none://"}
}
func (v vfkit) cmd(e *env, dir string) *exec.Cmd { return exec.Command(v.bin, v.args(e, dir)...) }
func (v vfkit) sock(dir string) string           { return filepath.Join(dir, "v.sock") }

// sockMeasure is measure for a launcher: warm-up, samples, facts, SIGKILL boot.
func (e *env) sockMeasure(t *testing.T, name string, l launcher) {
	if _, err := e.sockBoot(t, name, l, false); err != nil {
		t.Logf("macos fail %s warm-up: %v", name, err)
		t.Logf("macos %s=not-booted", name)
		return
	}
	var boots, totals, tds []int64
	var last result
	for i := range samples {
		r, err := e.sockBoot(t, name, l, false)
		if err != nil {
			t.Logf("macos fail %s sample %d: %v", name, i, err)
			return
		}
		t.Logf("macos sample=%d variant=%s boot_ms=%d total_ms=%d teardown_ms=%d", i, name, r.bootMS, r.totalMS, r.tdMS)
		boots, totals, tds, last = append(boots, r.bootMS), append(totals, r.totalMS), append(tds, r.tdMS), r
	}
	t.Logf("macos %s boot_ms %s", name, stats(boots))
	t.Logf("macos %s total_ms %s", name, stats(totals))
	t.Logf("macos %s teardown_ms %s", name, stats(tds))
	t.Logf("macos %s facts loopback=%s ifaces=%s gateway=%s env_leak=%s guest_exit=%s vmm_exit=%d exit_path=poweroff share=blk kernel=%s vsock=%s cmdline=%q leftover=%q helper_procs=%s",
		name, last.kv["loopback"], last.kv["ifaces"], last.kv["gateway"], last.kv["env_leak"], last.kv["exit"], last.vmmExit,
		kernels["A"], cmp.Or(last.child["vsock"], "port-map"), last.kv["cmdline"], last.leftover, last.helpers)
	r, err := e.sockBoot(t, name, l, true)
	if err != nil {
		t.Logf("macos kill %s fail: %v", name, err)
		return
	}
	t.Logf("macos kill %s kill_ms=%d orphans=%d method=%s held_by=%s", name, r.killMS, r.orphans, r.method, strings.TrimSuffix(r.heldBy, ","))
}

type echo struct {
	line        string
	first, done time.Time
	err         error
}

// exchange accepts the guest's connection, times the first byte, echoes the
// first line unless hold is set (closing sent either way) and waits for EOF.
func exchange(ln *net.UnixListener, hold bool, sent chan<- struct{}) <-chan echo {
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
		if !hold {
			_, e.err = io.WriteString(c, e.line)
		}
		close(sent)
		if e.err == nil {
			_, e.err = io.Copy(io.Discard, br)
		}
		e.done = time.Now()
	}()
	return got
}

// sockBoot runs one VM to completion (or, with kill, to SIGKILL once the
// guest's line has arrived, unanswered so the VM stays up) and measures it.
func (e *env) sockBoot(t *testing.T, name string, l launcher, kill bool) (r result, err error) {
	t.Helper()
	e.seq++
	dir := filepath.Join(e.tmp, "s"+strconv.Itoa(e.seq))
	var stdout, stderr bytes.Buffer
	defer func() {
		if err != nil {
			con, _ := os.ReadFile(filepath.Join(dir, "console.txt"))
			t.Logf("macos diag %s stdout:\n%s\nstderr:\n%s\nconsole:\n%s", name, tail(stdout.String(), 20),
				tail(stderr.String(), 20), tail(string(con), 40))
		}
		_ = os.RemoveAll(dir)
	}()
	token, err := e.prepare(dir, "blk")
	if err != nil {
		return r, err
	}
	img := filepath.Join(dir, "share.img")
	if len(l.sock(dir)) > 100 {
		return r, fmt.Errorf("socket path too long for sun_path: %s", l.sock(dir))
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: l.sock(dir), Net: "unix"})
	if err != nil {
		return r, err
	}
	defer ln.Close()
	sent := make(chan struct{})
	got := exchange(ln, kill, sent)
	baseline := count(helper)
	cmd := l.cmd(e, dir)
	cmd.Env = append(os.Environ(), "WC_CANARY="+e.canary)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	t0 := time.Now()
	if err = cmd.Start(); err != nil {
		return r, err
	}
	exited := make(chan time.Time, 1)
	go func() { _ = cmd.Wait(); exited <- time.Now() }()
	killGroup := func() time.Time {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return <-exited
	}
	timer := time.NewTimer(bootLimit)
	defer timer.Stop()
	var end time.Time

	if kill {
		select {
		case <-sent:
		case end = <-exited:
			_ = ln.Close()
			<-got
			return r, errors.New("the VMM exited before the guest's line")
		case <-timer.C:
			killGroup()
			return r, fmt.Errorf("no line within %v", bootLimit)
		}
		before := holders(img)
		for _, p := range procs() {
			if f := strings.Fields(p); slices.Contains(before, f[0]) {
				r.heldBy += filepath.Base(f[len(f)-1]) + ":ppid=" + f[1] + ","
			}
		}
		tk := time.Now()
		r.killMS = killGroup().Sub(tk).Milliseconds()
		time.Sleep(2 * time.Second)
		left := holders(img)
		r.method, r.orphans = "lsof", len(left)
		for _, p := range left { // what ran our VM, found by our own file
			if n, err := strconv.Atoi(p); err == nil && slices.Contains(before, p) {
				_ = syscall.Kill(n, syscall.SIGKILL)
			}
		}
		_ = ln.Close()
		<-got
		return r, nil
	}

	var x echo
	select {
	case x = <-got:
	case end = <-exited:
		_ = ln.Close()
		x = <-got
	case <-timer.C:
		killGroup()
		return r, fmt.Errorf("no exchange within %v", bootLimit)
	}
	if end.IsZero() {
		select {
		case end = <-exited:
		case <-time.After(10 * time.Second):
			end = killGroup()
			return r, errors.New("the VMM did not exit within 10 s of EOF")
		}
	}
	r.child, r.vmmExit = childKV(stdout.String()), cmd.ProcessState.ExitCode()
	r.helpers = fmt.Sprintf("%d->%d", baseline, count(helper))
	if x.err != nil {
		return r, fmt.Errorf("vsock exchange: %v (exit %d)", x.err, r.vmmExit)
	}
	left, _ := os.ReadDir(dir)
	var names []string
	for _, f := range left {
		names = append(names, f.Name())
	}
	r.leftover = strings.Join(names, ",")
	b, err := os.ReadFile(img)
	if err != nil || len(b) < 4096+2048 {
		return r, fmt.Errorf("share image unreadable: %v", err)
	}
	back := strings.TrimSpace(string(bytes.TrimRight(b[4096:4096+2048], "\x00")))
	line := strings.TrimSpace(x.line)
	gotToken, kv := parseHello(line)
	if gotToken != token || back != line {
		return r, fmt.Errorf("guest sent %q and wrote back %q, want token %s", line, back, token)
	}
	r.kv = kv
	start := t0 // vfkit has no separate start step
	if ns := unixNS(r.child, "enter"); ns != 0 {
		start = time.Unix(0, ns)
	}
	r.bootMS, r.totalMS = x.first.Sub(start).Milliseconds(), x.first.Sub(t0).Milliseconds()
	r.tdMS = end.Sub(x.done).Milliseconds()
	return r, nil
}

// lcRpaths lists the LC_RPATH entries in "otool -l" output.
func lcRpaths(out string) string {
	var paths []string
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "cmd LC_RPATH" && i+2 < len(lines) {
			p, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimSpace(lines[i+2]), "path "), " (offset")
			paths = append(paths, p)
		}
	}
	return orNone(paths)
}

// untar writes every regular file of a gzipped tar with a local name under
// dir. Links and everything else are skipped.
func untar(archive, dir string) error {
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
		if h.Typeflag != tar.TypeReg || !filepath.IsLocal(h.Name) {
			continue
		}
		out := filepath.Join(dir, h.Name)
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
