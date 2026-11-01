// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Package fcch is the U-101 spike: boot Firecracker and Cloud Hypervisor on
// Linux with the same guest, kernel and measurements as the libkrun spike
// (U-100), driven from Go with exec and net/http only. Findings are in notes.md.
package fcch

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Upstream inputs, pinned by the digest of the bytes this spike first downloaded.
// Fallbacks if one disappears: Firecracker v1.16.2 (same URL pattern), Cloud
// Hypervisor v48.0, kernel B ch-release-v6.12.8-20250613. See notes.md.
const (
	fcURL      = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	fcSHA256   = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	fcDir      = "release-v1.17.0-x86_64/"
	fcBin      = "firecracker-v1.17.0-x86_64"
	chURL      = "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static"
	chSHA256   = "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b"
	kernelAURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
	kernelASHA = "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
	kernelBURL = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	kernelBSHA = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"

	module    = "github.com/omkhar/workcell/v2/spikes/fcch/cmd/"
	vcpus     = 2
	memMiB    = 1024
	samples   = 20
	bootLimit = 60 * time.Second
	exitLimit = 10 * time.Second // the VMM should exit this soon after the guest closes vsock
)

// fcExtraArgs is where the last-resort "--no-seccomp" goes if the runner's
// kernel kills Firecracker's default seccomp filter.
var fcExtraArgs = []string{}

type variant struct{ name, vmm, kernel, share string }

var (
	vFC      = variant{"fc", "fc", "A", "blk"}
	vCHBlk   = variant{"ch-blk", "ch", "A", "blk"}
	vCHFS    = variant{"ch-fs", "ch", "B", "fs"}
	vFCkB    = variant{"fc-kB", "fc", "B", "blk"}
	vCHBlkkB = variant{"ch-blk-kB", "ch", "B", "blk"}
)

type env struct {
	tmp, fc, ch, kernelA, kernelB, initrd, virtiofsd string
	probe, canary                                    string
	seq                                              int
}

type result struct {
	kv                    map[string]string // what the guest reported
	bootMS, totalMS, tdMS int64
	apiMS, vfsReadyMS     int64 // -1: not applicable
	vfsExitMS             int64 // virtiofsd exit minus VMM exit (or kill); -1 n/a, -2 killed after 5 s
	vmmExit               int
	exitPath, leftover    string
	killMS                int64
	orphans               int
}

func TestFCCH(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("fcch spike runs on linux/amd64 only")
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	}
	_ = f.Close()
	start := time.Now()
	tmp := t.TempDir()
	e := &env{tmp: tmp, canary: "canary-" + rand.Text()}
	dl, bin := filepath.Join(tmp, "dl"), filepath.Join(tmp, "bin")
	for _, d := range []string{dl, bin} {
		must(t, os.MkdirAll(d, 0o755))
	}

	// virtiofsd has no prebuilt release: the distribution package, installed beside the downloads.
	aptDone := make(chan struct{})
	go func() { e.virtiofsd = installVirtiofsd(t); close(aptDone) }()
	defer func() { <-aptDone }() // t.Logf must not outlive the test

	phase := time.Now()
	jobs := []struct{ url, name, sha string }{
		{fcURL, "firecracker.tgz", fcSHA256}, {chURL, "cloud-hypervisor-static", chSHA256},
		{kernelAURL, "vmlinux-a", kernelASHA}, {kernelBURL, "vmlinux-b", kernelBSHA},
	}
	paths, errs := make([]string, len(jobs)), make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() { paths[i], errs[i] = download(t, dl, j.url, j.name, j.sha) })
	}
	wg.Wait()
	must(t, errors.Join(errs...))
	downloadS := time.Since(phase).Seconds()
	tgz := paths[0]
	e.ch, e.kernelA, e.kernelB = paths[1], paths[2], paths[3]
	must(t, untar(tgz, bin, func(name string) (string, bool) {
		switch name {
		case fcDir + fcBin:
			return "firecracker", true
		case fcDir + "SHA256SUMS":
			return "SHA256SUMS", true
		}
		return "", false
	}))
	e.fc = filepath.Join(bin, "firecracker")
	sums, err := os.ReadFile(filepath.Join(bin, "SHA256SUMS"))
	must(t, err)
	fcBytes, err := os.ReadFile(e.fc)
	must(t, err)
	h := sha256.Sum256(fcBytes)
	want, ok := sumFor(string(sums), fcBin)
	if !ok || want != hex.EncodeToString(h[:]) {
		t.Fatalf("firecracker sha256 %x is not the one in SHA256SUMS (%q, found %t)", h, want, ok)
	}
	t.Logf("fcch sha256 firecracker=%x fc_sha256sums=match", h)

	phase = time.Now()
	guest := filepath.Join(bin, "guest")
	goBuild(t, guest, "guest", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	guestBytes, err := os.ReadFile(guest)
	must(t, err)
	e.initrd = filepath.Join(bin, "initramfs.cpio")
	must(t, os.WriteFile(e.initrd, initramfs(guestBytes), 0o644))
	gobuildS := time.Since(phase).Seconds()
	<-aptDone

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
	e.probe = probe.Addr().String()

	t.Logf("fcch size fc_bytes=%d ch_bytes=%d kernel_a_bytes=%d kernel_b_bytes=%d initramfs_bytes=%d guest_bytes=%d virtiofsd_bytes=%d",
		size(e.fc), size(e.ch), size(e.kernelA), size(e.kernelB), size(e.initrd), size(guest), size(e.virtiofsd))
	elfs := [][2]string{{"firecracker", e.fc}, {"cloud-hypervisor", e.ch}, {"guest", guest}}
	versions := map[string]string{}
	for _, b := range [][2]string{{"fc", e.fc}, {"ch", e.ch}, {"virtiofsd", e.virtiofsd}} {
		versions[b[0]] = "none"
		if b[1] != "" {
			out, err := exec.Command(b[1], "--version").CombinedOutput()
			versions[b[0]] = firstLine(out)
			if err != nil {
				versions[b[0]] += "_err=" + err.Error()
			}
		}
	}
	if e.virtiofsd != "" {
		elfs = append(elfs, [2]string{"virtiofsd", e.virtiofsd})
		vb, err := os.ReadFile(e.virtiofsd)
		must(t, err)
		sum := sha256.Sum256(vb)
		t.Logf("fcch sha256 virtiofsd=%x virtiofsd_prebuilt=none", sum)
	}
	for _, b := range elfs {
		interp, needed := elfFacts(t, b[1])
		t.Logf("fcch elf %s interp=%s needed=%s", b[0], interp, needed)
	}
	t.Logf("fcch versions fc=%s ch=%s virtiofsd=%s", versions["fc"], versions["ch"], versions["virtiofsd"])

	// "go test ./spikes/..." runs libkrun.test beside this one; its cargo build would perturb the samples.
	phase = time.Now()
	for time.Since(phase) < 240*time.Second &&
		len(scanProc("comm", func(s string) bool { return strings.TrimSpace(s) == "libkrun.test" })) > 0 {
		time.Sleep(time.Second)
	}
	waitedS := time.Since(phase).Seconds()

	t.Run("fc", func(t *testing.T) { e.measure(t, vFC) })
	t.Run("ch-blk", func(t *testing.T) { e.measure(t, vCHBlk) })
	t.Run("ch-fs", func(t *testing.T) {
		if e.virtiofsd == "" {
			t.Log("fcch ch-fs virtiofsd=unavailable")
			t.Skip("virtiofsd=unavailable")
		}
		e.measure(t, vCHFS)
	})
	for _, v := range []variant{vFCkB, vCHBlkkB} {
		t.Run(v.name, func(t *testing.T) { // extras: a failure is logged, never fatal
			r, err := e.boot(t, v, false)
			if err != nil {
				t.Logf("fcch cross variant=%s fail: %v", v.name, err)
				return
			}
			t.Logf("fcch cross variant=%s ok boot_ms=%d total_ms=%d", v.name, r.bootMS, r.totalMS)
		})
	}
	t.Logf("fcch facts vcpus=%d mem_mib=%d download_s=%.1f gobuild_s=%.1f waited_for_libkrun_s=%.1f test_s=%.1f",
		vcpus, memMiB, downloadS, gobuildS, waitedS, time.Since(start).Seconds())
}

// measure runs one warm-up boot and the timed samples. A failed boot fails
// this subtest (its diagnostics are already logged) and nothing else.
func (e *env) measure(t *testing.T, v variant) {
	if _, err := e.boot(t, v, false); err != nil {
		t.Fatalf("%s warm-up: %v", v.name, err)
	}
	var boots, totals, tds []int64
	var last result
	for i := range samples {
		r, err := e.boot(t, v, false)
		if err != nil {
			t.Fatalf("%s sample %d: %v", v.name, i, err)
		}
		t.Logf("fcch sample=%d variant=%s boot_ms=%d total_ms=%d teardown_ms=%d", i, v.name, r.bootMS, r.totalMS, r.tdMS)
		boots, totals, tds, last = append(boots, r.bootMS), append(totals, r.totalMS), append(tds, r.tdMS), r
	}
	t.Logf("fcch %s boot_ms %s", v.name, stats(boots))
	t.Logf("fcch %s total_ms %s", v.name, stats(totals))
	t.Logf("fcch %s teardown_ms %s", v.name, stats(tds))
	kernel := map[string]string{"A": "A:vmlinux-6.1.155", "B": "B:ch-release-v7.2.8-20261009"}[v.kernel]
	t.Logf("fcch %s facts loopback=%s ifaces=%s env_leak=%s guest_exit=%s vmm_exit=%d exit_path=%q share=%s kernel=%s api_ms=%d virtiofsd_ready_ms=%d virtiofsd_exit_ms=%d cmdline=%q leftover=%q",
		v.name, last.kv["loopback"], last.kv["ifaces"], last.kv["env_leak"], last.kv["exit"], last.vmmExit, last.exitPath,
		v.share, kernel, last.apiMS, last.vfsReadyMS, last.vfsExitMS, last.kv["cmdline"], last.leftover)
	r, err := e.boot(t, v, true)
	if err != nil {
		t.Logf("fcch kill %s fail: %v", v.name, err)
		return
	}
	t.Logf("fcch kill %s kill_ms=%d orphans=%d virtiofsd_exit_after_kill_ms=%d", v.name, r.killMS, r.orphans, r.vfsExitMS)
}

// proc is a child process. Its stderr is read only after done is closed.
type proc struct {
	name   string
	cmd    *exec.Cmd
	stderr bytes.Buffer
	done   chan struct{}
	end    time.Time
	code   int
}

// start runs bin with the canary in its environment (the guest must never see it).
func (e *env) start(name, bin string, stdout *os.File, args ...string) (*proc, error) {
	p := &proc{name: name, done: make(chan struct{})}
	p.cmd = exec.Command(bin, args...)
	p.cmd.Env = append(os.Environ(), "FCCH_CANARY="+e.canary)
	if stdout != nil {
		p.cmd.Stdout = stdout
	}
	p.cmd.Stderr = &p.stderr
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		_ = p.cmd.Wait()
		p.end, p.code = time.Now(), -1
		if p.cmd.ProcessState != nil {
			p.code = p.cmd.ProcessState.ExitCode()
		}
		close(p.done)
	}()
	return p, nil
}

func (p *proc) kill() {
	if p != nil {
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

func (p *proc) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// vm is one booted VMM and its helper.
type vm struct {
	vmm, vfs          *proc
	startT            time.Time
	apiMS, vfsReadyMS int64
}

// dump logs everything a reader of the CI log needs, then stops what is left.
func dump(t *testing.T, m *vm, console string) {
	t.Helper()
	if m != nil {
		for _, p := range []*proc{m.vfs, m.vmm} {
			if p == nil {
				continue
			}
			state := "exited"
			if p.running() {
				state = "still running, killed by the test"
				p.kill()
			}
			t.Logf("fcch diag %s %s exit=%d stderr:\n%s", p.name, state, p.code, tail(p.stderr.String(), 20))
		}
	}
	b, _ := os.ReadFile(console)
	t.Logf("fcch diag console:\n%s", tail(string(b), 40))
}

type echo struct {
	line        string
	first, done time.Time
	err         error
}

// exchange accepts the guest's vsock connection, times the first byte, echoes
// the first line (closing sent once it is written) and waits for EOF.
func exchange(ln *net.UnixListener, sent chan<- struct{}) <-chan echo {
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
		close(sent)
		_, e.err = io.Copy(io.Discard, br)
		e.done = time.Now()
	}()
	return got
}

// boot runs one VM to completion (or, with kill, to SIGKILL right after the
// echo) and measures it. On error the diagnostics are already logged.
func (e *env) boot(t *testing.T, v variant, kill bool) (r result, err error) {
	t.Helper()
	runtime.LockOSThread() // Pdeathsig is tied to the thread that started the child
	defer runtime.UnlockOSThread()
	e.seq++
	dir := filepath.Join(e.tmp, "b"+strconv.Itoa(e.seq))
	console := filepath.Join(dir, "console.txt")
	var m *vm
	defer func() {
		if err != nil {
			dump(t, m, console)
		}
		_ = os.RemoveAll(dir)
	}()
	token := rand.Text()
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return r, err
	}
	if v.share == "blk" {
		img := make([]byte, 4<<20)
		copy(img, token+" "+e.probe+"\n")
		err = os.WriteFile(filepath.Join(dir, "share.img"), img, 0o644)
	} else {
		w := filepath.Join(dir, "work")
		err = errors.Join(os.Mkdir(w, 0o755),
			os.WriteFile(filepath.Join(w, "from-host.txt"), []byte(token+"\n"), 0o644),
			os.WriteFile(filepath.Join(w, "probe.txt"), []byte(e.probe+"\n"), 0o644))
	}
	if err != nil {
		return r, err
	}
	// Both VMMs dial "<their vsock socket>_<port>" when the guest connects.
	sock := filepath.Join(dir, map[string]string{"fc": "v.sock", "ch": "ch.vsock"}[v.vmm]+"_5000")
	if len(sock) > 100 {
		return r, fmt.Errorf("socket path too long for sun_path: %s", sock)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return r, err
	}
	defer ln.Close()
	sent := make(chan struct{})
	got := exchange(ln, sent)

	t0 := time.Now()
	if v.vmm == "fc" {
		m, err = e.launchFC(t0, v, dir, console)
	} else {
		m, err = e.launchCH(t0, v, dir, console)
	}
	if err != nil {
		_ = ln.Close()
		<-got
		return r, err
	}
	timer := time.NewTimer(bootLimit)
	defer timer.Stop()

	if kill { // A9: SIGKILL on the VMM leaves nothing behind
		select {
		case <-sent:
		case <-m.vmm.done:
		case <-timer.C:
			return r, fmt.Errorf("no exchange within %v before the kill", bootLimit)
		}
		tk := time.Now()
		m.vmm.kill()
		r.killMS = m.vmm.end.Sub(tk).Milliseconds()
		r.vfsExitMS = m.reapHelper(tk)
		r.orphans = len(scanProc("cmdline", func(s string) bool { return strings.Contains(s, dir+"/") }))
		select {
		case <-got:
		case <-time.After(5 * time.Second):
		}
		return r, nil
	}

	var x echo
	select {
	case x = <-got:
	case <-m.vmm.done:
		_ = ln.Close()
		x = <-got
	case <-timer.C:
		return r, fmt.Errorf("no exchange within %v", bootLimit)
	}
	r.exitPath = map[string]string{"fc": "reboot", "ch": "poweroff"}[v.vmm]
	select {
	case <-m.vmm.done:
		r.tdMS = m.vmm.end.Sub(x.done).Milliseconds()
	case <-time.After(exitLimit):
		m.vmm.kill()
		r.tdMS, r.exitPath = -1, r.exitPath+" hang"
	}
	r.vmmExit = m.vmm.code
	r.vfsExitMS = m.reapHelper(m.vmm.end)
	if x.err != nil {
		return r, fmt.Errorf("vsock exchange: %v (VMM exit %d)", x.err, m.vmm.code)
	}
	left, _ := os.ReadDir(dir)
	for _, f := range left {
		r.leftover += f.Name() + ","
	}
	r.leftover = strings.TrimSuffix(r.leftover, ",")
	var back []byte
	if v.share == "blk" {
		img, err := os.ReadFile(filepath.Join(dir, "share.img"))
		if err != nil || len(img) < 4096+2048 {
			return r, fmt.Errorf("share image unreadable: %v", err)
		}
		back = img[4096 : 4096+2048]
	} else if back, err = os.ReadFile(filepath.Join(dir, "work", "from-guest.txt")); err != nil {
		return r, fmt.Errorf("guest wrote nothing back: %w", err)
	}
	line := strings.TrimSpace(x.line)
	gotToken, kv := parseHello(line)
	if gotToken != token || strings.TrimSpace(string(bytes.TrimRight(back, "\x00"))) != line {
		return r, fmt.Errorf("guest sent %q and wrote back %q, want token %s", line, bytes.TrimRight(back, "\x00"), token)
	}
	r.kv = kv
	r.apiMS, r.vfsReadyMS = m.apiMS, m.vfsReadyMS
	r.bootMS = x.first.Sub(m.startT).Milliseconds()
	r.totalMS = x.first.Sub(t0).Milliseconds()
	return r, nil
}

// reapHelper waits up to 5 s for virtiofsd to follow its VMM and returns how
// long after ref it exited: -1 if there is no helper, -2 if it had to be killed.
func (m *vm) reapHelper(ref time.Time) int64 {
	if m.vfs == nil {
		return -1
	}
	select {
	case <-m.vfs.done:
		return m.vfs.end.Sub(ref).Milliseconds()
	case <-time.After(5 * time.Second):
		m.vfs.kill()
		return -2
	}
}

// waitFor polls ok every millisecond until limit, or until dead is closed.
func waitFor(ok func() bool, limit time.Duration, dead <-chan struct{}) error {
	for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(time.Millisecond) {
		select {
		case <-dead:
			return errors.New("process exited")
		default:
		}
		if ok() {
			return nil
		}
	}
	return fmt.Errorf("not ready within %v", limit)
}

// launchFC starts Firecracker (no jailer, default seccomp, MMIO devices) and
// configures it over its API socket. startT is the instant before InstanceStart.
func (e *env) launchFC(t0 time.Time, v variant, dir, console string) (*vm, error) {
	m := &vm{apiMS: -1, vfsReadyMS: -1}
	out, err := os.Create(console) // the serial port is Firecracker's stdout
	if err != nil {
		return m, err
	}
	sock := filepath.Join(dir, "fc.api")
	m.vmm, err = e.start("firecracker", e.fc, out, append([]string{"--api-sock", sock}, fcExtraArgs...)...)
	_ = out.Close()
	if err != nil {
		return m, err
	}
	dial := func() bool {
		c, err := net.Dial("unix", sock)
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}
	if err := waitFor(dial, 5*time.Second, m.vmm.done); err != nil {
		return m, fmt.Errorf("API socket: %w", err)
	}
	cli := newAPI(sock)
	steps := []struct {
		path string
		body any
	}{
		{"/machine-config", map[string]any{"vcpu_count": vcpus, "mem_size_mib": memMiB, "smt": false}},
		{"/boot-source", map[string]any{"kernel_image_path": e.kernel(v), "initrd_path": e.initrd,
			"boot_args": "console=ttyS0 reboot=k panic=-1 pci=off quiet wcexit=reboot wcshare=blk"}},
		{"/drives/share", map[string]any{"drive_id": "share", "path_on_host": filepath.Join(dir, "share.img"),
			"is_root_device": false, "is_read_only": false}},
		{"/vsock", map[string]any{"guest_cid": 3, "uds_path": filepath.Join(dir, "v.sock")}},
	}
	for i, s := range steps {
		if err := cli.put(s.path, s.body); err != nil {
			return m, err
		}
		if i == 0 {
			m.apiMS = time.Since(t0).Milliseconds()
		}
	}
	m.startT = time.Now()
	return m, cli.put("/actions", map[string]string{"action_type": "InstanceStart"})
}

func (e *env) kernel(v variant) string {
	if v.kernel == "B" {
		return e.kernelB
	}
	return e.kernelA
}
