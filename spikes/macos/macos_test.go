// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64

package macos

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Upstream inputs, pinned by the digest of the bytes this spike first downloaded.
// Fallbacks are in notes.md.
const (
	kernelAURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155"
	kernelASHA = "61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be"
	kernelBURL = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/Image-arm64"
	kernelBSHA = "8f8f3d5a983809f87a4e1e9a13053a3361fda47ef04e09c771a41c5e037cb6c2"
	// Kernel C is not downloaded here: it is the one "container system start
	// --enable-kernel-install" puts in place (Kata 3.32.0), used if B cannot boot.
	kernelCPath = "Library/Application Support/com.apple.container/kernels/vmlinux-6.18.35-197-debug"
	kernelCSHA  = "fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d"

	module    = "github.com/omkhar/workcell/v2/spikes/macos/cmd/"
	helper    = "com.apple.Virtualization.VirtualMachine" // the XPC service that runs each VZ VM
	vcpus     = 2
	memMiB    = 1024
	samples   = 20
	bootLimit = 90 * time.Second // vzchild gives up by itself after 60 s plus 10 s
	allRows   = 8 * time.Minute  // past this, the remaining rows are skipped
)

type variant struct{ name, kernel, share string }

var (
	vBlk    = variant{"vz-blk", "A", "blk"}
	vFS     = variant{"vz-fs", "B", "fs"}
	vBlkKB  = variant{"vz-blk-kB", "B", "blk"}
	vFSKC   = variant{"vz-fs-kC", "C", "fs"}
	kernels = map[string]string{"A": "A:vmlinux-6.1.155", "B": "B:ch-release-v7.2.8-20261009", "C": "C:kata-3.32.0-vmlinux-6.18.35-197-debug"}
)

type env struct {
	tmp, child, initrd, guest string
	kernel                    map[string]string
	probe, canary             string
	seq                       int
}

type result struct {
	kv, child             map[string]string // what the guest sent; what vzchild printed
	bootMS, totalMS, tdMS int64
	vmmExit               int
	leftover, helpers     string
	killMS                int64
	orphans               int
	method, heldBy        string
}

func TestMacOS(t *testing.T) {
	hv, _ := run(10*time.Second, "sysctl", "-n", "kern.hv_support")
	if strings.TrimSpace(hv) != "1" {
		t.Skipf("kern.hv_support=%q: no hypervisor here", strings.TrimSpace(hv))
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skipf("codesign is missing: %v", err)
	}
	start := time.Now()
	tmp := t.TempDir()
	if len(tmp) > 80 { // boot paths stay under 100 bytes (sun_path is 104 on macOS)
		var err error
		tmp, err = os.MkdirTemp("/tmp", "wc-")
		must(t, err)
		defer os.RemoveAll(tmp)
	}
	e := &env{tmp: tmp, canary: "canary-" + rand.Text(), kernel: map[string]string{}}

	phase := time.Now()
	var kA, kB string
	var errA, errB error
	var wg sync.WaitGroup
	wg.Go(func() { kA, errA = cached(t, kernelAURL, "vmlinux-6.1.155-aarch64", kernelASHA) })
	wg.Go(func() { kB, errB = cached(t, kernelBURL, "Image-arm64-ch-release-v7.2.8-20261009", kernelBSHA) })
	wg.Wait()
	must(t, errors.Join(errA, errB))
	e.kernel["A"], e.kernel["B"] = kA, kB
	downloadS := time.Since(phase).Seconds()
	okA, okB := magic(kA), magic(kB)
	t.Logf("macos kernel_a_magic=%t kernel_b_magic=%t", okA, okB)
	if !okA {
		t.Log("macos kernel A is not an arm64 Image: every row runs on kernel B")
		vBlk.kernel = "B"
	}

	phase = time.Now()
	e.guest = filepath.Join(tmp, "guest")
	hello, unsigned := filepath.Join(tmp, "hello-nocgo"), filepath.Join(tmp, "vzchild-unsigned")
	e.child = filepath.Join(tmp, "vzchild")
	goBuild(t, e.guest, "guest", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	goBuild(t, hello, "guest", "CGO_ENABLED=0") // on darwin the guest is an empty main
	goBuild(t, unsigned, "vzchild", "CGO_ENABLED=1")
	guestBytes, err := os.ReadFile(e.guest)
	must(t, err)
	e.initrd = filepath.Join(tmp, "initramfs.cpio")
	must(t, os.WriteFile(e.initrd, initramfs(guestBytes), 0o644))
	b, err := os.ReadFile(unsigned)
	must(t, err)
	must(t, os.WriteFile(e.child, b, 0o755)) // a fresh file: re-signing one that has run can get it killed
	if out, err := run(time.Minute, "codesign", "-s", "-", "-f", "--entitlements", "vz.entitlements", e.child); err != nil {
		t.Fatalf("codesign: %v\n%s", err, out)
	}
	gobuildS := time.Since(phase).Seconds()

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

	// Unsigned (the Go linker's ad hoc signature, no entitlements), then signed.
	dir := filepath.Join(tmp, "unsigned")
	_, err = e.prepare(dir, "blk")
	must(t, err)
	out, _ := run(time.Minute, unsigned, e.args(vBlk, dir, false)...)
	kv := childKV(out)
	unsignedErr, _ := strconv.Unquote(kv["validate_err"] + kv["start_err"])
	if unsignedErr, _, _ = strings.Cut(unsignedErr, " UserInfo="); unsignedErr == "" {
		unsignedErr = "none: " + firstLine(out)
	}
	must(t, os.RemoveAll(dir))
	ent, _ := run(time.Minute, "codesign", "-d", "--entitlements", "-", e.child)
	t.Logf("macos sign vzchild entitlements=%s unsigned_err=%q unsigned_sig=%q signed_sig=%q",
		entitlements(ent), unsignedErr, signature(unsigned), signature(e.child))
	if r, err := e.boot(t, vBlk, false); err != nil && (r.child["validate_err"] != "" || r.child["start_err"] != "") {
		t.Skipf("signed vzchild cannot start a VM: %v", err)
	}

	cli, cliMachO, runtimeBin := containerBins()
	bins := [][2]string{{"hello_nocgo", hello}, {"vzchild", e.child}, {"guest", e.guest},
		{"container", cliMachO}, {"container-runtime-linux", runtimeBin}}
	var sizes []string
	for _, b := range bins {
		sizes = append(sizes, fmt.Sprintf("%s_bytes=%d", b[0], size(b[1])))
		if b[1] == "" {
			continue
		}
		all, foreign := links(b[1])
		t.Logf("macos links %s=%s %s_foreign=%s", b[0], all, b[0], foreign)
	}
	t.Logf("macos size %s initramfs_bytes=%d kernel_a_bytes=%d kernel_b_bytes=%d",
		strings.Join(sizes, " "), size(e.initrd), size(kA), size(kB))

	rows := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{vBlk.name, func(t *testing.T) { e.measure(t, vBlk, true) }},
		{vFS.name, func(t *testing.T) { e.measure(t, vFS, false) }},
		{vBlkKB.name, func(t *testing.T) {
			r, err := e.boot(t, vBlkKB, false)
			if err != nil {
				t.Logf("macos cross variant=%s fail: %v", vBlkKB.name, err)
				return
			}
			t.Logf("macos cross variant=%s ok boot_ms=%d total_ms=%d", vBlkKB.name, r.bootMS, r.totalMS)
		}},
		{"container", func(t *testing.T) { e.container(t, cli, cliMachO, runtimeBin) }},
		{vFSKC.name, func(t *testing.T) {
			home, _ := os.UserHomeDir()
			kC := filepath.Join(home, kernelCPath)
			sum, err := sha256File(kC)
			t.Logf("macos sha256 kernel-c=%s pinned_match=%t bytes=%d magic=%t", sum, sum == kernelCSHA, size(kC), magic(kC))
			if err != nil {
				t.Logf("macos %s fail: %v", vFSKC.name, err)
				return
			}
			e.kernel["C"] = kC
			e.measure(t, vFSKC, false)
		}},
		{"krun-blk", e.krunRow},
		{"vfkit-blk", e.vfkitRow},
	}
	for _, row := range rows {
		if time.Since(start) > allRows {
			t.Logf("macos %s skipped: the test has run %v, past %v", row.name, time.Since(start).Round(time.Second), allRows)
			continue
		}
		t.Run(row.name, row.fn)
	}
	sw, _ := run(10*time.Second, "sw_vers", "-productVersion")
	chip, _ := run(10*time.Second, "sysctl", "-n", "machdep.cpu.brand_string")
	gov, _ := run(10*time.Second, "go", "version")
	clang, _ := run(10*time.Second, "clang", "--version")
	sdk, _ := run(10*time.Second, "xcrun", "--show-sdk-version")
	vz, _ := run(time.Minute, "go", "list", "-m", "-f", "{{.Version}}", "github.com/Code-Hex/vz/v3")
	t.Logf("macos facts vcpus=%d mem_mib=%d macos=%s chip=%s go=%s clang=%s sdk=%s vz=%s download_s=%.1f gobuild_s=%.1f test_s=%.1f",
		vcpus, memMiB, firstLine(sw), firstLine(chip), firstLine(gov), firstLine(clang), firstLine(sdk), firstLine(vz),
		downloadS, gobuildS, time.Since(start).Seconds())
}

// magic reports whether the file starts like an arm64 Linux Image.
func magic(path string) bool {
	b := make([]byte, 64)
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	_, _ = f.Read(b)
	return isImage(b)
}

// fail stops the row if it is fatal, and only logs otherwise.
func fail(t *testing.T, fatal bool, format string, a ...any) {
	t.Helper()
	if fatal {
		t.Fatalf(format, a...)
	}
	t.Logf("macos fail "+format, a...)
}

// measure runs one warm-up boot, the timed samples and the SIGKILL boot.
func (e *env) measure(t *testing.T, v variant, fatal bool) {
	if _, err := e.boot(t, v, false); err != nil {
		fail(t, fatal, "%s warm-up: %v", v.name, err)
		return
	}
	var boots, totals, tds []int64
	var last result
	for i := range samples {
		r, err := e.boot(t, v, false)
		if err != nil {
			fail(t, fatal, "%s sample %d: %v", v.name, i, err)
			return
		}
		t.Logf("macos sample=%d variant=%s boot_ms=%d total_ms=%d teardown_ms=%d", i, v.name, r.bootMS, r.totalMS, r.tdMS)
		boots, totals, tds, last = append(boots, r.bootMS), append(totals, r.totalMS), append(tds, r.tdMS), r
	}
	t.Logf("macos %s boot_ms %s", v.name, stats(boots))
	t.Logf("macos %s total_ms %s", v.name, stats(totals))
	t.Logf("macos %s teardown_ms %s", v.name, stats(tds))
	kernel := kernels[v.kernel]
	t.Logf("macos %s facts loopback=%s ifaces=%s gateway=%s env_leak=%s guest_exit=%s vmm_exit=%d exit_path=%s share=%s kernel=%s listen=%s entropy=none cmdline=%q leftover=%q helper_procs=%s",
		v.name, last.kv["loopback"], last.kv["ifaces"], last.kv["gateway"], last.kv["env_leak"], last.kv["exit"], last.vmmExit,
		last.child["exit_path"], v.share, kernel, last.child["listen"], last.kv["cmdline"], last.leftover, last.helpers)
	r, err := e.boot(t, v, true)
	if err != nil {
		t.Logf("macos kill %s fail: %v", v.name, err)
		return
	}
	t.Logf("macos kill %s kill_ms=%d orphans=%d method=%s held_by=%s", v.name, r.killMS, r.orphans, r.method, strings.TrimSuffix(r.heldBy, ","))
}

// prepare writes the share: a raw image with "<token> <probe>" at offset 0,
// or a directory with from-host.txt and probe.txt.
func (e *env) prepare(dir, share string) (string, error) {
	token := rand.Text()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if share == "blk" {
		img := make([]byte, 4<<20)
		copy(img, token+" "+e.probe+"\n")
		return token, os.WriteFile(filepath.Join(dir, "share.img"), img, 0o644)
	}
	w := filepath.Join(dir, "work")
	return token, errors.Join(os.Mkdir(w, 0o755),
		os.WriteFile(filepath.Join(w, "from-host.txt"), []byte(token+"\n"), 0o644),
		os.WriteFile(filepath.Join(w, "probe.txt"), []byte(e.probe+"\n"), 0o644))
}

func (e *env) args(v variant, dir string, noecho bool) []string {
	a := []string{"-kernel", e.kernel[v.kernel], "-initrd", e.initrd, "-console", filepath.Join(dir, "console.txt"),
		"-cmdline", "console=hvc0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=" + v.share,
		"-cpus", strconv.Itoa(vcpus), "-mem", strconv.Itoa(memMiB), "-noecho=" + strconv.FormatBool(noecho)}
	if v.share == "blk" {
		return append(a, "-img", filepath.Join(dir, "share.img"))
	}
	return append(a, "-share", filepath.Join(dir, "work"))
}

// boot runs one VM through vzchild to completion (or, with kill, to SIGKILL
// once the guest's first byte has arrived) and measures it.
func (e *env) boot(t *testing.T, v variant, kill bool) (r result, err error) {
	t.Helper()
	e.seq++
	dir := filepath.Join(e.tmp, "b"+strconv.Itoa(e.seq))
	var stderr bytes.Buffer
	var out strings.Builder
	defer func() {
		if err != nil {
			con, _ := os.ReadFile(filepath.Join(dir, "console.txt"))
			t.Logf("macos diag %s stdout:\n%s\nstderr:\n%s\nconsole:\n%s", v.name, tail(out.String(), 20),
				tail(stderr.String(), 20), tail(string(con), 40))
		}
		_ = os.RemoveAll(dir)
	}()
	token, err := e.prepare(dir, v.share)
	if err != nil {
		return r, err
	}
	held := filepath.Join(dir, "share.img")
	if v.share == "fs" {
		held = filepath.Join(dir, "work")
	}
	baseline := count(helper)
	cmd := exec.Command(e.child, e.args(v, dir, kill)...)
	cmd.Env = append(os.Environ(), "WC_CANARY="+e.canary)
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // no Pdeathsig on darwin: kill the group
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return r, err
	}
	t0 := time.Now()
	if err = cmd.Start(); err != nil {
		return r, err
	}
	first, exited := make(chan struct{}), make(chan time.Time, 1)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			out.WriteString(sc.Text() + "\n")
			if strings.HasPrefix(sc.Text(), "line=") {
				close(first)
			}
		}
		_ = cmd.Wait()
		exited <- time.Now()
	}()
	killGroup := func() time.Time {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return <-exited
	}
	timer := time.NewTimer(bootLimit)
	defer timer.Stop()

	if kill { // A9: what is left 2 s after SIGKILL on the process that owns the VM
		select {
		case <-first:
		case <-exited:
			return r, errors.New("vzchild exited before the guest's first line")
		case <-timer.C:
			killGroup()
			return r, fmt.Errorf("no first line within %v", bootLimit)
		}
		ours := slices.DeleteFunc(holders(held), func(p string) bool { return p == strconv.Itoa(cmd.Process.Pid) })
		for _, p := range procs() {
			if f := strings.Fields(p); slices.Contains(ours, f[0]) {
				r.heldBy += filepath.Base(f[len(f)-1]) + ":ppid=" + f[1] + ","
			}
		}
		tk := time.Now()
		r.killMS = killGroup().Sub(tk).Milliseconds()
		time.Sleep(2 * time.Second)
		if len(ours) > 0 {
			left := holders(held)
			r.method, r.orphans = "lsof", len(left)
			for _, p := range left { // the helper that ran our VM, found by our own file
				if n, err := strconv.Atoi(p); err == nil && slices.Contains(ours, p) {
					_ = syscall.Kill(n, syscall.SIGKILL)
				}
			}
		} else {
			r.method, r.orphans = "count", count(helper)-baseline
		}
		return r, nil
	}

	var end time.Time
	select {
	case end = <-exited:
	case <-timer.C:
		killGroup()
		return r, fmt.Errorf("vzchild still running after %v", bootLimit)
	}
	r.child, r.vmmExit = childKV(out.String()), cmd.ProcessState.ExitCode()
	r.helpers = fmt.Sprintf("%d->%d", baseline, count(helper))
	for _, k := range []string{"validate_err", "listen_err", "start_err", "exchange_err"} {
		if r.child[k] != "" {
			return r, fmt.Errorf("vzchild %s=%s (exit %d)", k, r.child[k], r.vmmExit)
		}
	}
	left, _ := os.ReadDir(dir)
	var names []string
	for _, f := range left {
		names = append(names, f.Name())
	}
	r.leftover = strings.Join(names, ",")
	var back []byte
	if v.share == "blk" {
		img, err := os.ReadFile(held)
		if err != nil || len(img) < 4096+2048 {
			return r, fmt.Errorf("share image unreadable: %v", err)
		}
		back = img[4096 : 4096+2048]
	} else if back, err = os.ReadFile(filepath.Join(held, "from-guest.txt")); err != nil {
		return r, fmt.Errorf("guest wrote nothing back: %w", err)
	}
	line := strings.TrimSpace(r.child["line"])
	gotToken, kv := parseHello(line)
	if gotToken != token || strings.TrimSpace(string(bytes.TrimRight(back, "\x00"))) != line {
		return r, fmt.Errorf("guest sent %q and wrote back %q, want token %s", line, bytes.TrimRight(back, "\x00"), token)
	}
	r.kv = kv
	startNS, firstNS, eofNS := unixNS(r.child, "start"), unixNS(r.child, "first"), unixNS(r.child, "eof")
	r.bootMS = (firstNS - startNS) / 1e6
	r.totalMS = (firstNS - t0.UnixNano()) / 1e6
	r.tdMS = (end.UnixNano() - eofNS) / 1e6
	return r, nil
}
