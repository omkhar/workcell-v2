// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64

package macos

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
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

// Images for the container row, pinned by the index digest of the first pull.
var images = []string{
	"docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec", // 1.37
	"docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f",  // 3.22, fallback
}

// containerBins finds the container CLI on PATH, the Mach-O behind it (a
// Homebrew install puts a bash wrapper on PATH) and the Linux runtime plugin.
func containerBins() (cli, macho, runtime string) {
	cli, err := exec.LookPath("container")
	if err != nil {
		return "", "", ""
	}
	real, err := filepath.EvalSymlinks(cli)
	if err != nil {
		return cli, "", ""
	}
	root := filepath.Dir(filepath.Dir(real))
	first := func(paths ...string) string {
		for _, p := range paths {
			if b, err := os.ReadFile(p); err == nil && len(b) > 4 && string(b[:2]) != "#!" {
				return p
			}
		}
		return ""
	}
	plugin := "container-runtime-linux/bin/container-runtime-linux"
	return cli, first(filepath.Join(root, "libexec/container"), real),
		first(filepath.Join(root, "libexec/container-plugins", plugin), filepath.Join(root, "libexec/container/plugins", plugin))
}

type crun struct {
	line                  string
	bootMS, totalMS, tdMS int64
	exit                  int
}

// container measures Apple's container CLI: one VM per container, driven by
// exec of the CLI, which talks XPC to a launchd agent. Failures only log.
func (e *env) container(t *testing.T, cli, macho, runtimeBin string) {
	if cli == "" {
		t.Log("macos container fail: no container CLI on PATH")
		return
	}
	ver, _ := run(30*time.Second, cli, "--version")
	status, err := run(30*time.Second, cli, "system", "status")
	wasRunning := err == nil && !strings.Contains(status, "not running")
	startedByTest, startS := false, 0.0
	if !wasRunning {
		phase := time.Now()
		out, err := run(5*time.Minute, cli, "system", "start", "--enable-kernel-install")
		startS, startedByTest = time.Since(phase).Seconds(), true
		defer func() {
			out, err := run(2*time.Minute, cli, "system", "stop")
			t.Logf("macos container system_stop err=%v out=%q", err, tail(out, 3))
		}()
		if err != nil {
			t.Logf("macos container fail: system start: %v\n%s", err, tail(out, 20))
			return
		}
	}
	uid := strconv.Itoa(os.Getuid())
	launchd := "none"
	for _, domain := range []string{"gui/", "user/"} {
		out, err := run(10*time.Second, "launchctl", "print", domain+uid+"/com.apple.container.apiserver")
		launchd += fmt.Sprintf(" %s:err=%v,first=%s", domain, err, firstLine(out))
	}
	t.Logf("macos container launchctl%s", strings.TrimPrefix(launchd, "none"))
	home, _ := os.UserHomeDir()
	kernel, _ := filepath.EvalSymlinks(filepath.Join(home, "Library/Application Support/com.apple.container/kernels/default.kernel-arm64"))
	ksum, _ := sha256File(kernel)
	// Apple's own pkg, if it is installed beside the one on PATH, shows how Apple signs it.
	pkg := "/usr/local/libexec/container/plugins/container-runtime-linux/bin/container-runtime-linux"
	for _, b := range [][2]string{{"container", macho}, {"container-runtime-linux", runtimeBin},
		{"pkg-container", "/usr/local/bin/container"}, {"pkg-container-runtime-linux", pkg}} {
		if size(b[1]) <= 0 || (strings.HasPrefix(b[0], "pkg-") && (b[1] == macho || b[1] == runtimeBin)) {
			continue
		}
		ent, _ := run(time.Minute, "codesign", "-d", "--entitlements", "-", b[1])
		t.Logf("macos sign %s entitlements=%s sig=%q", b[0], entitlements(ent), signature(b[1]))
	}

	image := ""
	for _, img := range images {
		out, err := run(5*time.Minute, cli, "image", "pull", img)
		t.Logf("macos container pull image=%s err=%v", img, err)
		if err == nil {
			image = img
			break
		}
		t.Logf("macos container pull output:\n%s", tail(out, 10))
	}
	dir := filepath.Join(e.tmp, "ctr")
	b, err := os.ReadFile(e.guest)
	if image == "" || err != nil || os.MkdirAll(dir, 0o755) != nil || os.WriteFile(filepath.Join(dir, "guest"), b, 0o755) != nil {
		t.Logf("macos container fail: image=%q guest=%v", image, err)
		return
	}
	defer os.RemoveAll(dir)

	if _, err := e.crun(cli, image, dir, "", nil); err != nil {
		t.Logf("macos container fail: warm-up: %v", err)
		return
	}
	var boots, totals, tds []int64
	var last crun
	for i := range samples {
		r, err := e.crun(cli, image, dir, "", nil)
		if err != nil {
			t.Logf("macos container fail: sample %d: %v", i, err)
			return
		}
		t.Logf("macos sample=%d variant=container boot_ms=%d total_ms=%d teardown_ms=%d", i, r.bootMS, r.totalMS, r.tdMS)
		boots, totals, tds, last = append(boots, r.bootMS), append(totals, r.totalMS), append(tds, r.tdMS), r
	}
	t.Logf("macos container boot_ms %s", stats(boots))
	t.Logf("macos container total_ms %s", stats(totals))
	t.Logf("macos container teardown_ms %s (upper bound: CLI exit minus first stdout byte)", stats(tds))
	ls, _ := run(30*time.Second, cli, "ls", "-a", "--format", "json")
	_, kv := parseHello(last.line)
	t.Logf("macos container facts loopback=%s ifaces=%s gateway=%s env_leak=%s guest_exit=%s vmm_exit=%d exit_path=cli share=bind-virtiofs kernel=%s cmdline=%q leftover=%q helper_procs=%d",
		kv["loopback"], kv["ifaces"], kv["gateway"], kv["env_leak"], kv["exit"], last.exit, filepath.Base(kernel),
		kv["cmdline"], "ls_a="+strings.TrimSpace(ls), count(helper))

	// The SIGKILL boot: a named container that sleeps 30 s after its line.
	name := "wc-" + strings.ToLower(rand.Text()[:10])
	baseline := count("container-runtime-linux") + count(helper)
	var processes string
	var killMS int64
	_, err = e.crun(cli, image, dir, name, func(cmd *exec.Cmd) {
		var seen []string
		for _, p := range procs() {
			f := strings.Fields(p)
			base := filepath.Base(f[len(f)-1])
			if strings.HasPrefix(base, "container-") || base == "machine-apiserver" || base == helper {
				seen = append(seen, base+":ppid="+f[1])
			}
		}
		slices.Sort(seen)
		processes = strings.Join(seen, ",")
		tk := time.Now()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		killMS = time.Since(tk).Milliseconds()
	})
	if err != nil {
		t.Logf("macos kill container fail: %v", err)
	}
	time.Sleep(2 * time.Second)
	out, _ := run(30*time.Second, cli, "ls", "-a", "--format", "json")
	afterKill, err := containerState([]byte(out), name)
	if err != nil {
		afterKill = "unknown:" + firstLine(out)
	}
	orphans := count("container-runtime-linux") + count(helper) - baseline
	phase := time.Now()
	rmOut, rmErr := run(time.Minute, cli, "rm", "-f", name)
	rmMS := time.Since(phase).Milliseconds()
	t.Logf("macos kill container kill_ms=%d orphans=%d method=count", killMS, orphans)
	t.Logf("macos container version=%s kernel_bytes=%d kernel_sha256=%s image=%s apiserver_was_running=%t started_by_test=%t system_start_s=%.1f processes=%s cli_exit=%d after_kill=%s rm_ms=%d rm_err=%v rm_out=%q",
		firstLine(ver), size(kernel), ksum, image, wasRunning, startedByTest, startS, processes, last.exit, afterKill, rmMS, rmErr, firstLine(rmOut))
}

// crun runs the guest's probe mode in one container. With kill, it names the
// container, makes the guest sleep 30 s and hands the CLI to kill after the first byte.
func (e *env) crun(cli, image, dir, name string, kill func(*exec.Cmd)) (r crun, err error) {
	args := []string{"run", "--rm", "--cpus", strconv.Itoa(vcpus), "--memory", strconv.Itoa(memMiB) + "M",
		"--mount", "type=bind,source=" + dir + ",target=/work"}
	if name != "" {
		args = append(args, "--name", name)
	}
	args = append(args, image, "/work/guest", "probe", e.probe)
	if kill != nil {
		args = append(args, "30")
	}
	cmd := exec.Command(cli, args...)
	cmd.Env = append(os.Environ(), "WC_CANARY="+e.canary)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return r, err
	}
	t0 := time.Now()
	if err := cmd.Start(); err != nil {
		return r, err
	}
	timer := time.AfterFunc(bootLimit, func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	defer timer.Stop()
	br := bufio.NewReader(pipe)
	if _, err := br.Peek(1); err != nil {
		_ = cmd.Wait()
		return r, fmt.Errorf("no output: %v; stderr: %s", err, tail(stderr.String(), 10))
	}
	first := time.Now()
	r.line, _ = br.ReadString('\n')
	r.line = strings.TrimSpace(r.line)
	r.totalMS = first.Sub(t0).Milliseconds()
	r.bootMS = r.totalMS
	if kill != nil {
		kill(cmd)
		return r, nil
	}
	_, _ = io.Copy(io.Discard, br)
	_ = cmd.Wait()
	r.tdMS, r.exit = time.Since(first).Milliseconds(), cmd.ProcessState.ExitCode()
	if tok, _ := parseHello(r.line); tok != "probe" || r.exit != 7 {
		return r, fmt.Errorf("line %q, CLI exit %d; stderr: %s", r.line, r.exit, tail(stderr.String(), 10))
	}
	return r, nil
}
