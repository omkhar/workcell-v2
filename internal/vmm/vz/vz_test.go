// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package vz

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/omkhar/workcell/v2/internal/vmm"
	"golang.org/x/sys/unix"
)

// The pinned arm64 kernel: Firecracker's CI build, kernel A of ADR-001, which boots
// under Virtualization.framework (U-102). It is what escape/sandbox boots on a Mac.
const (
	kernelURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155"
	kernelSHA = "61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be"

	port      = 5000 // the test guest dials this
	signedEnv = "VZ_TEST_SIGNED"
	bootLimit = 15 * time.Second
)

// entitlements is the plist an ad hoc signature carries so that a process may start a VM.
const entitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.virtualization</key>
	<true/>
</dict>
</plist>
`

// needVM skips a test that boots a guest where it cannot: no hypervisor, or no codesign
// to entitle a binary with.
func needVM(t *testing.T) {
	t.Helper()
	if hv, err := unix.SysctlUint32("kern.hv_support"); err != nil || hv != 1 {
		t.Skipf("kern.hv_support=%d (%v): no hypervisor here", hv, err)
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		t.Skipf("codesign is missing: %v", err)
	}
}

// TestMachine drives the Machine itself. The framework wants the entitlement on the
// process, so the test binary is copied, signed and run again with signedEnv set; the
// child does the work and the parent reports it.
func TestMachine(t *testing.T) {
	needVM(t)
	if os.Getenv(signedEnv) == "" {
		reexec(t, "^TestMachine$")
		return
	}
	kernel := pinned(t)
	dir := t.TempDir()
	initrd := initramfs(t, dir, file{"init", slurp(t, build(t, dir, "../firecracker/testdata/guest", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64"))})
	in := inputs{kernel: kernel, initrd: initrd}
	ctx := context.Background()

	t.Run("check", func(t *testing.T) {
		if err := in.machine(t, nil).Check(ctx); err != nil {
			t.Fatalf("Check on this host: %v", err)
		}
		missing := inputs{kernel: filepath.Join(t.TempDir(), "missing"), initrd: initrd}
		if err := missing.machine(t, nil).Check(ctx); err == nil {
			t.Fatal("Check passed with a missing kernel")
		} else {
			t.Logf("vmm check missing_kernel=%q", err)
		}
	})

	// The guest reboots when the host hangs up, as workcell-init does. The framework
	// boots the kernel again then: the guest dials once more, and the VM is still
	// running, so the host ends it with Kill. Should the framework ever stop the VM
	// instead, Wait returns and the test says so.
	t.Run("boot-and-stop", func(t *testing.T) {
		m, conn, ln, bootMS := boot(t, in)
		short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if err := m.Wait(short); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Wait with an ended context: %v", err)
		}
		t0 := time.Now()
		_ = conn.Close() // the guest reboots on EOF
		again := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			again <- err
			if err == nil {
				c.Close()
			}
		}()
		wait, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		stopped := make(chan error, 1)
		go func() { stopped <- m.Wait(wait) }()
		select {
		case err := <-again:
			if err != nil {
				t.Fatalf("Accept after the guest.s reboot: %v", err)
			}
			t.Logf("vmm restart_stops_vm=false guest_back_ms=%d", time.Since(t0).Milliseconds())
		case err := <-stopped:
			t.Logf("vmm restart_stops_vm=true teardown_ms=%d wait=%v", time.Since(t0).Milliseconds(), err)
		}
		t0 = time.Now()
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		t.Logf("vmm boot_ms=%d close_ms=%d", bootMS, time.Since(t0).Milliseconds())
	})

	t.Run("force-kill", func(t *testing.T) {
		m, conn, _, _ := boot(t, in)
		defer conn.Close()
		if _, err := m.Listen(port + 1); err == nil {
			t.Fatal("Listen after Start was accepted")
		}
		if err := m.Start(ctx); err == nil {
			t.Fatal("a second Start was accepted")
		}
		t0 := time.Now()
		if err := m.Kill(); err != nil {
			t.Fatalf("Kill: %v", err)
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := m.Wait(wait)
		if err == nil || !strings.Contains(err.Error(), "killed") {
			t.Fatalf("Wait after Kill = %v, want an error that says killed", err)
		}
		t.Logf("vmm kill_ms=%d wait=%q", time.Since(t0).Milliseconds(), err)
		if err := m.Kill(); err != nil {
			t.Fatalf("second Kill: %v", err)
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

// TestRun runs the built `workcell run` as a child, as a user would, against a data
// directory laid out the way `workcell update` will leave it on a Mac: the pinned kernel, an
// initramfs whose /init is workcell-init, and the Debian arm64 image from mkimage. The
// binary is signed ad hoc with the entitlement, as escape/sandbox does.
func TestRun(t *testing.T) {
	needVM(t)
	kernel := pinned(t)
	tmp := t.TempDir()
	data := filepath.Join(tmp, "workcell")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	workcellBin := entitle(t, bin, build(t, t.TempDir(), "github.com/omkhar/workcell/v2/cmd/workcell", "CGO_ENABLED=1"))
	initrd := initramfs(t, bin, file{"init", slurp(t, build(t, t.TempDir(), "github.com/omkhar/workcell/v2/cmd/workcell-init", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64"))})
	for dst, src := range map[string]string{"vmlinux": kernel, "initrd.cpio": initrd, "root.ext4": debianImage(t, bin)} {
		if err := os.Symlink(src, filepath.Join(data, dst)); err != nil {
			t.Fatal(err)
		}
	}
	var flags []string  // flags of `workcell run`, before the --
	repo := t.TempDir() // the directory `workcell run` starts in, and copies into the guest
	sessions := filepath.Join(tmp, "s")
	if err := os.Mkdir(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	workcell := func(dir string, stdin *os.File, args ...string) *exec.Cmd {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, workcellBin, append(append([]string{"run"}, append(flags, "--")...), args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+tmp, "HOME="+tmp, "TERM=xterm", "TMPDIR="+sessions)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		return cmd
	}
	// pipesIn runs the child in dir with stdin from the reader and returns what it printed and how it ended.
	pipesIn := func(t *testing.T, dir string, stdin *bytes.Reader, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		cmd := workcell(dir, nil, args...)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		t0 := time.Now()
		err := cmd.Run()
		t.Logf("workcell run %q took %d ms", args, time.Since(t0).Milliseconds())
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("stderr:\n%s", e.String())
			}
		})
		return o.String(), e.String(), cmd.ProcessState.ExitCode()
	}
	pipes := func(t *testing.T, stdin *bytes.Reader, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		return pipesIn(t, repo, stdin, args...)
	}

	t.Run("exit-code", func(t *testing.T) {
		tests := []struct {
			name string
			args []string
			code int
			err  string // a word in stderr, or ""
		}{
			{"exit 7", []string{"sh", "-c", "exit 7"}, 7, ""},
			{"success", []string{"true"}, 0, ""},
			{"killed by SIGTERM", []string{"sh", "-c", "kill -TERM $$"}, 143, ""},
			{"no such command", []string{"/nope"}, 126, "could not run"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, stderr, code := pipes(t, nil, tc.args...)
				if code != tc.code || !strings.Contains(stderr, tc.err) {
					t.Errorf("exit %d with stderr %q, want exit %d and %q", code, stderr, tc.code, tc.err)
				}
			})
		}
	})

	t.Run("pipes", func(t *testing.T) {
		stdout, stderr, code := pipes(t, nil, "sh", "-c", "echo out; echo err >&2")
		if stdout != "out\n" || stderr != "err\n" || code != 0 {
			t.Errorf("stdout %q, stderr %q, exit %d; want %q, %q, 0", stdout, stderr, code, "out\n", "err\n")
		}
	})

	// 5 MiB is 80 frames of 64 KiB: more than the init queues, to a command that reads late.
	t.Run("stdin-flow-control", func(t *testing.T) {
		const size = 5 << 20
		stdout, _, code := pipes(t, bytes.NewReader(make([]byte, size)), "sh", "-c", "sleep 1; wc -c")
		if want := fmt.Sprint(size, "\n"); stdout != want || code != 0 {
			t.Errorf("wc -c printed %q with exit %d, want %q", stdout, code, want)
		}
	})

	// The caps of I10 as the guest sees them: one vCPU, at most 256 MiB of RAM, and ENOSPC
	// at 64 MiB of writes to the root while less than that succeeds.
	t.Run("resource-caps", func(t *testing.T) {
		flags = []string{"--cpus", "1", "--memory", "256MiB", "--disk", "64MiB"}
		t.Cleanup(func() { flags = nil })
		const script = `nproc
sed -n 's/^MemTotal: *\([0-9]*\) kB/\1/p' /proc/meminfo
dd if=/dev/zero of=/var/tmp/a bs=1M count=32 2>/dev/null && echo small-ok
rm -f /var/tmp/a
dd if=/dev/zero of=/var/tmp/b bs=1M count=80 2>&1 | grep -o 'No space left on device'`
		stdout, _, _ := pipes(t, nil, "sh", "-c", script)
		got := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(got) != 4 {
			t.Fatalf("the guest printed %q, want 4 lines", stdout)
		}
		if got[0] != "1" {
			t.Errorf("nproc is %q, want 1", got[0])
		}
		var kb int
		if _, err := fmt.Sscan(got[1], &kb); err != nil || kb > 256<<10 {
			t.Errorf("MemTotal is %q kB, want at most %d", got[1], 256<<10)
		}
		if got[2] != "small-ok" {
			t.Errorf("a 32 MiB write: %q, want small-ok", got[2])
		}
		if got[3] != "No space left on device" {
			t.Errorf("an 80 MiB write: %q, want ENOSPC", got[3])
		}
	})

	// Clone mode: the guest starts in a copy of the directory, what it writes there stays
	// there (I1), and once the session ends the VMM's files are gone while the copy stays
	// as a session, with the directory it came from on record, for diff and pull.
	t.Run("workspace", func(t *testing.T) {
		own, err := filepath.EvalSymlinks(t.TempDir()) // as the child's Getwd will spell it: /tmp is a link here
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(own, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(data, "sessions")
		before, _ := os.ReadDir(kept)
		stdout, _, code := pipesIn(t, own, nil, "sh", "-c", "cat hello.txt; pwd; echo new > created.txt; cat created.txt")
		if want := "hi\n/workspace\nnew\n"; stdout != want || code != 0 {
			t.Errorf("the guest printed %q with exit %d, want %q and 0", stdout, code, want)
		}
		if _, err := os.Stat(filepath.Join(own, "created.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a file the guest wrote is on the host: %v", err)
		}
		if left, err := os.ReadDir(sessions); err != nil || len(left) != 0 {
			t.Errorf("left in %s after the session: %v (%v), want nothing", sessions, left, err)
		}
		after, err := os.ReadDir(kept)
		if err != nil || len(after) != len(before)+1 {
			t.Fatalf("%s holds %d entries after the session (%v), want %d: one more than before", kept, len(after), err, len(before)+1)
		}
		session := filepath.Join(kept, after[len(after)-1].Name())
		if _, err := os.Stat(filepath.Join(session, "workspace.ext4")); err != nil {
			t.Errorf("the session's image: %v", err)
		}
		if b, err := os.ReadFile(filepath.Join(session, "repo")); err != nil || strings.TrimSpace(string(b)) != own {
			t.Errorf("the session's repo file holds %q (%v), want %q", b, err, own)
		}
	})

	t.Run("workspace-cap", func(t *testing.T) {
		flags = []string{"--disk", "64MiB"}
		t.Cleanup(func() { flags = nil })
		stdout, _, _ := pipes(t, nil, "sh", "-c", "dd if=/dev/zero of=/workspace/big bs=1M count=100 2>&1 | grep -o 'No space left on device'")
		if strings.TrimSpace(stdout) != "No space left on device" {
			t.Errorf("a 100 MiB write to /workspace with --disk 64MiB: %q, want ENOSPC", stdout)
		}
	})

	t.Run("terminal", func(t *testing.T) {
		master, slave := openPTY(t)
		setSize(t, master, 24, 80)
		// A shell is the session leader, as it would be for a user: the terminal is revoked when
		// the leader exits here, so the shell itself compares the settings workcell left behind.
		script := fmt.Sprintf(`before=$(stty -g); %s run -- sh -c 'stty size; echo READY; read x; stty size; exit 3'; s=$?; [ "$before" = "$(stty -g)" ] && echo SAME || echo CHANGED; exit $s`, workcellBin)
		cmd := workcell(repo, slave, "unused")
		cmd.Args = []string{"/bin/sh", "-c", script}
		cmd.Path = "/bin/sh"
		cmd.Stdout, cmd.Stderr = slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true} // the slave is its terminal, as in a shell
		out := &screen{}
		go out.copyFrom(master)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("terminal output:\n%q", out.String())
			}
		})
		out.wait(t, "READY")
		if got := out.String(); !strings.Contains(got, "24 80\n") {
			t.Fatalf("stty size before the resize: %q, want 24 80", got)
		}
		setSize(t, master, 40, 100)        // the kernel sends SIGWINCH to workcell
		time.Sleep(500 * time.Millisecond) // the resize and the input travel apart; let the resize arrive first
		if _, err := master.WriteString("go\n"); err != nil {
			t.Fatal(err)
		}
		err := cmd.Wait()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatalf("workcell ended with %v, want exit 3", err)
		}
		if got := out.String(); !strings.Contains(got, "40 100\n") {
			t.Errorf("stty size after the resize: %q, want 40 100", got)
		}
		if got := out.String(); !strings.Contains(got, "SAME\n") {
			t.Errorf("the terminal was left changed: %q", got)
		}
	})
}

// reexec copies this test binary, signs the copy with the entitlement and runs the tests
// matching run in it, with the child's output as this test's log.
func reexec(t *testing.T, run string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	signed := entitle(t, t.TempDir(), self)
	args := []string{"-test.run=" + run, "-test.v", "-test.count=1"}
	if d, ok := t.Deadline(); ok {
		args = append(args, "-test.timeout="+time.Until(d).String())
	}
	cmd := exec.Command(signed, args...)
	cmd.Env = append(os.Environ(), signedEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("signed child:\n%s", out)
	if err != nil {
		t.Fatalf("the signed test binary: %v", err)
	}
}

// entitle writes a fresh copy of the binary at src into dir, signed ad hoc with the
// entitlement, and returns it. The copy is fresh because re-signing a binary that has
// run can get it killed (U-102).
func entitle(t *testing.T, dir, src string) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(out, b, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "vz.entitlements")
	if err := os.WriteFile(plist, []byte(entitlements), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("codesign", "-s", "-", "--entitlements", plist, "-f", out)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("codesign %s: %v\n%s", out, err, o)
	}
	return out
}

// inputs are the kernel and the initramfs of a test guest.
type inputs struct{ kernel, initrd string }

// machine is a Machine over the inputs, closed when the test ends.
func (in inputs) machine(t *testing.T, console io.Writer) *Machine {
	t.Helper()
	m := New(vmm.Config{Kernel: in.kernel, Initrd: in.initrd, CPUs: 2, MemoryMiB: 512, CID: 3, Console: console, Dir: t.TempDir()})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// boot starts a guest and returns it with the guest's connection and the listener it came
// on, once it said hello.
func boot(t *testing.T, in inputs) (m *Machine, conn net.Conn, ln net.Listener, bootMS int64) {
	t.Helper()
	console := &bytes.Buffer{}
	m = in.machine(t, console)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("console:\n%s", console.Bytes())
		}
	})
	ln, err := m.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		var err error
		conn, err = ln.Accept()
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(bootLimit):
		t.Fatalf("no vsock connection from the guest within %v", bootLimit)
	}
	bootMS = time.Since(t0).Milliseconds()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("guest said %q (%v), want hello", line, err)
	}
	return m, conn, ln, bootMS
}

// pins holds the pinned kernel, fetched once per test binary into the user's cache
// directory and checked against its digest on every use.
var pins struct {
	sync.Once
	kernel string
	err    error
}

// pinned is the pinned kernel, downloaded unless the cache holds the right bytes.
func pinned(t *testing.T) string {
	t.Helper()
	pins.Do(func() {
		cache, err := os.UserCacheDir()
		if err != nil {
			pins.err = err
			return
		}
		dir := filepath.Join(cache, "workcell-test")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			pins.err = err
			return
		}
		pins.kernel = filepath.Join(dir, "vmlinux-6.1.155-aarch64")
		if digest(pins.kernel) == kernelSHA {
			return
		}
		pins.err = download(pins.kernel, kernelURL, kernelSHA)
	})
	if pins.err != nil {
		t.Fatal(pins.err)
	}
	return pins.kernel
}

// digest is the SHA-256 of the file at path, or "" if it cannot be read.
func digest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// download fetches url into path, through a temporary file, only if its SHA-256 is want.
func download(path, url, want string) error {
	c := http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "download")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s, pinned %s", url, got, want)
	}
	return os.Rename(f.Name(), path)
}

// build compiles pkg into dir with env added and returns the binary; for the guest the
// caller passes GOOS=linux GOARCH=arm64.
func build(t *testing.T, dir, pkg string, env ...string) string {
	t.Helper()
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, pkg)
	cmd.Env = append(os.Environ(), env...)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, o)
	}
	return out
}

// slurp is the bytes of the file at path.
func slurp(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// debianImage builds cmd/mkimage into dir and runs it on the pinned Debian for arm64: the
// root image `workcell update` will leave, as the escape adapter makes it.
func debianImage(t *testing.T, dir string) string {
	t.Helper()
	build(t, dir, "github.com/omkhar/workcell/v2/cmd/mkimage", "CGO_ENABLED=1")
	image := filepath.Join(dir, "root.ext4")
	t0 := time.Now()
	mk := exec.Command(filepath.Join(dir, "mkimage"), "-pin", "../../../pins/debian.json", "-arch", "arm64", "-o", image)
	if out, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("mkimage: %v\n%s", err, out)
	}
	t.Logf("mkimage took %s", time.Since(t0).Round(time.Second))
	return image
}

// newc returns one entry of a "newc" cpio archive: the 110-byte header, the name and its
// NUL padded to 4, then the data padded to 4.
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

// file is one executable of an initramfs, by its name at the root.
type file struct {
	name string
	data []byte
}

// initramfs writes an uncompressed cpio of the files into dir and returns its path.
func initramfs(t *testing.T, dir string, files ...file) string {
	t.Helper()
	var b []byte
	for _, f := range files {
		b = append(b, newc(f.name, 0o100755, f.data)...)
	}
	path := filepath.Join(dir, "initramfs.cpio")
	if err := os.WriteFile(path, append(b, newc("TRAILER!!!", 0, nil)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// openPTY is a host pseudo-terminal pair, closed when the test ends.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fd := int(master.Fd())
	var name [128]byte
	for _, req := range []uint{unix.TIOCPTYGRANT, unix.TIOCPTYUNLK} {
		if err := unix.IoctlSetInt(fd, req, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		t.Fatal(e)
	}
	if slave, err = os.OpenFile(string(name[:bytes.IndexByte(name[:], 0)]), os.O_RDWR|unix.O_NOCTTY, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	return master, slave
}

func setSize(t *testing.T, master *os.File, rows, cols uint16) {
	t.Helper()
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil {
		t.Fatal(err)
	}
}

// screen collects what a terminal's master end yields, carriage returns dropped.
type screen struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *screen) copyFrom(r *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		s.mu.Lock()
		s.b.WriteString(strings.ReplaceAll(string(buf[:n]), "\r", ""))
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// wait polls for want for up to 30 s.
func (s *screen) wait(t *testing.T, want string) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(s.String(), want) {
			return
		}
	}
	t.Fatalf("no %q on the terminal in 30 s; it shows %q", want, s.String())
}
