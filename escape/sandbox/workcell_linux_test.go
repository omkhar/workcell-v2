// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCLICancel checks that a cancelled steered session ends when its
// context does, and leaves no product behind: at once when the product
// exits on the SIGTERM, and after WaitDelay when it ignores the signal.
// When the suite is not root the product sits behind root's sudo, and the
// kill Go sends then reaches only sudo, so the adapter must kill the
// product's group itself. The product is a shell that notes its pid in the
// session's directory. It needs unshare and, unless the test is root, sudo
// without a password; elsewhere it is skipped.
func TestCLICancel(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip(err)
	}
	if os.Geteuid() != 0 && exec.Command("sudo", "-n", "true").Run() != nil {
		t.Skip("needs root or sudo -n")
	}
	defer func(bin string) { prepared.bin = bin }(prepared.bin)
	prepared.bin = "/bin/sh"
	for _, tc := range []struct {
		name, script string
		within       time.Duration
	}{
		{"exits on SIGTERM", "echo $$ >pid; exec sleep 20", 5 * time.Second},
		{"ignores SIGTERM", "echo $$ >pid; trap '' TERM; exec sleep 20", 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &workcell{dir: t.TempDir(), cfg: Config{Resolver: "127.9.8.7"}}
			if err := os.Mkdir(filepath.Join(w.dir, "cwd"), 0o755); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			_, err := w.cli(ctx, nil, "-c", tc.script)
			if took := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || took > tc.within {
				t.Fatalf("after %s: %v; want context.DeadlineExceeded within %s", took.Round(time.Millisecond), err, tc.within)
			}
			b, err := os.ReadFile(filepath.Join(w.dir, "cwd", "pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(2 * time.Second); syscall.Kill(pid, 0) == nil; time.Sleep(50 * time.Millisecond) {
				if time.Now().After(deadline) {
					syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("the product, pid %d, is still running", pid)
				}
			}
		})
	}
}

// TestProductProcess starts a shell that forks a sleep, the shape of a run
// under steering (a wrapper above the product), and asks for the process
// whose executable is sleep's: the child, not the shell; the shell itself
// when its own executable is asked for; nothing for one that is not there.
func TestProductProcess(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 20; true") // the trailing command keeps the shell from exec'ing sleep
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	root := cmd.Process.Pid
	var pid int
	var ok bool
	for deadline := time.Now().Add(3 * time.Second); !ok && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		pid, ok = productProcess(root, sleep)
	}
	if !ok || pid == root {
		t.Fatalf("productProcess(%d, %s) = %d, %v; want the shell's child", root, sleep, pid, ok)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || !strings.Contains(string(b), " "+strconv.Itoa(root)+" ") {
		t.Fatalf("pid %d is not a child of %d: %q, %v", pid, root, b, err)
	}
	if sh, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", root)); err == nil {
		if got, ok := productProcess(root, sh); !ok || got != root {
			t.Fatalf("productProcess(%d, %s) = %d, %v; want the shell itself", root, sh, got, ok)
		}
	}
	if got, ok := productProcess(root, "/nonexistent/workcell"); ok {
		t.Fatalf("productProcess found %d for a binary that is not there", got)
	}
}

// TestIsolate holds a network namespace, binds the forward port in it, and
// has the payload's own dial probe, entered into the namespace as the
// product is, deliver a token to the listener. Nothing here dials the
// address from the host's own network: a packet to it from there could
// leave the host (SPEC T8). Root, or sudo without a password, and util-linux
// are needed, as the escape suite needs them.
func TestIsolate(t *testing.T) {
	if os.Geteuid() != 0 && exec.Command("sudo", "-n", "true").Run() != nil {
		t.Skip("needs root or sudo -n")
	}
	if _, err := exec.LookPath("nsenter"); err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	payload, err := BuildPayload(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := isolate(dir, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	ln, _, err := h.bind("tcp4", "host:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := ln.Addr().String(); got != isolatedAddr+":8443" {
		t.Fatalf("bound %s, want %s:8443", got, isolatedAddr)
	}
	if _, _, err := h.bind("tcp4", "host:8443"); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a second bind of the port: %v; want address in use", err)
	}
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		n, _ := c.Read(b)
		got <- string(b[:n])
	}()
	argv, err := steered(dir, "127.5.3.53", []string{"PATH=/usr/bin:/bin"}, []string{payload, "raw-ip-odd-port-tcp4", ln.Addr().String(), "token"}, h.pid)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("in the namespace: %v: %s", err, out)
	}
	select {
	case line := <-got:
		if line != "token\n" {
			t.Fatalf("the listener got %q (probe said %s)", line, bytes.TrimSpace(out))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("nothing reached the listener in the namespace (probe said %s)", bytes.TrimSpace(out))
	}
}
