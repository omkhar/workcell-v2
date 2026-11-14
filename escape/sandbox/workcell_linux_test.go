// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

// TestIsolatedNetwork starts the network a session of its own gets (isolate, suite.Hold) and looks from inside it: the loopback device holds IsolatedNet;
// "host" and "neighbour" bind at CanaryAddr and Neighbour (bind), and a dial inside the namespace reaches both, the first through a local route alone. It
// needs unshare and root, since the test enters the namespace itself; elsewhere it is skipped.
func TestIsolatedNetwork(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip(err)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	payload, err := BuildPayload(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, err := isolate(t.TempDir(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	var ifs []net.Interface
	var held string
	inside(t, h.pid, func() error {
		var err error
		if ifs, err = net.Interfaces(); err == nil {
			addrs, _ := ifs[0].Addrs()
			held = fmt.Sprint(addrs)
		}
		return err
	})
	if len(ifs) != 1 || ifs[0].Name != "lo" || !strings.Contains(held, IsolatedNet) || !strings.Contains(held, "127.0.0.1/8") {
		t.Fatalf("the namespace holds %d interfaces, lo with %s; want lo alone, holding %s", len(ifs), held, IsolatedNet)
	}
	for addr, want := range map[string]string{"host:8443": CanaryAddr, "neighbour:8443": Neighbour} {
		ln, _, err := h.bind("tcp4", addr)
		if err != nil {
			t.Fatalf("bind %s: %v", addr, err)
		}
		defer ln.Close()
		go func() {
			for c, err := ln.Accept(); err == nil; c, err = ln.Accept() {
				c.Close()
			}
		}()
		if got := ln.Addr().String(); got != net.JoinHostPort(want, "8443") {
			t.Errorf("bind %s listens at %s; want %s", addr, got, want)
		}
		inside(t, h.pid, func() error {
			c, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
			if err == nil {
				c.Close()
			}
			return err
		})
	}
}

// inside runs f on a thread moved into the network namespace of the process pid and left there: Go discards a locked thread with its goroutine.
func inside(t *testing.T, pid int, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		ns, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err == nil {
			defer ns.Close()
			err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
		}
		if err == nil {
			err = f()
		}
		done <- err
	}()
	if err := <-done; err != nil {
		t.Errorf("inside the namespace of pid %d: %v", pid, err)
	}
}
