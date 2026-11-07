// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"errors"
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
