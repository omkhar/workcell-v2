// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && cgo

package suite

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// The host figures behave as the Linux ones: the available memory is a plausible size, and a process shows while it runs, not once reaped.
func TestHostMemAvailable(t *testing.T) {
	mem, err := hostMemAvailable()
	if err != nil || mem < 64<<20 {
		t.Fatalf("available memory %d, %v", mem, err)
	}
}

func TestHelperAlive(t *testing.T) {
	if alive, err := helperAlive(os.Getpid()); err != nil || !alive {
		t.Fatalf("self: %v %v", alive, err)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if alive, err := helperAlive(pid); err != nil || !alive {
		t.Fatalf("running child: %v %v", alive, err)
	}
	cmd.Process.Kill()
	for start := time.Now(); time.Since(start) < 3*time.Second; time.Sleep(10 * time.Millisecond) {
		if alive, err := helperAlive(pid); err != nil {
			t.Fatal(err)
		} else if !alive {
			break // a zombie: killed, not yet waited for
		}
	}
	if alive, _ := helperAlive(pid); alive {
		t.Fatal("a killed, unwaited child counts as alive")
	}
	cmd.Wait()
	if alive, err := helperAlive(pid); err != nil || alive {
		t.Fatalf("reaped child: %v %v", alive, err)
	}
}
