// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && cgo

package suite

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

// The host figures behave as the Linux ones: a spin shows as ticks of 1/100
// s, a process shows while it runs and not once reaped, and the rest are
// plausible sizes.
func TestHostBusy(t *testing.T) {
	before, err := hostBusy()
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
	}
	runtime.UnlockOSThread()
	after, err := hostBusy()
	if err != nil {
		t.Fatal(err)
	}
	if ticks := after - before; ticks < 25 || ticks > 300*int64(runtime.NumCPU()) {
		t.Fatalf("a 0.3 s spin showed as %d ticks", ticks)
	}
}

func TestHostSizes(t *testing.T) {
	mem, err := hostMemAvailable()
	if err != nil {
		t.Fatal(err)
	}
	procs, err := hostProcs()
	if err != nil {
		t.Fatal(err)
	}
	files, err := hostFiles()
	if err != nil {
		t.Fatal(err)
	}
	disk, err := hostDiskFree()
	if err != nil {
		t.Fatal(err)
	}
	if mem < 64<<20 || procs < 10 || files < 100 || disk < 1<<30 {
		t.Fatalf("available memory %d, processes %d, files %d, free disk %d", mem, procs, files, disk)
	}
}

func TestContainer(t *testing.T) {
	cases := map[string]string{
		"/dev/disk3s1s1": "/dev/disk3",
		"/dev/disk3s5":   "/dev/disk3",
		"/dev/disk10":    "/dev/disk10",
		"devfs":          "devfs",
		"map auto_home":  "map auto_home",
	}
	for dev, want := range cases {
		if got := container(dev); got != want {
			t.Errorf("container(%q) = %q, want %q", dev, got, want)
		}
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
