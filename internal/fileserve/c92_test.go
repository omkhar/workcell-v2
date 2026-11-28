// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C92 of S-1008 sweep 4 (I10): a READDIR at an offset far from the handle's position costs the host a walk of the whole listing when the directory is a merged overlayfs one, and is charged as one cheap frame, so a flood of them under the pace takes host cores. Fails until the fix lands.
// Re-created by the fix unit S-F78 from the record of C92 in loop/state/FINDINGS.md; it lives here, in the suite, from that unit on.

//go:build linux

package fileserve

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestC92SeekOfOneFrame is I10 on the host's CPU, as c76: a directory of 100,000 entries that lies in a lower layer and the upper one, so the overlay merges it, exported; 16 handles; READDIR frames at offsets of 1<<40 and up, 8 KiB each, as fast as the service takes them for two seconds. Judged by this process's CPU over wall against one core plus slack. Control: the same flood on the same directory in the lower layer, a plain filesystem. Root is used once, for the overlay mount: the test re-runs itself through sudo -n, as c65 does.
func TestC92SeekOfOneFrame(t *testing.T) {
	if os.Geteuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("not root, and sudo -n fails:", err)
		}
		exe, _ := os.Executable()
		out, err := exec.Command("sudo", "-n", "env", "TMPDIR="+os.TempDir(), exe, "-test.run=^TestC92SeekOfOneFrame$", "-test.v", "-test.count=1").CombinedOutput()
		if t.Logf("as root:\n%s", out); err != nil {
			t.Fatal(err)
		}
		return
	}
	const bound, budget, entries = 1.5, 2 * time.Second, 100000
	base := t.TempDir()
	lower, upper, work, merged := filepath.Join(base, "lower", "big"), filepath.Join(base, "upper", "big"), filepath.Join(base, "work"), filepath.Join(base, "merged")
	if err := cmp.Or(os.MkdirAll(lower, 0o755), os.MkdirAll(upper, 0o755), os.Mkdir(work, 0o755), os.Mkdir(merged, 0o755), os.WriteFile(filepath.Join(upper, "x"), nil, 0o644)); err != nil {
		t.Fatal(err)
	}
	dir, err := unix.Open(lower, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	for i := 0; err == nil && i < entries; i++ { // the lower layer holds the listing; one entry in the upper makes the directory a merged one
		err = unix.Mknodat(dir, fmt.Sprint(i), unix.S_IFREG|0o644, 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("overlay", merged, "overlay", 0, "lowerdir="+filepath.Dir(lower)+",upperdir="+filepath.Dir(upper)+",workdir="+work); err != nil {
		t.Skip("root without the right to mount an overlay here:", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
	cpu := func() time.Duration { // this process's CPU time, user and system
		var ru unix.Rusage
		_ = unix.Getrusage(unix.RUSAGE_SELF, &ru)
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	for _, tc := range []struct{ name, dir string }{{"control: the plain directory", lower}, {"the merged overlay directory", filepath.Join(merged, "big")}} {
		t.Run(tc.name, func(t *testing.T) {
			k, stop, _ := started(t, tc.dir)
			defer func() { _ = stop() }()
			fhs := make([]uint64, workers)
			for i := range fhs {
				fhs[i] = le.Uint64(k.ok(reqOpendir(rootID)))
			}
			c0, w0, n0, done := cpu(), time.Now(), k.n, make(chan uint64, 1)
			go func() { // frames until the budget is spent, then a STATFS with unique 0 as the marker; done says how many went before it
				for i := 0; time.Since(w0) < budget; i++ {
					k.send(reqReaddir(rootID, fhs[i%workers], 1<<40+uint64(i), 8192, false))
				}
				k.raw(reqStatfs())
				done <- k.n - n0
			}()
			for got, want := 0, -1; got != want; got++ {
				if k.recv().unique == 0 {
					want = int(<-done) + 1
				}
			}
			if c, w := cpu()-c0, time.Since(w0); c.Seconds() > bound*w.Seconds() {
				t.Errorf("I10: %d READDIR frames under the pace took %.2f host cores (%v CPU in %v), want at most %.1f", k.n-n0, c.Seconds()/w.Seconds(), c, w, bound)
			}
		})
	}
}
