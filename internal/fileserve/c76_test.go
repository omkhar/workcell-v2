// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C76 of S-1008 (I10), fixed by S-F60. The harness is Linux only, so the build constraint stays.

//go:build linux

package fileserve

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestC76WorkOfOneFrame is I10 on the host's CPU: the pace counts frames, and one frame may ask thousands of syscalls, so a flood under the pace takes several host cores. A GETATTR at the bottom of a chain re-checks every link; a READDIRPLUS page of directories stats, opens, stats and closes every entry, on one handle per worker. Judged by this process's CPU over wall during a second of flood, against one core plus slack, so that any shape of fix passes.
func TestC76WorkOfOneFrame(t *testing.T) {
	const bound, budget, depth, dirs = 1.5, time.Second, 300, 512
	cpu := func() time.Duration { // this process's CPU time, user and system
		var ru unix.Rusage
		_ = unix.Getrusage(unix.RUSAGE_SELF, &ru)
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	flood := func(t *testing.T, k *kern, req func(i int) []byte) { // frames as fast as the service takes them until the budget is spent, then drained
		c0, w0, n0, done := cpu(), time.Now(), k.n, make(chan uint64, 1)
		go func() { // the last frame is a STATFS with unique 0, the marker; done then says how many went before it
			for i := 0; time.Since(w0) < budget; i++ {
				k.send(req(i))
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
			t.Errorf("I10: %d frames under the pace took %.2f host cores (%v CPU in %v), want at most %.1f", k.n-n0, c.Seconds()/w.Seconds(), c, w, bound)
		}
	}
	t.Run("getattr at the bottom of a chain", func(t *testing.T) {
		k, stop, _ := started(t, t.TempDir())
		defer func() { _ = stop() }()
		dir := uint64(rootID)
		for range depth { // the deepest chain the service admits, within depth: a refusal leaves dir where it is
			if e, b := k.call(reqMkdir(dir, "d")); e == 0 {
				dir = le.Uint64(b)
			}
		}
		flood(t, k, func(int) []byte { return reqGetattr(dir) })
	})
	t.Run("readdirplus of a page of directories", func(t *testing.T) {
		k, stop, _ := started(t, t.TempDir())
		defer func() { _ = stop() }()
		fhs := make([]uint64, workers)
		for i := range dirs {
			k.ok(reqMkdir(rootID, fmt.Sprint(i)))
		}
		for i := range fhs {
			fhs[i] = le.Uint64(k.ok(reqOpendir(rootID)))
		}
		flood(t, k, func(i int) []byte { return reqReaddir(rootID, fhs[i%workers], 0, MaxWrite, true) })
	})
}
