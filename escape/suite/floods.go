// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// capped is the sandbox the I10 tests want. Each judge holds the host to
// these caps, with slack for the noise of a shared host, while the probe
// asks for about twice as much.
var capped = Want{CPUs: 1, MemoryMiB: 256, DiskMiB: 64}

const (
	forkCount   = 256             // processes the fork probe makes at once: about 50 MiB of page tables, stacks and slab, which a 256 MiB guest holds without thrashing
	forkSlack   = 64              // host processes a whole session may add
	memoryTouch = 512             // MiB the memory probe touches
	memorySlack = 128             // MiB of host memory the session may take over its cap
	diskWrite   = 128             // MiB the disk probe writes
	diskSlack   = 32              // MiB of host disk the session may fill over its cap
	fileCount   = 8192            // descriptors the descriptor probe opens
	fileSlack   = 2048            // open file handles a whole session may add to the host
	logWrite    = 96 << 20        // bytes the log probe streams
	logCap      = 1 << 20         // bytes of one session's output the host may keep
	cpuSpin     = 3               // seconds the CPU probe spins on every CPU it sees
	cpuSlack    = 1.0             // CPU seconds of host noise allowed
	ticksPerSec = 100             // USER_HZ, the unit of /proc/stat
	hold        = 1500 * ms       // how long a probe holds its load for the judge's samples
	childWait   = 5 * time.Second // how long a probe waits for its child, which needs about hold, before killing it
	ms          = time.Millisecond
)

// sampled runs the probe while read samples the host every 50 ms. It returns
// the result with how far below and above the sample taken just before the
// run the host went meanwhile.
func sampled(s Session, read func() (int64, error), args ...string) (r Result, below, above int64, err error) {
	base, err := read()
	if err != nil {
		return r, 0, 0, err
	}
	low, high := base, base
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(50 * ms)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if v, err := read(); err == nil {
					low, high = min(low, v), max(high, v)
				}
			}
		}
	})
	r, err = s.Run(args...)
	close(stop)
	wg.Wait()
	return r, base - low, high - base, err
}

// forkJudge fails if the guest's processes show up on the host.
func forkJudge(ctx context.Context, s Session) (bool, string, error) {
	r, _, above, err := sampled(s, hostProcs, "parent", strconv.Itoa(forkCount))
	if err != nil {
		return false, "", err
	}
	if above > forkSlack {
		return false, fmt.Sprintf("the host gained %d processes while the guest forked (guest says %s: %s)", above, r.Status, r.Detail), nil
	}
	return true, fmt.Sprintf("the host gained %d processes (guest says %s: %s)", above, r.Status, r.Detail), nil
}

// memoryJudge fails if the host lost more available memory than the cap and
// its slack while the guest touched twice the cap.
func memoryJudge(ctx context.Context, s Session) (bool, string, error) {
	r, below, _, err := sampled(s, hostMemAvailable, "parent", strconv.Itoa(memoryTouch))
	if err != nil {
		return false, "", err
	}
	detail := fmt.Sprintf("the host lost %d MiB of available memory while the guest, capped at %d MiB, touched %d MiB (guest says %s: %s)", below>>20, capped.MemoryMiB, memoryTouch, r.Status, r.Detail)
	return below <= int64(capped.MemoryMiB+memorySlack)<<20, detail, nil
}

// diskJudge fails if the host's filesystems lost more free space than the cap
// and its slack while the guest wrote twice the cap.
func diskJudge(ctx context.Context, s Session) (bool, string, error) {
	r, below, _, err := sampled(s, hostDiskFree, strconv.Itoa(diskWrite))
	if err != nil {
		return false, "", err
	}
	detail := fmt.Sprintf("the host lost %d MiB of free disk while the guest, capped at %d MiB, wrote %d MiB (guest says %s: %s)", below>>20, capped.DiskMiB, diskWrite, r.Status, r.Detail)
	return below <= int64(capped.DiskMiB+diskSlack)<<20, detail, nil
}

// fileJudge fails if the guest's open descriptors count as the host's.
func fileJudge(ctx context.Context, s Session) (bool, string, error) {
	r, _, above, err := sampled(s, hostFiles, strconv.Itoa(fileCount))
	if err != nil {
		return false, "", err
	}
	detail := fmt.Sprintf("the host gained %d open file handles while the guest opened %d (guest says %s: %s)", above, fileCount, r.Status, r.Detail)
	return above <= fileSlack, detail, nil
}

// logJudge fails if the host's disk filled by more than one session's log
// may hold, plus slack, while the guest streamed far more than that.
func logJudge(ctx context.Context, s Session) (bool, string, error) {
	r, below, _, err := sampled(s, hostDiskFree, strconv.Itoa(logWrite))
	if err != nil {
		return false, "", err
	}
	detail := fmt.Sprintf("the host lost %d MiB of free disk while the guest streamed %d MiB of output, log cap %d MiB (guest says %s: %s)", below>>20, logWrite>>20, logCap>>20, r.Status, r.Detail)
	return below <= logCap+diskSlack<<20, detail, nil
}

// cpuJudge fails if the host spent more CPU time on the probe's run than its
// one CPU could have, plus slack. A host with one CPU cannot show this.
func cpuJudge(ctx context.Context, s Session) (bool, string, error) {
	before, err := hostBusy()
	if err != nil {
		return false, "", err
	}
	start := time.Now()
	r, err := s.Run(strconv.Itoa(cpuSpin))
	wall := time.Since(start).Seconds()
	if err != nil {
		return false, "", err
	}
	after, err := hostBusy()
	if err != nil {
		return false, "", err
	}
	busy := float64(after-before) / ticksPerSec
	allowed := float64(capped.CPUs)*wall + cpuSlack
	detail := fmt.Sprintf("the host spent %.1f CPU seconds in %.1f s of wall time while the guest, capped at %d CPU, spun (allowed %.1f; guest says %s: %s)", busy, wall, capped.CPUs, allowed, r.Status, r.Detail)
	return busy <= allowed, detail, nil
}

// memoryProbe runs itself again as a child that touches args[1] MiB and holds
// it, so that a guest which kills the child still reports.
func memoryProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want parent|child and MiB"}
	}
	mib, err := strconv.Atoi(args[1])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	if args[0] == "child" {
		b := make([]byte, mib<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		time.Sleep(hold)
		runtime.KeepAlive(b)
		return Result{Status: "touched", Detail: fmt.Sprintf("%d MiB", mib)}
	}
	return asChild(os.Args[1], "child", args[1], "asking for "+args[1]+" MiB")
}

// asChild runs this binary again as a child, in its own process group, with
// the arguments and returns what the child reports; or child-killed, as a
// tried result, when the guest killed it, which is what a sandbox that holds
// I10 does to a flood. A child still running after childWait is killed with
// everything it forked, and reported the same way, so that a guest thrashing
// on a flood never takes the session's whole bound without a report.
func asChild(args ...string) Result {
	exe, err := os.Executable()
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	doing := args[len(args)-1]
	ctx, cancel := context.WithTimeout(context.Background(), childWait)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args[:len(args)-1]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) } // the whole group: the child and what it forked
	cmd.WaitDelay = time.Second                                                    // a forked copy that still holds the child's stdout does not hold the report
	out, err := cmd.Output()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return Result{Status: "child-killed", Detail: fmt.Sprintf("by the probe, still %s after %s", doing, childWait)}
	case errors.As(err, &exit):
		return Result{Status: "child-killed", Detail: exit.String() + " after " + doing}
	default:
		return Result{Status: "error", Detail: "child: " + err.Error()}
	}
	r, err := ParseResult(out)
	if err != nil {
		return Result{Status: "error", Detail: "child: " + err.Error()}
	}
	return r
}

// diskProbe writes args[0] MiB to an unlinked file in the guest's first temp
// directory that lies on a disk, syncs it, and holds it. The space is freed
// when it exits. A directory held in memory would load memory, not disk, and
// is not what this probe is for.
func diskProbe(args []string) Result {
	if len(args) != 1 {
		return Result{Status: "error", Detail: "want MiB"}
	}
	mib, err := strconv.Atoi(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	var f *os.File
	var dir string
	for _, dir = range []string{os.TempDir(), "/var/tmp", "/root", "/"} {
		if memoryBacked(dir) {
			err = errors.New("memory-backed")
			continue
		}
		if f, err = os.CreateTemp(dir, "escape-disk-"); err == nil {
			break
		}
	}
	if err != nil {
		return Result{Status: "error", Detail: "no writable directory on a disk: " + err.Error()}
	}
	os.Remove(f.Name())
	defer f.Close()
	chunk := bytes.Repeat([]byte{0x5a}, 1<<20)
	wrote := 0
	for ; wrote < mib; wrote++ {
		if _, err = f.Write(chunk); err != nil {
			break
		}
	}
	f.Sync()
	time.Sleep(hold)
	detail := fmt.Sprintf("wrote=%d of %d MiB in %s", wrote, mib, dir)
	if err != nil {
		detail += " err=" + short(err)
	}
	return Result{Status: "tried", Detail: detail}
}

// fileProbe raises its own descriptor limit as far as it goes, past the hard
// limit when it may as root, and opens up to args[0] descriptors, as pipe
// ends, then holds them.
func fileProbe(args []string) Result {
	if len(args) != 1 {
		return Result{Status: "error", Detail: "want count"}
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	time.Sleep(ms) // the runtime's poller takes two descriptors on first use: make that now, not once the table is full
	var lim unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_NOFILE, &lim)
	if want := uint64(n) + 64; lim.Max < want {
		if raised := (unix.Rlimit{Cur: want, Max: want}); unix.Setrlimit(unix.RLIMIT_NOFILE, &raised) == nil {
			lim = raised
		}
	}
	lim.Cur = lim.Max
	unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
	var fds []int
	for len(fds) < n {
		var p [2]int
		if err = unix.Pipe(p[:]); err != nil {
			break
		}
		fds = append(fds, p[0], p[1])
	}
	time.Sleep(hold)
	for _, fd := range fds {
		unix.Close(fd)
	}
	detail := fmt.Sprintf("opened=%d of %d limit=%d", len(fds), n, lim.Max)
	if err != nil {
		detail += " err=" + short(err)
	}
	return Result{Status: "tried", Detail: detail}
}

// logProbe streams args[0] bytes of noise to stderr, then holds for the
// judge's samples.
func logProbe(args []string) Result {
	if len(args) != 1 {
		return Result{Status: "error", Detail: "want bytes"}
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	chunk := bytes.Repeat([]byte("escape log flood\n"), 4096)
	wrote := 0
	for wrote < n {
		k, err := os.Stderr.Write(chunk[:min(len(chunk), n-wrote)])
		wrote += k
		if err != nil {
			return Result{Status: "tried", Detail: fmt.Sprintf("wrote=%d of %d bytes err=%s", wrote, n, short(err))}
		}
	}
	time.Sleep(hold)
	return Result{Status: "tried", Detail: fmt.Sprintf("wrote=%d bytes to stderr", wrote)}
}

// cpuProbe spins one thread per CPU the guest sees for args[0] seconds.
func cpuProbe(args []string) Result {
	if len(args) != 1 {
		return Result{Status: "error", Detail: "want seconds"}
	}
	secs, err := strconv.Atoi(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	n := min(runtime.NumCPU(), 8)
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			x := 0
			for time.Now().Before(deadline) {
				for i := range 100000 {
					x += i
				}
			}
			runtime.KeepAlive(x)
		})
	}
	wg.Wait()
	return Result{Status: "tried", Detail: fmt.Sprintf("spun %d threads for %d s", n, secs)}
}
