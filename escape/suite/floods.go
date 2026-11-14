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
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// capped is the sandbox the I10 tests want: each judge holds the host to these caps, with slack, while the probe asks for twice as much.
var capped = Want{CPUs: 1, MemoryMiB: 256, DiskMiB: 64}

// cappedLive is capped in mount mode: a write inside the live export lands on the host's disk, where the cap must hold.
var cappedLive = Want{Workspace: true, Mount: true, CPUs: capped.CPUs, MemoryMiB: capped.MemoryMiB, DiskMiB: capped.DiskMiB}

const (
	forkCount   = 256             // processes the fork probe makes at once: about 50 MiB of page tables, stacks and slab, which a 256 MiB guest holds without thrashing
	forkSlack   = 64              // host processes a whole session may add
	memoryTouch = 512             // MiB the memory probe touches
	memorySlack = 128             // MiB of host memory the session may take over its cap
	diskWrite   = 128             // MiB the disk probe writes
	diskSlack   = 32              // MiB of host disk the session may fill over its cap
	sparseGrow  = 4               // GiB the mount-mode disk probe grows a file to without writing it
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

// sampled runs the probe while read samples the host every 50 ms. It returns the result with how far below and above the sample taken just before the run the
// host went meanwhile.
func sampled(s Session, read func() (int64, error), args ...string) (r Result, below, above int64, err error) {
	var rerr error
	below, above, err = sampledRun(read, func() { r, rerr = s.Run(args...) })
	if err == nil {
		err = rerr
	}
	return r, below, above, err
}

// sampledRun is sampled around any run.
func sampledRun(read func() (int64, error), run func()) (below, above int64, err error) {
	base, err := read()
	if err != nil {
		return 0, 0, err
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
	run()
	close(stop)
	wg.Wait()
	return base - low, high - base, nil
}

// loadJudge runs the probe with args while read samples the host, and fails if the host gained (gained) or lost more than bound meanwhile: a guest's processes,
// memory, disk or descriptors counted as the host's. The detail says what in the words given, the figure in units of unit.
func loadJudge(read func() (int64, error), gained bool, bound, unit int64, what string, args ...string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		r, below, above, err := sampled(s, read, args...)
		if err != nil {
			return false, "", err
		}
		got := below
		if gained {
			got = above
		}
		return got <= bound, fmt.Sprintf("the host %s (guest says %s: %s)", fmt.Sprintf(what, got/unit), r.Status, r.Detail), nil
	}
}

// The I10 judges on one figure each: the probe asks for about twice the cap, and the host may lose no more than the cap and its slack, or gain no more than the
// slack. The log judge holds the host's disk to one session's log.
var (
	forkJudge   = loadJudge(hostProcs, true, forkSlack, 1, "gained %d processes while the guest forked", "parent", strconv.Itoa(forkCount))
	memoryJudge = loadJudge(hostMemAvailable, false, int64(capped.MemoryMiB+memorySlack)<<20, 1<<20, fmt.Sprintf("lost %%d MiB of available memory while the guest, capped at %d MiB, touched %d MiB", capped.MemoryMiB, memoryTouch), "parent", strconv.Itoa(memoryTouch))
	diskJudge   = loadJudge(hostDiskFree, false, int64(capped.DiskMiB+diskSlack)<<20, 1<<20, fmt.Sprintf("lost %%d MiB of free disk while the guest, capped at %d MiB, wrote %d MiB", capped.DiskMiB, diskWrite), strconv.Itoa(diskWrite))
	fileJudge   = loadJudge(hostFiles, true, fileSlack, 1, fmt.Sprintf("gained %%d open file handles while the guest opened %d", fileCount), strconv.Itoa(fileCount))
	logJudge    = loadJudge(hostDiskFree, false, logCap+diskSlack<<20, 1<<20, fmt.Sprintf("lost %%d MiB of free disk while the guest streamed %d MiB of output, log cap %d MiB", logWrite>>20, logCap>>20), strconv.Itoa(logWrite))
)

// mountDiskJudge is diskJudge for a live export: the probe writes twice the cap under the export and grows a file there far past it without writing; neither
// the host's free disk nor a file in the export may pass the cap and its slack. A run that did not end in the probe's own "tried" report is never a pass.
func mountDiskJudge(ctx context.Context, s Session) (bool, string, error) {
	var r Result
	var size int64
	var rerr error
	below, _, err := sampledRun(hostDiskFree, func() {
		r, _, size, rerr = sampled(s, func() (int64, error) { return exportSize(s.Workspace) },
			s.Guest, strconv.Itoa(diskWrite), strconv.Itoa(sparseGrow))
	})
	if err == nil {
		err = rerr
	}
	if err != nil {
		return false, "", err
	}
	if r.Status != "tried" {
		return false, fmt.Sprintf("the guest did not report its flood as tried (guest says %s: %s)", r.Status, r.Detail), nil
	}
	bound := int64(capped.DiskMiB+diskSlack) << 20
	detail := fmt.Sprintf("the host lost %d MiB of free disk and a file in the export reached %d MiB while the guest, capped at %d MiB, wrote %d MiB and grew a file to %d GiB in its live export (guest says %s: %s)",
		below>>20, size>>20, capped.DiskMiB, diskWrite, sparseGrow, r.Status, r.Detail)
	return below <= bound && size <= bound, detail, nil
}

// exportSize is the largest apparent size of a file directly in the export, as the host sees it: what a sparse growth costs the host in a quota or a later
// copy, though not in free disk.
func exportSize(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var size int64
	for _, e := range entries {
		if st, err := e.Info(); err == nil && st.Mode().IsRegular() {
			size = max(size, st.Size())
		}
	}
	return size, nil
}

// cpuJudge runs the probe for cpuSpin seconds, told the host end of the relay too when relay is set, and fails if the host spent more CPU time on
// the run than the guest's one CPU could have, plus slack. A host with one CPU cannot show this.
func cpuJudge(relay bool) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		args := []string{strconv.Itoa(cpuSpin)}
		if relay {
			ch, err := s.Relay(ctx)
			if err != nil {
				return false, "", err
			}
			args = append(args, ch.Addr)
		}
		before, err := hostBusy()
		if err != nil {
			return false, "", err
		}
		start := time.Now()
		r, err := s.Run(args...)
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
		detail := fmt.Sprintf("the host spent %.1f CPU seconds in %.1f s of wall time while the guest, capped at %d CPU, loaded it (allowed %.1f; guest says %s: %s)", busy, wall, capped.CPUs, allowed, r.Status, r.Detail)
		return busy <= allowed, detail, nil
	}
}

// ints reads args as the n integers a probe wants, and says what it wants when they are not.
func ints(args []string, n int, want string) ([]int, Result) {
	out := make([]int, 0, n)
	for _, a := range args {
		v, err := strconv.Atoi(a)
		if err != nil {
			return nil, Result{Status: "error", Detail: err.Error()}
		}
		out = append(out, v)
	}
	if len(args) != n {
		return nil, Result{Status: "error", Detail: "want " + want}
	}
	return out, Result{}
}

// memoryProbe runs itself again as a child that touches args[1] MiB and holds it, so that a guest which kills the child still reports.
func memoryProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want parent|child and MiB"}
	}
	v, r := ints(args[1:], 1, "MiB")
	if r.Status != "" {
		return r
	}
	mib := v[0]
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

// asChild runs this binary again as a child, in its own process group, and returns what it reports; or child-killed, a tried result, when the guest killed it,
// or when it still runs after childWait and is killed with everything it forked.
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
// directory on a disk (one in memory would load memory, not disk), syncs it, and holds it.
func diskProbe(args []string) Result {
	v, r := ints(args, 1, "MiB")
	if r.Status != "" {
		return r
	}
	f, dir, err := onDisk()
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	os.Remove(f.Name())
	defer f.Close()
	detail := fill(f, v[0]) + " in " + dir
	time.Sleep(hold)
	return Result{Status: "tried", Detail: detail}
}

// onDisk makes a temp file in the guest's first temp directory on a disk (one in memory would load memory, not disk), and says which directory.
func onDisk() (f *os.File, dir string, err error) {
	for _, dir = range []string{os.TempDir(), "/var/tmp", "/root", "/"} {
		if memoryBacked(dir) {
			err = errors.New("memory-backed")
			continue
		}
		if f, err = os.CreateTemp(dir, "escape-disk-"); err == nil {
			return f, dir, nil
		}
	}
	return nil, "", errors.New("no writable directory on a disk: " + err.Error())
}

// fill writes mib MiB to f a MiB at a time, stops at the first error, syncs, and says how far it got.
func fill(f *os.File, mib int) string {
	chunk := bytes.Repeat([]byte{0x5a}, 1<<20)
	wrote := 0
	var err error
	for ; wrote < mib; wrote++ {
		if _, err = f.Write(chunk); err != nil {
			break
		}
	}
	f.Sync()
	detail := fmt.Sprintf("wrote=%d of %d MiB", wrote, mib)
	if err != nil {
		detail += " err=" + short(err)
	}
	return detail
}

// mountDiskProbe is diskProbe for a live export: in the export at args[0] it grows a file to args[2] GiB without writing it, by ftruncate and then by a byte at
// the end, then writes args[1] MiB to a second file, syncs, holds both for the judge's samples, and removes them. The growth comes first so that it is judged
// on its own, not as what a byte count of the writes left.
func mountDiskProbe(args []string) Result {
	if len(args) != 3 {
		return Result{Status: "error", Detail: "want export, MiB and GiB"}
	}
	v, r := ints(args[1:], 2, "MiB and GiB")
	if r.Status != "" {
		return r
	}
	mib, gib := v[0], v[1]
	sparse, err := os.Create(filepath.Join(args[0], "escape-sparse"))
	if err != nil {
		return Result{Status: "error", Detail: "create in export: " + short(err)}
	}
	defer os.Remove(sparse.Name())
	defer sparse.Close()
	end := int64(gib) << 30
	detail := "truncate=" + status(sparse.Truncate(end))
	_, err = sparse.WriteAt([]byte{1}, end-1)
	detail += " pwrite=" + status(err)
	sparse.Sync()
	if st, err := sparse.Stat(); err == nil {
		detail += fmt.Sprintf(" size=%dMiB", st.Size()>>20)
	}
	full, err := os.Create(filepath.Join(args[0], "escape-fill"))
	if err != nil {
		return Result{Status: "tried", Detail: detail + " create: " + short(err)}
	}
	defer os.Remove(full.Name())
	defer full.Close()
	detail += " " + fill(full, mib)
	time.Sleep(hold)
	return Result{Status: "tried", Detail: detail}
}

// fileProbe raises its own descriptor limit as far as it goes, past the hard limit when it may as root, and opens up to args[0] descriptors, as pipe ends, then
// holds them.
func fileProbe(args []string) Result {
	v, r := ints(args, 1, "count")
	if r.Status != "" {
		return r
	}
	n := v[0]
	var err error
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

// logProbe streams args[0] bytes of noise to stderr, then holds for the judge's samples.
func logProbe(args []string) Result {
	v, r := ints(args, 1, "bytes")
	if r.Status != "" {
		return r
	}
	n := v[0]
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
	v, r := ints(args, 1, "seconds")
	if r.Status != "" {
		return r
	}
	secs := v[0]
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
