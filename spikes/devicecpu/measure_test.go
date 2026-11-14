// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package devicecpu measures, on a real VM, where the host's CPU goes while the I10 rows cpu-flood and device-cpu-flood run (C6 of S-1003, which S-F3
// answers with a CPU affinity mask on the Firecracker child): a measurement for the CI log, never a verdict. It starts only the escape runner, as
// loop/gate.sh does, and reads /proc. The runner is lent (S12), so processes outside this test's own tree are one unnamed sum.
package devicecpu

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// proc is one process over a phase: its utime+stime in ticks when the phase began and when last seen, and, for the VMM and the supervisor, each thread
// as "name=cpus" from the latest snapshot that saw the most threads.
type proc struct {
	comm        string
	ppid        int
	kthread     bool
	first, last int64
	threads     []string
}

// phase is one window of the run: the preparation, then each row, each ended by a line the runner prints on stderr.
type phase struct {
	name         string
	n            int // samples so far
	begin, end   time.Time
	busy0, busy1 int64 // /proc/stat busy ticks, as the suite's judge counts them
	procs        map[int]*proc
}

func TestMeasure(t *testing.T) {
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); runtime.GOOS != "linux" || err != nil {
		t.Skipf("no usable /dev/kvm on %s: %v", runtime.GOOS, err)
	} else {
		_ = f.Close()
	}
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/omkhar/workcell/v2").Output()
	if err != nil {
		t.Skipf("the module root: %v", err)
	}
	cmd := exec.Command("go", "run", "./escape/cmd/escape", "-sandbox", "workcell", "-only", "cpu-flood,device-cpu-flood")
	cmd.Dir, cmd.Stdout = strings.TrimSpace(string(root)), io.Discard // the verdict lines on stderr say it all
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("the escape runner did not start: %v", err)
	}
	var mu sync.Mutex
	phases := []*phase{{name: "prepare", procs: map[int]*proc{}}}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { // every 100 ms, one sample into the current phase
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			mu.Lock()
			sample(phases[len(phases)-1])
			mu.Unlock()
			select {
			case <-tick.C:
			case <-stop:
				return
			}
		}
	}()
	ready := false
	for sc := bufio.NewScanner(stderr); sc.Scan(); {
		line := sc.Text()
		fmt.Fprintln(os.Stderr, line)
		next := ""
		switch {
		case strings.Contains(line, "workcell sandbox ready"):
			next, ready = "cpu-flood", true
		case strings.HasPrefix(line, "escape: workcell: I10 cpu-flood:"):
			next = "device-cpu-flood"
		case strings.HasPrefix(line, "escape: workcell: I10 device-cpu-flood:"):
			next = "after"
		}
		if strings.HasPrefix(line, "escape: workcell: I10") {
			t.Log(line) // the row's own verdict
		}
		if next != "" {
			mu.Lock()
			phases = append(phases, &phase{name: next, procs: map[int]*proc{}})
			mu.Unlock()
		}
	}
	err = cmd.Wait()
	close(stop)
	<-done
	if !ready {
		t.Skipf("the escape harness did not come up (%v); nothing measured", err)
	}
	t.Logf("escape runner: %v (a failing row is the measurement, not this test's)", err)
	for _, ph := range phases[1:] {
		if ph.name == "after" || ph.n < 2 {
			continue
		}
		t.Logf("phase %s: %.1f s wall, host busy %.2f CPU s over every CPU", ph.name, ph.end.Sub(ph.begin).Seconds(), float64(ph.busy1-ph.busy0)/100)
		var tree, kernel, threads []string
		kern, other := map[string]int64{}, int64(0)
		for pid, p := range ph.procs {
			d := p.last - p.first
			switch {
			case ph.descends(pid):
				tree = append(tree, fmt.Sprintf("%s[%d]=%.2f", p.comm, pid, float64(d)/100))
			case p.kthread:
				kern[strings.TrimRight(strings.SplitN(p.comm, "/", 2)[0], "0123456789")] += d // kworker/u8:1 and ksoftirqd/0 by family
			default:
				other += d
			}
			if len(p.threads) > 0 {
				threads = append(threads, fmt.Sprintf("%s[%d]: %s", p.comm, pid, strings.Join(p.threads, " ")))
			}
		}
		for name, d := range kern {
			if d > 0 {
				kernel = append(kernel, fmt.Sprintf("%s=%.2f", name, float64(d)/100))
			}
		}
		for _, l := range [][]string{tree, kernel, threads} {
			slices.Sort(l)
		}
		t.Logf("  own tree: %s\n  kernel threads: %s\n  other: %.2f\n  threads: %s", strings.Join(tree, " "), strings.Join(kernel, " "), float64(other)/100, strings.Join(threads, "; "))
	}
}

// descends says whether pid is in this test's own process tree: go, the runner, the product and the VMM.
func (ph *phase) descends(pid int) bool {
	for self := os.Getpid(); pid > 1; {
		if pid == self {
			return true
		}
		p, ok := ph.procs[pid]
		if !ok {
			return false
		}
		pid = p.ppid
	}
	return false
}

// sample reads every process once into ph. A process first seen after the phase's first sample started inside it, so its ticks count from zero.
func sample(ph *phase) {
	if ph.n == 0 {
		ph.begin, ph.busy0 = time.Now(), busy()
	}
	ph.end, ph.busy1 = time.Now(), busy()
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		b, err2 := os.ReadFile("/proc/" + e.Name() + "/stat")
		s := string(b)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if err != nil || err2 != nil || open < 0 || close < open {
			continue
		}
		f := strings.Fields(s[close+1:]) // state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime ...
		if len(f) < 13 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		flags, _ := strconv.ParseUint(f[6], 10, 64)
		ut, _ := strconv.ParseInt(f[11], 10, 64)
		st, _ := strconv.ParseInt(f[12], 10, 64)
		p := ph.procs[pid]
		if p == nil {
			p = &proc{comm: s[open+1 : close], ppid: ppid, kthread: flags&0x00200000 != 0} // PF_KTHREAD
			if ph.n == 0 {
				p.first = ut + st
			}
			ph.procs[pid] = p
		}
		p.last = ut + st
		if p.comm == "firecracker" || p.comm == "workcell" {
			if th := threads(e.Name()); len(th) >= len(p.threads) {
				p.threads = th
			}
		}
	}
	ph.n++
}

// threads is each thread of pid as "name=cpus", from /proc/<pid>/task/*/status.
func threads(pid string) (out []string) {
	tasks, _ := os.ReadDir("/proc/" + pid + "/task")
	for _, task := range tasks {
		b, err := os.ReadFile("/proc/" + pid + "/task/" + task.Name() + "/status")
		if err != nil {
			continue
		}
		name, cpus := "", ""
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "Name:\t"); ok {
				name = v
			} else if v, ok := strings.CutPrefix(line, "Cpus_allowed_list:\t"); ok {
				cpus = v
			}
		}
		out = append(out, name+"="+cpus)
	}
	return out
}

// busy is the host's busy ticks from the cpu line of /proc/stat: every field but idle, iowait, guest and guest_nice, as the suite's judge counts them.
func busy() int64 {
	b, _ := os.ReadFile("/proc/stat")
	line, _, _ := strings.Cut(string(b), "\n")
	var sum int64
	for i, s := range strings.Fields(line)[1:] {
		if v, _ := strconv.ParseInt(s, 10, 64); i != 3 && i != 4 && i != 8 && i != 9 {
			sum += v
		}
	}
	return sum
}
