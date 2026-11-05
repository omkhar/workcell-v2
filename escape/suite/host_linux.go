// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The host as the judge sees it, from /proc. A guest's load must not show here.

// hostProcs counts the host's processes.
func hostProcs() (int64, error) {
	es, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range es {
		if c := e.Name()[0]; c >= '0' && c <= '9' {
			n++
		}
	}
	return n, nil
}

// hostMemAvailable is the host's MemAvailable, in bytes.
func hostMemAvailable() (int64, error) {
	return procField("/proc/meminfo", "MemAvailable:", 1024)
}

// hostFiles is the host's count of open file handles (fs.file-nr).
func hostFiles() (int64, error) {
	return procField("/proc/sys/fs/file-nr", "", 1)
}

// hostBusy is the host's CPU time spent on anything but idle and iowait, in
// clock ticks, summed over every CPU.
func hostBusy() (int64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "cpu ") {
			return busyTicks(line)
		}
	}
	return 0, errors.New("/proc/stat has no cpu line")
}

// busyTicks sums the columns of a /proc/stat cpu line that are both busy and
// counted once: user nice system irq softirq steal, skipping idle, iowait,
// and guest and guest_nice, which user and nice already hold.
func busyTicks(line string) (int64, error) {
	fields := strings.Fields(line)
	if len(fields) < 8 {
		return 0, fmt.Errorf("short cpu line %q", line)
	}
	var busy int64
	for i, s := range fields[1:] {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		if i != 3 && i != 4 && i != 8 && i != 9 { // idle, iowait, guest, guest_nice
			busy += v
		}
	}
	return busy, nil
}

// hostDiskFree sums the free bytes of every real filesystem the host has
// mounted, each counted once.
func hostDiskFree() (int64, error) {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	seen := map[unix.Fsid]bool{}
	var free int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		var st unix.Statfs_t
		if unix.Statfs(fields[1], &st) != nil || st.Blocks == 0 || seen[st.Fsid] {
			continue
		}
		seen[st.Fsid] = true
		free += int64(st.Bavail) * int64(st.Bsize)
	}
	return free, nil
}

// helperAlive says whether the process runs on the host: it has a /proc
// entry and is neither a zombie nor dead.
func helperAlive(pid int) (bool, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	i := bytes.LastIndexByte(b, ')') // the state follows the comm, which may hold spaces
	if i < 0 || i+2 >= len(b) {
		return false, fmt.Errorf("/proc/%d/stat is malformed", pid)
	}
	return b[i+2] != 'Z' && b[i+2] != 'X', nil
}

// processGroup is the process group of pid.
func processGroup(pid int) (int, error) {
	f, err := statFields(pid)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(f[2])
}

// descendants lists every process below pid, children first, as the tree
// stands now.
func descendants(pid int) ([]int, error) {
	children := map[int][]int{}
	if err := eachProcess(func(p, ppid, _ int) { children[ppid] = append(children[ppid], p) }); err != nil {
		return nil, err
	}
	var out []int
	queue := []int{pid}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		out = append(out, children[p]...)
		queue = append(queue, children[p]...)
	}
	return out, nil
}

// groupMembers lists the processes of the group pgid.
func groupMembers(pgid int) ([]int, error) {
	var out []int
	err := eachProcess(func(p, _, g int) {
		if g == pgid {
			out = append(out, p)
		}
	})
	return out, err
}

// eachProcess calls f with the pid, parent and group of every process.
func eachProcess(f func(pid, ppid, pgid int)) error {
	es, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range es {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fields, err := statFields(pid)
		if err != nil {
			continue // gone between the listing and the read
		}
		ppid, err1 := strconv.Atoi(fields[1])
		pgid, err2 := strconv.Atoi(fields[2])
		if err1 == nil && err2 == nil {
			f(pid, ppid, pgid)
		}
	}
	return nil
}

// statFields is /proc/pid/stat after the comm, which may hold spaces: the
// state, the parent, the group and the rest.
func statFields(pid int) ([]string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return nil, fmt.Errorf("/proc/%d/stat is malformed", pid)
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 3 {
		return nil, fmt.Errorf("/proc/%d/stat is malformed", pid)
	}
	return f, nil
}

// procField reads the first number after the label (or the first number of
// the file, when label is "") and scales it.
func procField(path, label string, scale int64) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := string(b)
	if label != "" {
		_, after, ok := strings.Cut(s, label)
		if !ok {
			return 0, fmt.Errorf("%s has no %s", path, label)
		}
		s = after
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, fmt.Errorf("%s has no number after %q", path, label)
	}
	v, err := strconv.ParseInt(fields[0], 10, 64)
	return v * scale, err
}
