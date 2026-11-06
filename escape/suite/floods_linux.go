// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// forkProbe runs itself again as a child that forks args[1] processes at
// once, holds them, and reaps them, so that a guest which kills the child
// still reports. The child marks itself, and so every process it forks, as
// the first to kill when memory runs out, so that the parent survives to
// report. Each forked process waits for one byte on a pipe and exits, with
// raw system calls only, since a forked copy of a Go process can call nothing
// else safely. Such a copy costs the kernel about 190 KiB, mostly page
// tables, which is what bounds the count.
func forkProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want parent|child and count"}
	}
	n, err := strconv.Atoi(args[1])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	if args[0] != "child" {
		return asChild(os.Args[1], "child", args[1], "forking "+args[1]+" processes")
	}
	os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0) // best effort; the flood is the same without
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		return Result{Status: "error", Detail: "pipe: " + err.Error()}
	}
	var buf [1]byte
	made := 0
	var errno unix.Errno
	for made < n {
		pid, _, e := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
		if e != 0 {
			errno = e
			break
		}
		if pid == 0 { // the forked process
			unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0)
			unix.RawSyscall(unix.SYS_READ, uintptr(pipe[0]), uintptr(unsafe.Pointer(&buf)), 1)
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		}
		made++
	}
	time.Sleep(hold)
	release := make([]byte, made)
	unix.Write(pipe[1], release) // one byte per process; the write fits the pipe whole
	reaped := 0
	for reaped < made {
		if _, err := unix.Wait4(-1, nil, 0, nil); err != nil {
			break
		}
		reaped++
	}
	unix.Close(pipe[0])
	unix.Close(pipe[1])
	detail := fmt.Sprintf("forked=%d of %d reaped=%d", made, n, reaped)
	if errno != 0 {
		detail += " err=" + errno.Error()
	}
	return Result{Status: "tried", Detail: detail}
}

// memoryBacked says whether the directory lies on a filesystem held in memory.
func memoryBacked(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return true // unknown is no disk
	}
	switch st.Type {
	case unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.HUGETLBFS_MAGIC:
		return true
	}
	return false
}
