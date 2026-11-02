// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// forkProbe forks args[0] processes at once, holds them, and reaps them. Each
// child waits for one byte on a pipe and exits; it makes raw system calls
// only, since a forked copy of a Go process can call nothing else safely, and
// it dies with the probe.
func forkProbe(args []string) Result {
	if len(args) != 1 {
		return Result{Status: "error", Detail: "want count"}
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
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
		if pid == 0 { // the child
			unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0)
			unix.RawSyscall(unix.SYS_READ, uintptr(pipe[0]), uintptr(unsafe.Pointer(&buf)), 1)
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		}
		made++
	}
	time.Sleep(hold)
	release := make([]byte, made)
	unix.Write(pipe[1], release) // one byte per child; a 2000-byte write fits the pipe whole
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
