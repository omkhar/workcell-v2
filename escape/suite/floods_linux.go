// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// forkProbe runs itself again as a child that forks args[1] processes at once, holds them, and reaps them, so that a guest which kills the child still reports.
// The child marks itself, and so every process it forks, as the first to kill when memory runs out, so that the parent survives to report. Each forked process
// waits for one byte on a pipe and exits, with raw system calls only, since a forked copy of a Go process can call nothing else safely. Such a copy costs the
// kernel about 190 KiB, mostly page tables, which is what bounds the count.
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

// emulationProbe loads, for args[0] seconds at once, what a VMM serves off the vCPU thread: the first virtio block device, read with O_DIRECT a MiB a
// request; the host end of the relay at args[1], by connect-then-close, each a vsock request and an accept and a header read on the host; and, as the
// arm the cap does hold, the serial console, whose every byte is an exit of the vCPU itself. Off the product's VM, which the harness names by a vsock
// address, a file on disk and /dev/null stand in for the device and the console: the session's own are not the test's (S12). Each arm runs to the
// deadline on its own; one that blocks is left behind, so the report is on time.
func emulationProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want seconds and relay address"}
	}
	v, r := ints(args[:1], 1, "seconds")
	if r.Status != "" {
		return r
	}
	peer, err := parsePeer(args[1])
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	deadline := time.Now().Add(time.Duration(v[0]) * time.Second)
	var read, connects, refused, wrote atomic.Int64
	disks, consoles := []string{"/dev/null"}, []string{"/dev/null"}
	if peer.vsock {
		disks, _ = filepath.Glob("/dev/vd?")
		consoles = []string{"/dev/ttyS0", "/dev/hvc0"}
	} else if f, _, err := onDisk(); err == nil { // the stand-in: a file the size of the disk cap, read past the page cache
		fill(f, capped.DiskMiB)
		disks = []string{f.Name()}
		defer os.Remove(f.Name())
		f.Close()
	}
	disk, dfd, derr := firstOpen(disks, os.O_RDONLY|unix.O_DIRECT)
	if derr != nil { // a filesystem without O_DIRECT: the arm reads through the cache
		disk, dfd, derr = firstOpen(disks, os.O_RDONLY)
	}
	console, cfd, cerr := firstOpen(consoles, os.O_WRONLY)
	if derr == nil {
		go func() {
			raw := make([]byte, 2<<20)
			off := 4096 - int(uintptr(unsafe.Pointer(&raw[0]))%4096)
			buf := raw[off : off+1<<20]
			size, _ := unix.Seek(dfd, 0, unix.SEEK_END)
			for at := int64(0); time.Now().Before(deadline); at += int64(len(buf)) {
				if at+int64(len(buf)) > size {
					at = 0
				}
				n, err := unix.Pread(dfd, buf, at)
				if err != nil || n == 0 {
					break
				}
				read.Add(int64(n))
			}
		}()
	}
	go func() {
		for time.Now().Before(deadline) {
			c, err := dialChannel(args[1])
			if err != nil {
				refused.Add(1)
				continue
			}
			c.close()
			connects.Add(1)
		}
	}()
	if cerr == nil {
		go func() {
			zero := make([]byte, 4096)
			for time.Now().Before(deadline) {
				n, err := unix.Write(cfd, zero)
				if err != nil {
					break
				}
				wrote.Add(int64(n))
			}
		}()
	}
	time.Sleep(time.Until(deadline))
	return Result{Status: "tried", Detail: fmt.Sprintf("disk=%s:%dMiB(%s) relay=%d+%d-refused console=%s:%dMiB(%s) in %ds",
		disk, read.Load()>>20, status(derr), connects.Load(), refused.Load(), console, wrote.Load()>>20, status(cerr), v[0])}
}

// firstOpen opens the first of the paths that opens with flag, and says which; with none, the last error.
func firstOpen(paths []string, flag int) (path string, fd int, err error) {
	err = unix.ENOENT
	for _, path = range paths {
		if fd, err = unix.Open(path, flag|unix.O_CLOEXEC, 0); err == nil {
			return path, fd, nil
		}
	}
	return "", -1, err
}
