// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && cgo

package suite

/*
#include <mach/mach.h>
#include <mach/mach_host.h>

// cpuTicks fills ticks with the host's CPU ticks since boot, summed over
// every CPU, in CPU_STATE_* order: user, system, idle, nice. The port that
// mach_host_self hands out is given back, since the judges sample often.
static kern_return_t cpuTicks(natural_t ticks[CPU_STATE_MAX]) {
	host_cpu_load_info_data_t info;
	mach_msg_type_number_t n = HOST_CPU_LOAD_INFO_COUNT;
	host_t host = mach_host_self();
	kern_return_t kr = host_statistics(host, HOST_CPU_LOAD_INFO, (host_info_t)&info, &n);
	mach_port_deallocate(mach_task_self(), host);
	for (int i = 0; kr == KERN_SUCCESS && i < CPU_STATE_MAX; i++) ticks[i] = info.cpu_ticks[i];
	return kr;
}

// freePages fills pages with the host's free, speculative and purgeable
// page counts: what it can hand out at once, as MemAvailable is on Linux.
static kern_return_t freePages(unsigned long long pages[3]) {
	vm_statistics64_data_t s;
	mach_msg_type_number_t n = HOST_VM_INFO64_COUNT;
	host_t host = mach_host_self();
	kern_return_t kr = host_statistics64(host, HOST_VM_INFO64, (host_info_t)&s, &n);
	mach_port_deallocate(mach_task_self(), host);
	if (kr == KERN_SUCCESS) {
		pages[0] = s.free_count;
		pages[1] = s.speculative_count;
		pages[2] = s.purgeable_count;
	}
	return kr;
}
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The host as the judge sees it, from Mach and sysctl, the same figures the
// Linux judges read from /proc. A guest's load must not show here.

// hostProcs counts the host's processes.
func hostProcs() (int64, error) {
	ps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	return int64(len(ps)), err
}

// hostMemAvailable is the memory the host can hand out at once, in bytes.
func hostMemAvailable() (int64, error) {
	var pages [3]C.ulonglong
	if kr := C.freePages(&pages[0]); kr != C.KERN_SUCCESS {
		return 0, fmt.Errorf("host_statistics64: kern_return %d", int(kr))
	}
	return int64(pages[0]+pages[1]+pages[2]) * int64(os.Getpagesize()), nil
}

// hostFiles is the host's count of open file handles (kern.num_files).
func hostFiles() (int64, error) {
	n, err := unix.SysctlUint32("kern.num_files")
	return int64(n), err
}

// hostBusy is the host's CPU time spent on anything but idle, in clock
// ticks of 1/100 s, summed over every CPU.
func hostBusy() (int64, error) {
	var ticks [C.CPU_STATE_MAX]C.natural_t
	if kr := C.cpuTicks(&ticks[0]); kr != C.KERN_SUCCESS {
		return 0, fmt.Errorf("host_statistics: kern_return %d", int(kr))
	}
	return int64(ticks[C.CPU_STATE_USER]) + int64(ticks[C.CPU_STATE_SYSTEM]) + int64(ticks[C.CPU_STATE_NICE]), nil
}

// hostDiskFree sums the free bytes of every local, writable filesystem the
// host has mounted, each APFS container counted once.
func hostDiskFree() (int64, error) {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return 0, err
	}
	mounts := make([]unix.Statfs_t, n)
	if n, err = unix.Getfsstat(mounts, unix.MNT_NOWAIT); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	var free int64
	for _, st := range mounts[:n] {
		key := container(unix.ByteSliceToString(st.Mntfromname[:]))
		if st.Flags&unix.MNT_RDONLY != 0 || st.Flags&unix.MNT_LOCAL == 0 || st.Blocks == 0 || seen[key] {
			continue
		}
		seen[key] = true
		free += int64(st.Bavail) * int64(st.Bsize)
	}
	return free, nil
}

// container names what a volume's free space belongs to. The APFS volumes
// of one container, /dev/diskNsM and a snapshot /dev/diskNsMsK, share it,
// so all of them map to /dev/diskN; any other device is its own.
func container(dev string) string {
	rest, ok := strings.CutPrefix(dev, "/dev/disk")
	if !ok {
		return dev
	}
	if i := strings.IndexByte(rest, 's'); i >= 0 {
		rest = rest[:i]
	}
	return "/dev/disk" + rest
}

// szomb is the state of a process that exited and has not been reaped
// (sys/proc.h SZOMB).
const szomb = 5

// processGroup is the process group of pid.
func processGroup(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("kern.proc.pid %d: %w", pid, err)
	}
	return int(kp.Eproc.Pgid), nil
}

// descendants lists every process below pid, children first, as the tree
// stands now.
func descendants(pid int) ([]int, error) {
	ps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	children := map[int][]int{}
	for _, kp := range ps {
		children[int(kp.Eproc.Ppid)] = append(children[int(kp.Eproc.Ppid)], int(kp.Proc.P_pid))
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
	ps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	var out []int
	for _, kp := range ps {
		if int(kp.Eproc.Pgid) == pgid {
			out = append(out, int(kp.Proc.P_pid))
		}
	}
	return out, nil
}

// helperAlive says whether the process runs on the host: the kernel knows
// it and it is not a zombie.
func helperAlive(pid int) (bool, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return false, nil
		}
		return false, fmt.Errorf("kern.proc.pid %d: %w", pid, err)
	}
	return kp.Proc.P_stat != szomb, nil
}
