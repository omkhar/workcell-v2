// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && cgo

package suite

/*
#include <mach/mach.h>
#include <mach/mach_host.h>

// freePages fills pages with the host's free, speculative and purgeable
// page counts: what it can hand out at once, as MemAvailable is on Linux.
// The port that mach_host_self hands out is given back, since the judges
// sample often.
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
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// The host as the judge sees it, from Mach and sysctl: the memory the I12
// flood row reads and the processes the I11 rows kill and count. The other
// load figures serve I10 rows not enforced on a Mac: an error, never a pass.

// hostMemAvailable is the memory the host can hand out at once, in bytes.
func hostMemAvailable() (int64, error) {
	var pages [3]C.ulonglong
	if kr := C.freePages(&pages[0]); kr != C.KERN_SUCCESS {
		return 0, fmt.Errorf("host_statistics64: kern_return %d", int(kr))
	}
	return int64(pages[0]+pages[1]+pages[2]) * int64(os.Getpagesize()), nil
}

var errLinuxOnly = errors.New("reading that host figure is Linux only")

func hostProcs() (int64, error)    { return 0, errLinuxOnly }
func hostFiles() (int64, error)    { return 0, errLinuxOnly }
func hostBusy() (int64, error)     { return 0, errLinuxOnly }
func hostDiskFree() (int64, error) { return 0, errLinuxOnly }

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
	return below(children, pid), nil
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
