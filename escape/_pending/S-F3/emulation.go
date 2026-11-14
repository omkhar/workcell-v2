// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Parked under S4 until the fix unit S-F3 lands. S-F3 moves the two functions below back to the end of escape/suite/floods_linux.go (whose imports
// gain path/filepath and sync/atomic again), adds the non-Linux stub `func emulationProbe([]string) Result { return linuxOnly("emulation") }` to
// escape/suite/files_other.go beside forkProbe's, and adds this row to All in escape/suite/tests.go, directly after the row named cpu-flood, under
// the comment "The same cap, loaded off the vCPU: the devices a VMM serves on host threads of its own (virtio-blk, vsock), and the console as the arm it does hold.":
//
//	{ID: "I10", Name: "device-cpu-flood", Probe: emulationProbe, Host: cpuJudge(true), Want: capped},

package suite

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

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
