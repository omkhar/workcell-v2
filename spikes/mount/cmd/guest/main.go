// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command guest is PID 1 of the mount spike's microVM. It dials the host on vsock
// port 5000 and answers one key=value line per command line the host sends. "mount"
// mounts FUSE on /workspace and passes every request through, unparsed, to the host on
// vsock port 5002 (fuse.Copy); the other commands measure that mount and the guest's
// own tmpfs. It never returns: a PID 1 that exits is a kernel panic.
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"github.com/omkhar/workcell/v2/spikes/mount/fuse"
	"github.com/omkhar/workcell/v2/spikes/netpath/relay"
	"golang.org/x/sys/unix"
)

const (
	mnt     = "/workspace"
	options = "fd=%d,rootmode=40000,user_id=0,group_id=0,max_read=61440"
)

var symbols = []string{"FUSE_FS", "VIRTIO_FS", "OVERLAY_FS", "NFS_FS", "NFS_V3", "NFS_V4", "NET_9P", "9P_FS",
	"IKCONFIG_PROC", "VSOCKETS", "VIRTIO_VSOCKETS", "TMPFS"}

var copied = make(chan error, 1) // fuse.Copy's result, once the mount ends

func main() {
	for _, d := range []string{"/dev", "/proc", "/sys", "/tmp", mnt} {
		_ = os.MkdirAll(d, 0o755)
	}
	mount("devtmpfs", "/dev", "devtmpfs", "")
	if fd, err := unix.Open("/dev/console", unix.O_RDWR|unix.O_NOCTTY, 0); err == nil {
		_ = unix.Dup3(fd, 1, 0)
		_ = unix.Dup3(fd, 2, 0)
	}
	mount("proc", "/proc", "proc", "")
	mount("sysfs", "/sys", "sysfs", "")
	mount("tmpfs", "/tmp", "tmpfs", "size=600m")
	fmt.Fprintln(os.Stderr, "guest:", serve())
	for {
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART) // reboot=k: Firecracker exits
		time.Sleep(time.Second)
	}
}

func mount(src, dir, fstype, data string) {
	if err := unix.Mount(src, dir, fstype, 0, data); err != nil && !errors.Is(err, unix.EBUSY) {
		fmt.Fprintln(os.Stderr, "guest: mount", dir, err)
	}
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "guest: "+format+"\n", a...) }

// dial connects to the host (CID 2) on port, retrying while the device probes. The
// socket is non-blocking so that deadlines work on it.
func dial(port uint32, retry time.Duration) (*os.File, error) {
	var err error
	for end := time.Now().Add(retry); ; time.Sleep(20 * time.Millisecond) {
		var fd int
		if fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
			if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err == nil {
				if err = unix.SetNonblock(fd, true); err == nil {
					return os.NewFile(uintptr(fd), "vsock"), nil
				}
			}
			_ = unix.Close(fd)
		}
		if !time.Now().Before(end) {
			return nil, err
		}
	}
}

func serve() error {
	c, err := dial(relay.Control, 5*time.Second)
	if err != nil {
		return err
	}
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if _, err := io.WriteString(c, relay.Join(run(f[0], f[1:]))); err != nil || f[0] == "quit" {
			return err
		}
	}
}

func run(cmd string, args []string) (out []string) {
	defer func() {
		if r := recover(); r != nil {
			out = []string{relay.Pair("error", fmt.Sprint("panic: ", r))}
		}
	}()
	switch {
	case cmd == "features":
		return features()
	case cmd == "mount":
		return mountFUSE()
	case cmd == "walk" && len(args) == 2:
		return walk(args[0], args[1])
	case cmd == "drop":
		return []string{result("drop_caches", dropCaches())}
	case cmd == "rtt" && len(args) == 2:
		return rtt(args[0], atoi(args[1]))
	case cmd == "cat" && len(args) == 2:
		return cat(args[0], atoi(args[1]))
	case cmd == "write" && len(args) == 3:
		return write(args[0], atoi(args[1]), args[2])
	case cmd == "read" && len(args) == 2:
		return read(args[0], args[1])
	case cmd == "tmpfs":
		return tmpfs()
	case cmd == "umount":
		return umount()
	case cmd == "quit":
		return []string{relay.Pair("bye", 1)}
	}
	return []string{relay.Pair("error", "bad command "+cmd+" "+strings.Join(args, " "))}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func features() []string {
	var out []string
	text, err := kernelConfig()
	for _, s := range symbols {
		if err != nil {
			out = append(out, relay.Err("cfg_"+s, err))
		} else {
			out = append(out, relay.Pair("cfg_"+s, relay.Config(text, s)))
		}
	}
	var u unix.Utsname
	_ = unix.Uname(&u)
	fsys, _ := os.ReadFile("/proc/filesystems")
	return append(out, relay.Pair("kernel", unix.ByteSliceToString(u.Release[:])),
		relay.Pair("proc_fs_fuse", strings.Contains(string(fsys), "\tfuse\n")))
}

func kernelConfig() (string, error) {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return "", err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(z)
	return string(b), err
}

// mountFUSE opens /dev/fuse (making the node if devtmpfs has none), dials the host's
// FUSE port, mounts, starts the copier and waits for the first stat of the mount, which
// waits for the INIT handshake.
func mountFUSE() []string {
	var out []string
	_, err := os.Stat("/dev/fuse")
	out = append(out, relay.Pair("fuse_dev", errno(err)))
	if errors.Is(err, fs.ErrNotExist) {
		out = append(out, relay.Pair("fuse_mknod", errno(unix.Mknod("/dev/fuse", unix.S_IFCHR|0o666, int(unix.Mkdev(10, 229))))))
	}
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	out = append(out, relay.Pair("fuse_open", errno(err)))
	var data *os.File
	if err == nil {
		data, err = dial(fuse.Port, 2*time.Second)
		out = append(out, relay.Pair("data_dial", errno(err)))
	}
	t0 := time.Now()
	err = unix.Mount("workcell", mnt, "fuse", unix.MS_NOSUID|unix.MS_NODEV, fmt.Sprintf(options, fd))
	out = append(out, relay.Pair("mount", errno(err)))
	if err != nil || data == nil {
		return out
	}
	dev := os.NewFile(uintptr(fd), "/dev/fuse") // blocking: one read(2) is one request
	go func() {
		err := fuse.Copy(dev, wire.New(data, 10*time.Second), logf)
		logf("fuse copy ended: %v", err)
		_ = data.Close()
		copied <- err
	}()
	statted := make(chan error, 1)
	go func() { _, err := os.Stat(mnt); statted <- err }()
	select {
	case err = <-statted:
	case <-time.After(10 * time.Second):
		err = errors.New("timeout")
	}
	return append(out, relay.Pair("mount_ms", ms(time.Since(t0))), relay.Pair("mount_stat", errno(err)))
}

// walk is filepath.WalkDir plus os.Lstat of every entry below root.
func walk(root, key string) []string {
	var files, dirs, other int
	t0 := time.Now()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == root {
			return err
		}
		fi, err := os.Lstat(path)
		switch {
		case err != nil:
			return err
		case fi.IsDir():
			dirs++
		case fi.Mode().IsRegular():
			files++
		default:
			other++
		}
		return nil
	})
	d := time.Since(t0)
	if err != nil {
		return []string{relay.Err(key+"_ms", err)}
	}
	return []string{relay.Pair(key+"_ms", ms(d)), relay.Pair("walk_entries", files+dirs+other),
		relay.Pair("walk_files", files), relay.Pair("walk_dirs", dirs)}
}

func dropCaches() error { return os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0) }

// rtt is n sequential Lstat of path, then n fstat of it open: one GETATTR each with timeouts 0.
func rtt(path string, n int) []string {
	var us, fus []int64
	for range n {
		t0 := time.Now()
		if _, err := os.Lstat(path); err != nil {
			return []string{relay.Err("rtt_stat_p50_us", err)}
		}
		us = append(us, time.Since(t0).Microseconds())
	}
	f, err := os.Open(path)
	if err != nil {
		return []string{relay.Err("rtt_stat_p50_us", err)}
	}
	defer f.Close()
	for range n {
		t0 := time.Now()
		if _, err := f.Stat(); err != nil {
			return []string{relay.Err("rtt_fstat_p50_us", err)}
		}
		fus = append(fus, time.Since(t0).Microseconds())
	}
	p50, lo, hi := relay.Stats(us)
	f50, flo, fhi := relay.Stats(fus)
	return []string{relay.Pair("rtt_stat_p50_us", p50), relay.Pair("rtt_stat_min_us", lo), relay.Pair("rtt_stat_max_us", hi),
		relay.Pair("rtt_fstat_p50_us", f50), relay.Pair("rtt_fstat_min_us", flo), relay.Pair("rtt_fstat_max_us", fhi)}
}

// cat opens, reads to the end and closes every file of the first dirs directories.
func cat(root string, dirs int) []string {
	buf := make([]byte, 4096)
	n := 0
	t0 := time.Now()
	for d := range dirs {
		for f := range 100 {
			fh, err := os.Open(filepath.Join(root, fmt.Sprintf("d%02d/f%02d", d, f)))
			if err == nil {
				for err == nil {
					_, err = fh.Read(buf)
				}
				_ = fh.Close()
			}
			if err != io.EOF {
				return []string{relay.Err("cat_ms", err)}
			}
			n++
		}
	}
	dt := time.Since(t0)
	return []string{relay.Pair("cat_files", n), relay.Pair("cat_ms", ms(dt)),
		relay.Pair("cat_per_file_us", dt.Microseconds()/int64(max(n, 1)))}
}

// pattern fills the k-th MiB of the test file; the host checks the digest.
func pattern(buf []byte, k int) {
	for j := range buf {
		buf[j] = byte(j*7 + k*13 + j>>9)
	}
}

func write(path string, mib int, key string) []string {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return []string{relay.Err(key+"_ms", err)}
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	h := sha256.New()
	t0 := time.Now()
	for k := range mib {
		pattern(buf, k)
		h.Write(buf)
		if _, err := f.Write(buf); err != nil {
			return []string{relay.Err(key+"_ms", err)}
		}
	}
	dw := time.Since(t0)
	t1 := time.Now()
	err = f.Sync()
	ds := time.Since(t1)
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		return []string{relay.Err(key+"_fsync_ms", err)}
	}
	return []string{relay.Pair(key+"_mib", mib), relay.Pair(key+"_ms", ms(dw)),
		relay.Pair(key+"_mib_s", fmt.Sprintf("%.1f", float64(mib)/dw.Seconds())), relay.Pair(key+"_fsync_ms", ms(ds)),
		relay.Pair(key+"_sha256", hex.EncodeToString(h.Sum(nil)))}
}

func read(path, want string) []string {
	if err := dropCaches(); err != nil {
		return []string{relay.Err("read_mib_s", err)}
	}
	f, err := os.Open(path)
	if err != nil {
		return []string{relay.Err("read_mib_s", err)}
	}
	defer f.Close()
	h := sha256.New()
	t0 := time.Now()
	n, err := io.CopyBuffer(h, struct{ io.Reader }{f}, make([]byte, 1<<20))
	d := time.Since(t0)
	if err != nil {
		return []string{relay.Err("read_mib_s", err)}
	}
	return []string{relay.Pair("read_bytes", n), relay.Pair("read_ms", ms(d)),
		relay.Pair("read_mib_s", fmt.Sprintf("%.1f", float64(n)/(1<<20)/d.Seconds())),
		relay.Pair("read_sha256_match", hex.EncodeToString(h.Sum(nil)) == want)}
}

// tmpfs is the baseline: the same tree and the same write on the guest's own tmpfs.
func tmpfs() []string {
	root := "/tmp/tree"
	t0 := time.Now()
	for d := range 100 {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", d))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return []string{relay.Err("tree_tmpfs_ms", err)}
		}
		for f := range 100 {
			name := fmt.Sprintf("d%02d/f%02d", d, f)
			if err := os.WriteFile(filepath.Join(root, name), fmt.Appendf(nil, "%15s\n", name), 0o644); err != nil {
				return []string{relay.Err("tree_tmpfs_ms", err)}
			}
		}
	}
	out := []string{relay.Pair("tree_tmpfs_ms", ms(time.Since(t0)))}
	out = append(out, walk(root, "walk_tmpfs")[0])
	w := write("/tmp/big.bin", 100, "write_tmpfs")
	_ = os.Remove("/tmp/big.bin")
	_ = os.RemoveAll(root)
	for _, p := range w {
		if strings.HasPrefix(p, "write_tmpfs_mib_s=") || strings.Contains(p, "=err:") {
			out = append(out, p)
		}
	}
	return out
}

func umount() []string {
	t0 := time.Now()
	err := unix.Unmount(mnt, 0)
	d := time.Since(t0)
	out := []string{relay.Pair("umount", errno(err)), relay.Pair("umount_ms", ms(d))}
	select {
	case err := <-copied:
		return append(out, relay.Pair("copier_exit", errno(err)))
	case <-time.After(5 * time.Second):
		return append(out, relay.Pair("copier_exit", "timeout"))
	}
}

func result(key string, err error) string {
	if err != nil {
		return relay.Pair(key, "err:"+errno(err))
	}
	return relay.Pair(key, "ok")
}

// errno names the error number in err, or says "ok" for no error.
func errno(err error) string {
	var e syscall.Errno
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &e) && unix.ErrnoName(e) != "":
		return unix.ErrnoName(e)
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	return err.Error()
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
