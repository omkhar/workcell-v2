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
	"sync/atomic"
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

var (
	copied = make(chan error, 1) // fuse.Copy's result, once the mount ends
	ring   = &fuse.Ring{}        // the last requests forwarded, dumped to the console
)

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

// stepLimit bounds every command: after it the guest reports what it has and moves on.
const stepLimit = 20 * time.Second

func run(cmd string, args []string) []string {
	switch {
	case cmd == "features":
		return features()
	case cmd == "mount":
		return bounded("mount_stat", func(*progress) []string { return mountFUSE() })
	case cmd == "walk" && len(args) == 3:
		return bounded(args[1]+"_ms", func(p *progress) []string {
			return walk(p, args[0], args[1], time.Duration(atoi(args[2]))*time.Second)
		})
	case cmd == "drop":
		return bounded("drop_caches", func(*progress) []string { return []string{result("drop_caches", dropCaches())} })
	case cmd == "rtt" && len(args) == 2:
		return bounded("rtt_stat_p50_us", func(p *progress) []string { return rtt(p, args[0], atoi(args[1])) })
	case cmd == "cat" && len(args) == 2:
		return bounded("cat_ms", func(p *progress) []string { return cat(p, args[0], atoi(args[1])) })
	case cmd == "write" && len(args) == 3:
		return bounded(args[2]+"_ms", func(p *progress) []string { return write(p, args[0], atoi(args[1]), args[2]) })
	case cmd == "read" && len(args) == 2:
		return bounded("read_mib_s", func(p *progress) []string { return read(p, args[0], args[1]) })
	case cmd == "tmpfs":
		return bounded("walk_tmpfs_ms", tmpfs)
	case cmd == "umount":
		return bounded("umount_ms", func(*progress) []string { return umount() })
	case cmd == "quit":
		ring.Dump(logf)
		return []string{relay.Pair("bye", 1)}
	}
	return []string{relay.Pair("error", "bad command "+cmd+" "+strings.Join(args, " "))}
}

// progress is how far a step got, for its partial report and the console.
type progress struct{ v atomic.Value }

func (p *progress) set(format string, a ...any) { p.v.Store(fmt.Sprintf(format, a...)) }

// bounded runs a step for at most stepLimit. A step that has not returned by then is left
// where it is (a syscall on the mount may never return) and reported as key=partial:<progress>.
func bounded(key string, f func(*progress) []string) []string {
	p := &progress{}
	p.set("started")
	done := make(chan []string, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- []string{relay.Pair("error", fmt.Sprint("panic: ", r))}
			}
		}()
		done <- f(p)
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(stepLimit):
		s := p.v.Load().(string)
		logf("%s partial after %v: %s", key, stepLimit, s)
		ring.Dump(logf)
		return []string{relay.Pair(key, "partial:"+s)}
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func features() []string {
	var out []string
	text, err := kernelConfig()
	out = append(out, relay.Pair("config_gz", errno(err)))
	for _, s := range symbols {
		out = append(out, relay.Pair("cfg_"+s, relay.Config(text, s))) // absent when there is no config
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
	dev := os.NewFile(uintptr(fd), "/dev/fuse") // blocking, so never in the poller: one read(2) is one request
	go func() {
		err := fuse.Copy(dev, wire.New(data, 10*time.Second), ring, logf)
		logf("fuse copy ended: %v", err)
		ring.Dump(logf)
		_ = data.Close()
		copied <- err
	}()
	statted := make(chan error, 1)
	go func() {
		var st unix.Stat_t
		statted <- unix.Stat(mnt, &st)
	}()
	select {
	case err = <-statted:
	case <-time.After(10 * time.Second):
		err = errors.New("timeout")
	}
	return append(out, relay.Pair("mount_ms", ms(time.Since(t0))), relay.Pair("mount_stat", errno(err)))
}

// Every operation on the mount below is a raw syscall. An *os.File would add the descriptor
// to the runtime's epoll set; on a FUSE file that is a FUSE_POLL request, made from the
// runtime with a P held and not marked as a syscall, so this process, which also serves
// the mount, can stop the world around it and never deliver the reply.

// walk lists every directory below root with getdents and lstats every entry, depth first.
// After limit it stops and reports how many entries it reached.
func walk(p *progress, root, key string, limit time.Duration) []string {
	var files, dirs, other int
	t0 := time.Now()
	buf := make([]byte, 64<<10)
	stack := []string{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return []string{relay.Err(key+"_ms", err)}
		}
		var names []string
		for {
			n, err := unix.ReadDirent(fd, buf)
			if err != nil {
				_ = unix.Close(fd)
				return []string{relay.Err(key+"_ms", err)}
			}
			if n <= 0 {
				break
			}
			_, _, names = unix.ParseDirent(buf[:n], -1, names)
		}
		_ = unix.Close(fd)
		for _, name := range names {
			var st unix.Stat_t
			path := dir + "/" + name
			if err := unix.Lstat(path, &st); err != nil {
				return []string{relay.Err(key+"_ms", err)}
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				dirs++
				stack = append(stack, path)
			case unix.S_IFREG:
				files++
			default:
				other++
			}
		}
		p.set("entries=%d", files+dirs+other)
		if limit > 0 && time.Since(t0) > limit {
			logf("%s stopped after %v at %d entries", key, limit, files+dirs+other)
			return []string{relay.Pair(key+"_ms", fmt.Sprintf("partial:%d", files+dirs+other)),
				relay.Pair(key+"_partial_ms", ms(time.Since(t0)))}
		}
	}
	d := time.Since(t0)
	return []string{relay.Pair(key+"_ms", ms(d)), relay.Pair("walk_entries", files+dirs+other),
		relay.Pair("walk_files", files), relay.Pair("walk_dirs", dirs)}
}

func dropCaches() error { return os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0) }

// rtt is n sequential lstat of path, then n fstat of it open: one GETATTR each with timeouts 0.
func rtt(p *progress, path string, n int) []string {
	var us, fus []int64
	var st unix.Stat_t
	for i := range n {
		t0 := time.Now()
		if err := unix.Lstat(path, &st); err != nil {
			return []string{relay.Err("rtt_stat_p50_us", err)}
		}
		us = append(us, time.Since(t0).Microseconds())
		p.set("lstat=%d", i+1)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	logf("rtt lstat=%d open=%s", len(us), errno(err))
	p50, lo, hi := relay.Stats(us)
	out := []string{relay.Pair("rtt_stat_p50_us", p50), relay.Pair("rtt_stat_min_us", lo), relay.Pair("rtt_stat_max_us", hi)}
	if err != nil {
		return append(out, relay.Err("rtt_fstat_p50_us", err))
	}
	defer unix.Close(fd)
	for i := range n {
		t0 := time.Now()
		if err := unix.Fstat(fd, &st); err != nil {
			return append(out, relay.Err("rtt_fstat_p50_us", err))
		}
		fus = append(fus, time.Since(t0).Microseconds())
		p.set("lstat=%d open=ok fstat=%d", n, i+1)
	}
	logf("rtt lstat=%d open=ok fstat=%d", n, len(fus))
	f50, flo, fhi := relay.Stats(fus)
	return append(out, relay.Pair("rtt_fstat_p50_us", f50), relay.Pair("rtt_fstat_min_us", flo), relay.Pair("rtt_fstat_max_us", fhi))
}

// readAll reads fd to its end into h (nil: discard) with buf, and returns the bytes read.
func readAll(fd int, buf []byte, h io.Writer) (int64, error) {
	var total int64
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return total, err
		}
		total += int64(n)
		if h != nil {
			h.Write(buf[:n])
		}
	}
}

// cat opens, reads to the end and closes every file of the first dirs directories.
func cat(p *progress, root string, dirs int) []string {
	buf := make([]byte, 4096)
	n := 0
	t0 := time.Now()
	for d := range dirs {
		for f := range 100 {
			fd, err := unix.Open(fmt.Sprintf("%s/d%02d/f%02d", root, d, f), unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err == nil {
				_, err = readAll(fd, buf, nil)
				_ = unix.Close(fd)
			}
			if err != nil {
				return []string{relay.Err("cat_ms", err)}
			}
			n++
		}
		p.set("files=%d", n)
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

func writeFull(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func write(p *progress, path string, mib int, key string) []string {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return []string{relay.Err(key+"_ms", err)}
	}
	defer unix.Close(fd)
	buf := make([]byte, 1<<20)
	h := sha256.New()
	t0 := time.Now()
	for k := range mib {
		pattern(buf, k)
		h.Write(buf)
		if err := writeFull(fd, buf); err != nil {
			return []string{relay.Err(key+"_ms", err)}
		}
		p.set("mib=%d", k+1)
	}
	dw := time.Since(t0)
	t1 := time.Now()
	err = unix.Fsync(fd)
	ds := time.Since(t1)
	if err != nil {
		return []string{relay.Err(key+"_fsync_ms", err)}
	}
	return []string{relay.Pair(key+"_mib", mib), relay.Pair(key+"_ms", ms(dw)),
		relay.Pair(key+"_mib_s", fmt.Sprintf("%.1f", float64(mib)/dw.Seconds())), relay.Pair(key+"_fsync_ms", ms(ds)),
		relay.Pair(key+"_sha256", hex.EncodeToString(h.Sum(nil)))}
}

func read(p *progress, path, want string) []string {
	if err := dropCaches(); err != nil {
		return []string{relay.Err("read_mib_s", err)}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return []string{relay.Err("read_mib_s", err)}
	}
	defer unix.Close(fd)
	p.set("open=ok")
	h := sha256.New()
	t0 := time.Now()
	n, err := readAll(fd, make([]byte, 1<<20), h)
	d := time.Since(t0)
	if err != nil {
		return []string{relay.Err("read_mib_s", err), relay.Pair("read_bytes", n)}
	}
	return []string{relay.Pair("read_bytes", n), relay.Pair("read_ms", ms(d)),
		relay.Pair("read_mib_s", fmt.Sprintf("%.1f", float64(n)/(1<<20)/d.Seconds())),
		relay.Pair("read_sha256_match", hex.EncodeToString(h.Sum(nil)) == want)}
}

// tmpfs is the baseline: the same tree, walk and write on the guest's own tmpfs.
func tmpfs(p *progress) []string {
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
	out = append(out, walk(p, root, "walk_tmpfs", 0)[0])
	w := write(p, "/tmp/big.bin", 100, "write_tmpfs")
	_ = os.Remove("/tmp/big.bin")
	_ = os.RemoveAll(root)
	for _, s := range w {
		if strings.HasPrefix(s, "write_tmpfs_mib_s=") || strings.Contains(s, "=err:") {
			out = append(out, s)
		}
	}
	return out
}

// umount unmounts, lazily if something still holds the mount, and waits for the copier.
func umount() []string {
	t0 := time.Now()
	err := unix.Unmount(mnt, 0)
	how := errno(err)
	if errors.Is(err, unix.EBUSY) {
		how = "EBUSY,detach:" + errno(unix.Unmount(mnt, unix.MNT_DETACH))
	}
	out := []string{relay.Pair("umount", how), relay.Pair("umount_ms", ms(time.Since(t0)))}
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
