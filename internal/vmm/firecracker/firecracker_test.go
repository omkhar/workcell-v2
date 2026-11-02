// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// The same inputs, URLs and digests as the U-101 spike (spikes/fcch).
const (
	fcURL     = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	fcSHA256  = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	fcMember  = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	kernelURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
	kernelSHA = "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"

	port      = 5000 // testdata/guest dials this
	helperEnv = "FIRECRACKER_TEST_HELPER"
	bootLimit = 10 * time.Second
)

func TestConfig(t *testing.T) {
	base := vmm.Config{Binary: "/b/fc", Kernel: "/k", CPUs: 2, MemoryMiB: 512, CID: 3, Dir: "/d"}
	initrd := base
	initrd.Initrd = "/i"
	disks := base
	disks.Image, disks.Workspace, disks.Cmdline = "/root.img", "/work.img", "init=/sbin/init"
	tests := []struct {
		name string
		cfg  vmm.Config
		want string
	}{
		{"initrd only", initrd, `{"boot-source":{"kernel_image_path":"/k","initrd_path":"/i",` +
			`"boot_args":"console=ttyS0 reboot=k panic=-1 pci=off quiet"},"drives":[],` +
			`"machine-config":{"vcpu_count":2,"mem_size_mib":512,"smt":false},"vsock":{"guest_cid":3,"uds_path":"/d/vsock"}}`},
		{"disks and cmdline", disks, `{"boot-source":{"kernel_image_path":"/k",` +
			`"boot_args":"console=ttyS0 reboot=k panic=-1 pci=off quiet init=/sbin/init"},"drives":[` +
			`{"drive_id":"root","path_on_host":"/root.img","is_root_device":true,"is_read_only":true},` +
			`{"drive_id":"workspace","path_on_host":"/work.img","is_root_device":false,"is_read_only":false}],` +
			`"machine-config":{"vcpu_count":2,"mem_size_mib":512,"smt":false},"vsock":{"guest_cid":3,"uds_path":"/d/vsock"}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encode(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("encode:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
	if got, want := args("/d/firecracker.json"), []string{"--no-api", "--config-file", "/d/firecracker.json"}; !slices.Equal(got, want) {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// inputs are the pinned binary and kernel, and the initramfs built from testdata/guest.
type inputs struct{ binary, kernel, initrd string }

func TestFirecracker(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the pinned Firecracker and kernel are linux/amd64 builds")
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
	in := fetch(t)
	ctx := context.Background()

	t.Run("check", func(t *testing.T) {
		if err := New(vmm.Config{Binary: in.binary}).Check(ctx); err != nil {
			t.Fatalf("Check on this host: %v", err)
		}
		missing := filepath.Join(t.TempDir(), "missing")
		if err := New(vmm.Config{Binary: missing}).Check(ctx); err == nil {
			t.Fatal("Check passed with a missing binary")
		} else {
			t.Logf("vmm check missing_binary=%q", err)
		}
	})

	t.Run("boot-and-stop", func(t *testing.T) {
		m, conn, _, bootMS := boot(t, in)
		short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if err := m.Wait(short); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Wait with an ended context: %v", err)
		}
		if gone(m.cmd.Process.Pid) {
			t.Fatal("Wait with an ended context killed the guest")
		}
		t0 := time.Now()
		_ = conn.Close() // the guest reboots on EOF
		wait, cancel := context.WithTimeout(ctx, bootLimit)
		defer cancel()
		if err := m.Wait(wait); err != nil {
			t.Fatalf("Wait after the guest's shutdown: %v", err)
		}
		t.Logf("vmm boot_ms=%d teardown_ms=%d", bootMS, time.Since(t0).Milliseconds())
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("force-kill", func(t *testing.T) {
		m, conn, dir, _ := boot(t, in)
		defer conn.Close()
		if err := os.WriteFile(filepath.Join(dir, "keep"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Listen(port + 1); err == nil {
			t.Fatal("Listen after Start was accepted")
		}
		if err := m.Start(ctx); err == nil {
			t.Fatal("a second Start was accepted")
		}
		pid := m.cmd.Process.Pid
		t0 := time.Now()
		if err := m.Kill(); err != nil {
			t.Fatalf("Kill: %v", err)
		}
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := m.Wait(wait)
		if err == nil || !strings.Contains(err.Error(), "killed") {
			t.Fatalf("Wait after Kill = %v, want an error that says killed", err)
		}
		t.Logf("vmm kill_ms=%d wait=%q", time.Since(t0).Milliseconds(), err)
		if !gone(pid) {
			t.Fatalf("firecracker pid %d is still there after Kill and Wait", pid)
		}
		if err := m.Kill(); err != nil {
			t.Fatalf("second Kill: %v", err)
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if left := list(t, dir); !slices.Equal(left, []string{"keep"}) {
			t.Fatalf("after Close, Dir holds %q, want only the file the test put there", left)
		}
	})

	t.Run("supervisor-killed", func(t *testing.T) {
		dir := shortDir(t)
		helper := exec.Command(os.Args[0], "-test.run=^TestHelper$")
		helper.Env = append(os.Environ(), helperEnv+"="+strings.Join([]string{dir, in.binary, in.kernel, in.initrd}, "\n"))
		var stderr bytes.Buffer
		helper.Stderr = &stderr
		out, err := helper.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := helper.Start(); err != nil {
			t.Fatal(err)
		}
		stop := time.AfterFunc(30*time.Second, func() { _ = helper.Process.Kill() })
		line, err := bufio.NewReader(out).ReadString('\n')
		stop.Stop()
		pid, convErr := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || convErr != nil {
			_ = helper.Process.Kill()
			_ = helper.Wait()
			t.Fatalf("helper printed %q (%v); stderr:\n%s", line, err, stderr.String())
		}
		t0 := time.Now()
		if err := helper.Process.Kill(); err != nil { // SIGKILL on the supervisor
			t.Fatal(err)
		}
		_ = helper.Wait()
		var orphans []string
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			orphans = scanProc(dir)
			if gone(pid) && len(orphans) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after SIGKILL of the supervisor: firecracker pid %d gone=%t, processes naming %s: %v",
					pid, gone(pid), dir, orphans)
			}
		}
		t.Logf("vmm supervisor_killed vmm_gone_ms=%d orphans=0", time.Since(t0).Milliseconds())
	})
}

// TestHelper is the supervisor that supervisor-killed SIGKILLs: it boots a guest in
// the directory its parent chose, prints the VMM's pid once the guest said hello,
// and then waits to be killed. It skips unless the parent set helperEnv.
func TestHelper(t *testing.T) {
	v := os.Getenv(helperEnv)
	if v == "" {
		t.Skip("the helper of TestFirecracker/supervisor-killed")
	}
	f := strings.Split(v, "\n")
	if len(f) != 4 {
		t.Fatalf("%s holds %d fields, want 4", helperEnv, len(f))
	}
	in := inputs{binary: f[1], kernel: f[2], initrd: f[3]}
	m := in.machine(t, f[0], nil)
	ln, err := m.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	fmt.Println(m.cmd.Process.Pid)
	time.Sleep(time.Minute)
}

// machine is a Machine over the inputs in dir, closed when the test ends.
func (in inputs) machine(t *testing.T, dir string, console io.Writer) *Machine {
	t.Helper()
	m := New(vmm.Config{Binary: in.binary, Kernel: in.kernel, Initrd: in.initrd,
		CPUs: 2, MemoryMiB: 512, CID: 3, Console: console, Dir: dir})
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// boot starts a guest in a fresh short Dir and returns it with the guest's
// connection, once the guest's hello arrived. The console goes to a file that
// is logged if the test fails.
func boot(t *testing.T, in inputs) (m *Machine, conn net.Conn, dir string, bootMS int64) {
	t.Helper()
	console, err := os.Create(filepath.Join(t.TempDir(), "console.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = console.Close()
		if b, _ := os.ReadFile(console.Name()); t.Failed() {
			t.Logf("console:\n%s", b)
		}
	})
	dir = shortDir(t)
	m = in.machine(t, dir, console)
	ln, err := m.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ln.(*net.UnixListener).SetDeadline(time.Now().Add(bootLimit)); err != nil {
		t.Fatal(err)
	}
	if conn, err = ln.Accept(); err != nil {
		t.Fatalf("no vsock connection from the guest within %v: %v", bootLimit, err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("guest said %q (%v), want hello", line, err)
	}
	return m, conn, dir, time.Since(t0).Milliseconds()
}

// shortDir is a fresh directory whose vsock socket paths fit sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(dir) > 80 {
		var err error
		if dir, err = os.MkdirTemp("", "wc"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	return dir
}

func list(t *testing.T, dir string) (names []string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// gone reports whether pid is no process, or a zombie waiting for its reaper.
func gone(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return true
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	_, state, _ := strings.Cut(string(b), ") ")
	return err != nil || strings.HasPrefix(state, "Z")
}

// scanProc returns the pids whose command line names dir.
func scanProc(dir string) (pids []string) {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline"); err == nil && bytes.Contains(b, []byte(dir+"/")) {
			pids = append(pids, e.Name())
		}
	}
	return pids
}

// fetch downloads the pinned inputs, checks their digests before anything is
// used, extracts the binary and builds the guest into an initramfs.
func fetch(t *testing.T) inputs {
	t.Helper()
	dl := t.TempDir()
	var tgz, kernel string
	var errs [2]error
	var wg sync.WaitGroup
	wg.Go(func() { tgz, errs[0] = download(dl, fcURL, "firecracker.tgz", fcSHA256) })
	wg.Go(func() { kernel, errs[1] = download(dl, kernelURL, "vmlinux", kernelSHA) })
	wg.Wait()
	if err := errors.Join(errs[:]...); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dl, "firecracker")
	if err := untar(tgz, fcMember, binary); err != nil {
		t.Fatal(err)
	}
	guest := filepath.Join(dl, "init")
	cmd := exec.Command("go", "build", "-trimpath", "-o", guest, "./testdata/guest")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build testdata/guest: %v\n%s", err, out)
	}
	b, err := os.ReadFile(guest)
	if err != nil {
		t.Fatal(err)
	}
	initrd := filepath.Join(dl, "initramfs.cpio")
	if err := os.WriteFile(initrd, initramfs(b), 0o644); err != nil {
		t.Fatal(err)
	}
	return inputs{binary: binary, kernel: kernel, initrd: initrd}
}

// download fetches url into dir/name and compares its SHA-256 with want.
func download(dir, url, name, want string) (string, error) {
	path := filepath.Join(dir, name)
	c := http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path, nil
}

// untar writes the one regular member of a gzipped tar to out, executable.
func untar(archive, member, out string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s in %s: %w", member, archive, err)
		}
		if h.Name != member || h.Typeflag != tar.TypeReg {
			continue
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, tr)
		return errors.Join(err, w.Close())
	}
}

// newc returns one entry of a "newc" cpio archive: the 110-byte header, the
// name and its NUL padded to 4, then the data padded to 4.
func newc(name string, mode uint32, data []byte) []byte {
	var b bytes.Buffer
	fields := []uint32{1, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	b.WriteString("070701")
	for _, f := range fields { // ino mode uid gid nlink mtime filesize devmajor devminor rdevmajor rdevminor namesize check
		fmt.Fprintf(&b, "%08X", f)
	}
	b.WriteString(name)
	b.WriteByte(0)
	b.Write(make([]byte, -b.Len()&3))
	b.Write(data)
	b.Write(make([]byte, -b.Len()&3))
	return b.Bytes()
}

// initramfs is an uncompressed cpio holding one executable, /init.
func initramfs(init []byte) []byte {
	return slices.Concat(newc("init", 0o100755, init), newc("TRAILER!!!", 0, nil))
}
