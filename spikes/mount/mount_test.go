// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Package mount is the U-502a spike: a FUSE mount in the real guest whose requests the
// guest init passes through, unparsed, over vsock to a FUSE server on the host (ADR-005).
// It boots kernel A for the fact that it has no FUSE, then kernel B for every number.
// Findings are in notes.md.
package mount

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/vmm/firecracker"
	"github.com/omkhar/workcell/v2/internal/wire"
	"github.com/omkhar/workcell/v2/spikes/mount/fuse"
	"github.com/omkhar/workcell/v2/spikes/mount/serve"
	"github.com/omkhar/workcell/v2/spikes/netpath/relay"
)

const (
	hardLimit = 120 * time.Second // from the first boot; the VM is killed and the test fails
	waitCap   = 240 * time.Second // for the other spikes' VMs
	nDirs     = 100
	nFiles    = 100
	bigMiB    = 100
	bigName   = "big.bin"
)

func TestMount(t *testing.T) {
	needKVM(t)
	start := time.Now()
	dl := t.TempDir()
	var fc, kA, kB, initrd string
	var errs [5]error
	var wg sync.WaitGroup
	wg.Go(func() {
		var tgz string
		if tgz, errs[0] = download(dl, fcURL, "firecracker.tgz", fcSHA256); errs[0] == nil {
			fc = filepath.Join(dl, "firecracker")
			errs[0] = untar(tgz, fcMember, fc)
		}
	})
	wg.Go(func() { kA, errs[1] = download(dl, kernelAURL, "vmlinux-a", kernelASHA) })
	wg.Go(func() { kB, errs[2] = download(dl, kernelBURL, "vmlinux-b", kernelBSHA) })
	wg.Go(func() { initrd, errs[3] = guestInitramfs(t.TempDir()) })
	export := filepath.Join(t.TempDir(), "export")
	wg.Go(func() { errs[4] = makeTree(export) })
	wg.Wait()
	if err := errors.Join(errs[:]...); err != nil {
		t.Fatal(err)
	}
	prepS := time.Since(start).Seconds()

	// "go test ./spikes/..." runs the other spikes' VMs beside this one.
	phase := time.Now()
	others := func() []string {
		return procs("comm", func(s string) bool { return s == "fcch.test" || s == "libkrun.test" || s == "netpath.test" })
	}
	for len(others()) > 0 && time.Since(phase) < waitCap {
		time.Sleep(time.Second)
	}
	waitedS := time.Since(phase).Seconds()

	deadline := time.Now().Add(hardLimit)
	boot(t, "A", fc, kA, initrd, export, deadline)
	end := boot(t, "B", fc, kB, initrd, export, deadline)
	t.Logf("mount %s prep_s=%.1f waited_s=%.1f others_left=%d test_s=%.1f", end, prepS, waitedS, len(others()),
		time.Since(start).Seconds())
}

// boot runs one guest on kernel and, where the mount works, every measurement. It returns
// the end-of-test pairs for that guest.
func boot(t *testing.T, kernelName, fc, kernel, initrd, export string, deadline time.Time) string {
	logf := func(format string, a ...any) { t.Logf("mount "+format, a...) }
	bad := false
	console, err := os.Create(filepath.Join(t.TempDir(), "console.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = console.Close()
		if b, _ := os.ReadFile(console.Name()); bad || t.Failed() || kernelName == "B" {
			t.Logf("mount kernel=%s console tail:\n%s", kernelName, b[max(0, len(b)-4096):])
		}
	}()
	srv, err := serve.New(export, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := firecracker.New(vmm.Config{Binary: fc, Kernel: kernel, Initrd: initrd, CPUs: 2, MemoryMiB: 1024, CID: 3,
		Console: console, Dir: shortDir(t)})
	defer m.Close()
	ctl, err := m.Listen(relay.Control)
	if err != nil {
		t.Fatal(err)
	}
	data, err := m.Listen(fuse.Port)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		_ = data.(interface{ SetDeadline(time.Time) error }).SetDeadline(deadline)
		c, err := data.Accept()
		_ = data.Close()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		served <- srv.Serve(wire.New(c, 10*time.Second))
	}()
	defer srv.Close()
	guard := time.AfterFunc(time.Until(deadline), func() {
		t.Errorf("mount hard limit %v reached: the VM is killed", hardLimit)
		_ = m.Kill()
	})
	defer guard.Stop()
	t0 := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = ctl.(interface{ SetDeadline(time.Time) error }).SetDeadline(t0.Add(15 * time.Second))
	conn, err := ctl.Accept()
	if err != nil {
		bad = true
		logf("kernel=%s boot_ms=err:%s", kernelName, relay.Clean(err.Error()))
		return "boot=err"
	}
	bootMS := time.Since(t0).Milliseconds()
	defer conn.Close()
	g := &guest{c: conn, r: bufio.NewReader(conn)}
	ask := func(key string, limit time.Duration, cmd ...string) (map[string]string, string) {
		kv, line, err := g.ask(limit, cmd...)
		if err != nil {
			bad = true
			return nil, relay.Err(key, err)
		}
		return kv, line
	}

	// The per-kernel line: config, the mount, the handshake.
	_, feat := ask("cfg", 10*time.Second, "features")
	mkv, mline := ask("mount", 20*time.Second, "mount")
	hs := "fuse_init_major=none"
	if in, flags, ok := srv.Init(); ok {
		hs = fmt.Sprintf("fuse_init_major=%d fuse_init_minor=%d fuse_init_flags=0x%x fuse_reply_flags=0x%x fuse_init_max_readahead=%d",
			in.Major, in.Minor, in.Flags, flags, in.MaxReadahead)
	}
	logf("kernel=%s boot_ms=%d %s %s %s", kernelName, bootMS, feat, mline, hs)
	logf("step=mount valid_s=1 %s", srv.Step())

	var sha string
	if mkv["mount_stat"] == "ok" {
		step := func(name string, valid time.Duration, limit time.Duration, cmd ...string) map[string]string {
			srv.SetValid(valid)
			kv, line := ask(name, limit, cmd...)
			logf("%s", line)
			logf("step=%s valid_s=%g %s", name, valid.Seconds(), srv.Step())
			return kv
		}
		const s1 = time.Second
		step("walk_t1", s1, 60*time.Second, "walk", "/workspace", "walk_t1")
		step("walk_t1_warm", s1, 60*time.Second, "walk", "/workspace", "walk_t1_warm")
		step("drop_t0", 0, 10*time.Second, "drop")
		step("walk_t0", 0, 60*time.Second, "walk", "/workspace", "walk_t0")
		step("rtt", 0, 30*time.Second, "rtt", "/workspace/d00/f00", "1000")
		step("drop_cat", s1, 10*time.Second, "drop")
		step("cat", s1, 30*time.Second, "cat", "/workspace", "20")
		if kv := step("write", s1, 60*time.Second, "write", "/workspace/"+bigName, fmt.Sprint(bigMiB), "write"); kv != nil {
			sha = kv["write_sha256"]
		}
		step("read", s1, 60*time.Second, "read", "/workspace/"+bigName, sha)
		step("tmpfs", s1, 60*time.Second, "tmpfs")
		step("umount", s1, 15*time.Second, "umount")
	}
	serveExit := "not-connected"
	if mkv["data_dial"] == "ok" {
		select {
		case err := <-served:
			serveExit = relay.Clean(fmt.Sprint(err))
		case <-time.After(5 * time.Second):
			serveExit = "timeout"
		}
	}
	_, bye := ask("bye", 5*time.Second, "quit")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t1 := time.Now()
	vmmErr := m.Wait(ctx)
	end := fmt.Sprintf("kernel=%s %s vmm_exit=%s teardown_ms=%d serve_exit=%s %s", kernelName, bye,
		relay.Clean(fmt.Sprint(vmmErr)), time.Since(t1).Milliseconds(), serveExit, srv.Totals())
	if kernelName == "A" {
		logf("%s", end)
		return end
	}
	return end + " " + hostChecks(export, sha)
}

// hostChecks is what the host sees of the export after the guest is gone.
func hostChecks(export, sha string) string {
	big := filepath.Join(export, bigName)
	size := "err:absent"
	if fi, err := os.Lstat(big); err == nil {
		size = fmt.Sprint(fi.Size())
	}
	match := "false"
	if f, err := os.Open(big); err == nil {
		h := sha256.New()
		if _, err := io.Copy(h, f); err == nil && sha != "" && hex.EncodeToString(h.Sum(nil)) == sha {
			match = "true"
		}
		_ = f.Close()
	}
	intact := "true"
	if err := checkTree(export); err != nil {
		intact = "false:" + relay.Clean(err.Error())
	}
	return fmt.Sprintf("host_bigfile_bytes=%s host_sha256_match=%s host_tree_intact=%s", size, match, intact)
}

func content(d, f int) []byte { return fmt.Appendf(nil, "%15s\n", fmt.Sprintf("d%02d/f%02d", d, f)) }

// makeTree writes nDirs directories of nFiles 16-byte files under root.
func makeTree(root string) error {
	for d := range nDirs {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", d))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		for f := range nFiles {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d", f)), content(d, f), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkTree says whether root holds the tree of makeTree and the big file, and nothing else.
func checkTree(root string) error {
	top, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(top) != nDirs+1 {
		return fmt.Errorf("%d top-level entries", len(top))
	}
	for d := range nDirs {
		dir := filepath.Join(root, fmt.Sprintf("d%02d", d))
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(ents) != nFiles {
			return fmt.Errorf("%s has %d entries", dir, len(ents))
		}
		for f := range nFiles {
			b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("f%02d", f)))
			if err != nil {
				return err
			}
			if string(b) != string(content(d, f)) {
				return fmt.Errorf("d%02d/f%02d changed", d, f)
			}
		}
	}
	return nil
}

// guest is the host end of the control connection.
type guest struct {
	c net.Conn
	r *bufio.Reader
}

// ask sends one command and reads the guest's one reply line.
func (g *guest) ask(limit time.Duration, cmd ...string) (map[string]string, string, error) {
	_ = g.c.SetDeadline(time.Now().Add(limit))
	if _, err := io.WriteString(g.c, strings.Join(cmd, " ")+"\n"); err != nil {
		return nil, "", err
	}
	line, err := g.r.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	line = strings.TrimSpace(line)
	kv := relay.Parse(line)
	if e, ok := kv["error"]; ok {
		return nil, line, errors.New(e)
	}
	return kv, line, nil
}
