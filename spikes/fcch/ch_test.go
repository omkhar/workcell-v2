// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fcch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// chExtraArgs is where "--api-socket <dir>/ch.api" goes if Cloud Hypervisor
// refuses to start without one.
var chExtraArgs = []string{}

// launchCH starts Cloud Hypervisor, with virtiofsd first for the fs share. CH
// has no separate start step, so startT is the instant before cmd.Start.
func (e *env) launchCH(t0 time.Time, v variant, dir, console string) (*vm, error) {
	m := &vm{apiMS: -1, vfsReadyMS: -1}
	memory := fmt.Sprintf("size=%dM", memMiB)
	cmdline := "console=ttyS0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=" + v.share
	args := []string{"--kernel", e.kernel(v), "--initramfs", e.initrd, "--cmdline", cmdline,
		"--cpus", fmt.Sprintf("boot=%d", vcpus), "--vsock", "cid=3,socket=" + filepath.Join(dir, "ch.vsock"),
		"--serial", "file=" + console, "--console", "off"}
	var err error
	if v.share == "fs" {
		sock := filepath.Join(dir, "fs.sock")
		m.vfs, err = e.start("virtiofsd", e.virtiofsd, nil, "--socket-path", sock, "--shared-dir", filepath.Join(dir, "work"),
			"--cache", "never", "--sandbox", "none", "--seccomp", "none")
		if err != nil {
			return m, err
		}
		exists := func() bool { _, err := os.Stat(sock); return err == nil }
		if err := waitFor(exists, 5*time.Second, m.vfs.done); err != nil {
			return m, fmt.Errorf("virtiofsd socket: %w", err)
		}
		m.vfsReadyMS = time.Since(t0).Milliseconds()
		memory += ",shared=on"
		args = append(args, "--fs", "tag=work,socket="+sock)
	} else {
		args = append(args, "--disk", "path="+filepath.Join(dir, "share.img")+",image_type=raw")
	}
	args = append(args, "--memory", memory)
	args = append(args, chExtraArgs...)
	m.startT = time.Now()
	m.vmm, err = e.start("cloud-hypervisor", e.ch, nil, args...)
	return m, err
}

// installVirtiofsd returns the path of virtiofsd, installing the distribution
// package if need be, or "" if that is not possible. No upstream prebuilt exists.
func installVirtiofsd(t *testing.T) string {
	find := func() string {
		for _, p := range []string{"/usr/libexec/virtiofsd", "/usr/lib/qemu/virtiofsd", "/usr/bin/virtiofsd"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		p, _ := exec.LookPath("virtiofsd")
		return p
	}
	if p := find(); p != "" {
		return p
	}
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return exec.CommandContext(ctx, "sudo", append([]string{"-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get"}, args...)...).CombinedOutput()
	}
	install := []string{"install", "-y", "--no-install-recommends", "virtiofsd"}
	out, err := run(install...)
	if err != nil {
		_, _ = run("update")
		out, err = run(install...)
	}
	if err != nil {
		t.Logf("fcch virtiofsd=unavailable install failed: %v\n%s", err, tail(string(out), 15))
		return ""
	}
	return find()
}
