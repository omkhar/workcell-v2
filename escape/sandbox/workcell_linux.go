// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The pinned x86_64 guest artifacts: the Firecracker release and the kernel
// the product's own hosted test uses.
const (
	guestArch      = "amd64"
	firecrackerURL = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	firecrackerSum = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	firecrackerBin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	vmlinuxURL     = "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64"
	vmlinuxSum     = "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"
)

// hostReady says whether this host can run that guest: the pins are x86_64.
func hostReady() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("the pinned guest is x86_64, this host is %s", runtime.GOARCH)
	}
	return nil
}

// hypervisor puts the pinned Firecracker in data, where `workcell run` looks.
func hypervisor(ctx context.Context, data string) error {
	tgz, err := fetch(ctx, firecrackerURL, firecrackerSum)
	if err != nil {
		return err
	}
	bin, err := tarMember(tgz, firecrackerBin)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(data, "firecracker"), bin, 0o755)
}

// tarMember returns the named member of a gzipped tar archive.
func tarMember(tgz []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("archive has no %s: %w", name, err)
		}
		if h.Name == name {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

// hostBuild compiles pkg for this host: static Linux, as the product's own
// build does.
func hostBuild(ctx context.Context, repo, out, pkg string) error {
	return goBuild(ctx, repo, out, pkg, "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
}

// sign does nothing: a Linux binary runs unsigned.
func sign(context.Context, string, string) error { return nil }

// steersResolver: on Linux the product can be run under a /etc/resolv.conf
// of the session's own, so a session may name a resolver.
const steersResolver = true

// isolatedAddr is the one address the test host holds in a session's own
// network namespace. It is in 192.175.48.0/24, the AS112 range (RFC 7534):
// an IANA special-purpose range that is global unicast, so the product's
// vetting accepts it where it refuses every loopback, private, link-local,
// documentation and benchmarking range, and no operator's allocation. The
// namespace has a loopback device and nothing else: a packet to this
// address is delivered inside it, and one to any other address has no
// route, so nothing can leave the test host (SPEC T8, S12).
const isolatedAddr = "192.175.48.1"

// holder is a session's own network namespace: the payload that made it
// and holds it, as root, and the connection it binds sockets over. The
// product is started inside it (steered) and the judge's canaries listen
// in it (bind).
type holder struct {
	pid  int
	conn *net.UnixConn
	mu   sync.Mutex
}

// isolate starts the holder: the payload under `unshare -n`, as root (sudo
// when the suite is not), which brings its loopback up with isolatedAddr,
// dials back at a socket under dir and says its pid.
func isolate(dir, payload string) (*holder, error) {
	path := filepath.Join(dir, "netns")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	var argv []string
	if os.Geteuid() != 0 {
		argv = append(argv, "sudo", "-n")
	}
	argv = append(argv, "unshare", "-n", payload, "netns", path, isolatedAddr)
	cmd := exec.Command(argv[0], argv[1:]...)
	stderr := &bounded{limit: MaxStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the holder of the session's network namespace: %w", err)
	}
	go cmd.Wait()
	ln.SetDeadline(time.Now().Add(5 * time.Second))
	c, err := ln.AcceptUnix()
	if err != nil {
		return nil, fmt.Errorf("the holder of the session's network namespace did not call back: %v: %s", err, bytes.TrimSpace(stderr.bytes()))
	}
	h := &holder{conn: c}
	if _, err := fmt.Fscanf(c, "pid %d\n", &h.pid); err != nil || h.pid <= 1 {
		c.Close()
		return nil, fmt.Errorf("the holder of the session's network namespace said no pid: %v: %s", err, bytes.TrimSpace(stderr.bytes()))
	}
	return h, nil
}

// bind has the holder bind network/addr in the namespace, "host" in addr
// standing for isolatedAddr, and hands the socket back over SCM_RIGHTS.
func (h *holder) bind(network, addr string) (net.Listener, net.PacketConn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if host, port, err := net.SplitHostPort(addr); err == nil && host == "host" {
		addr = net.JoinHostPort(isolatedAddr, port)
	}
	where := fmt.Sprintf("bind %s %s in the session's network namespace", network, addr)
	if _, err := fmt.Fprintf(h.conn, "%s %s\n", network, addr); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", where, err)
	}
	buf, oob := make([]byte, 256), make([]byte, 64)
	h.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := h.conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", where, err)
	}
	if line := strings.TrimSpace(string(buf[:n])); line != "ok" {
		return nil, nil, fmt.Errorf("%s: %s", where, line)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	var fds []int
	if err == nil && len(msgs) == 1 {
		fds, err = syscall.ParseUnixRights(&msgs[0])
	}
	if err != nil || len(fds) != 1 {
		return nil, nil, fmt.Errorf("%s: no descriptor came back (%v)", where, err)
	}
	f := os.NewFile(uintptr(fds[0]), network)
	defer f.Close()
	if strings.HasPrefix(network, "udp") {
		pc, err := net.FilePacketConn(f)
		return nil, pc, err
	}
	l, err := net.FileListener(f)
	return l, nil, err
}

// stop hangs up on the holder, which then exits; the namespace goes once
// nothing runs in it.
func (h *holder) stop() { h.conn.Close() }

// productProcess finds the product's own process under root, the process
// the adapter started for a run: root itself, or the deepest of its
// descendants, whose executable is bin. Under steering root is sudo and the
// product sits below it; a product that forked a supervisor of its own is
// found below itself. A process between fork and exec still shows its
// parent's executable, so a caller that finds nothing asks again.
func productProcess(root int, bin string) (int, bool) {
	es, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	children := map[int][]int{}
	for _, e := range es {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:])) // after the comm: state ppid pgrp ...
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			children[ppid] = append(children[ppid], pid)
		}
	}
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real
	}
	found, depth := 0, -1
	var walk func(pid, d int)
	walk = func(pid, d int) {
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && exe == bin && d > depth {
			found, depth = pid, d
		}
		for _, c := range children[pid] {
			walk(c, d+1)
		}
	}
	walk(root, 0)
	return found, depth >= 0
}

// resolverLoader runs as the product's own process, in a mount namespace of
// its own: it makes every mount private, so that nothing it binds shows on
// the host, binds the session's resolv.conf ($1) over /etc/resolv.conf,
// becomes the user the suite runs as ($2, $3; the loader itself runs as
// root, since binding needs that), and becomes the product with exactly the
// environment the suite gives it (the K=V words after the ids, then the
// command). The product then resolves every name with the resolver that
// file names, as any program on the host would, and knows nothing else.
const resolverLoader = `mount --make-rprivate / && mount --bind "$1" /etc/resolv.conf || { echo "workcell adapter: cannot bind the session's resolv.conf over /etc/resolv.conf" >&2; exit 125; }; u=$2 g=$3; shift 3; exec setpriv --reuid="$u" --regid="$g" --init-groups -- env -i "$@"`

// steered returns the argv that runs argv under a /etc/resolv.conf naming
// resolver, with env as its whole environment: the loader above in a new
// mount namespace, through sudo when the suite is not root, as a hosted
// runner grants without a password, and inside the network namespace that
// the process ns holds when ns is set. The resolv.conf is written under dir.
func steered(dir, resolver string, env, argv []string, ns int) ([]string, error) {
	file := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(file, []byte("nameserver "+resolver+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write the session's resolv.conf: %w", err)
	}
	var out []string
	if os.Geteuid() != 0 {
		out = append(out, "sudo", "-n")
	}
	if ns > 0 {
		out = append(out, "nsenter", "--net=/proc/"+strconv.Itoa(ns)+"/ns/net")
	}
	out = append(out, "unshare", "-m", "/bin/sh", "-c", resolverLoader, "sh", file, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	for _, kv := range env {
		if strings.Contains(kv, "=") { // a word without one would be read as the command
			out = append(out, kv)
		}
	}
	return append(out, argv...), nil
}
