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
	"time"
)

// The pinned guest artifacts by host architecture: the Firecracker release and a kernel, x86_64's the one the product's own hosted test uses, aarch64's the
// Firecracker CI Image the Mac pins too.
var pinned = map[string]struct{ firecrackerURL, firecrackerSum, firecrackerBin, vmlinuxURL, vmlinuxSum string }{
	"amd64": {"https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz", "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558", "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64", "https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64", "edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853"},
	"arm64": {"https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-aarch64.tgz", "e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256", "release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64", "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155", "61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be"},
}

var guestArch, pin = runtime.GOARCH, pinned[runtime.GOARCH]
var vmlinuxURL, vmlinuxSum = pin.vmlinuxURL, pin.vmlinuxSum

// hostReady says whether this host can run that guest: a pinned architecture.
func hostReady() error {
	if _, ok := pinned[runtime.GOARCH]; !ok {
		return fmt.Errorf("no pinned guest for linux/%s", runtime.GOARCH)
	}
	return nil
}

// hypervisor puts the pinned Firecracker in data, where `workcell run` looks.
func hypervisor(ctx context.Context, data string) error {
	tgz, err := fetch(ctx, pin.firecrackerURL, pin.firecrackerSum)
	if err != nil {
		return err
	}
	bin, err := tarMember(tgz, pin.firecrackerBin)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(data, "firecracker"), bin, 0o755)
}

// tarMember returns the named member of a gzipped tar archive.
func tarMember(tgz []byte, name string) ([]byte, error) {
	var out []byte
	err := untar(tgz, func(h *tar.Header, r io.Reader) (err error) {
		if h.Name == name {
			out, err = io.ReadAll(io.LimitReader(r, maxDownload))
		}
		return err
	})
	if err == nil && out == nil {
		err = fmt.Errorf("archive has no %s", name)
	}
	return out, err
}

// untar calls each with every entry of a tar archive, gzipped or plain.
func untar(b []byte, each func(*tar.Header, io.Reader) error) error {
	r := io.Reader(bytes.NewReader(b))
	if gz, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
		r = gz
	}
	for tr := tar.NewReader(r); ; {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err == nil {
			err = each(h, tr)
		}
		if err != nil {
			return err
		}
	}
}

// hostBuild compiles pkg for this host: static Linux, as the product's own build does, under the build overlay file named when one is.
func hostBuild(ctx context.Context, repo, out, pkg, overlay string) error {
	return goBuild(ctx, repo, out, pkg, overlay, "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
}

// sign does nothing: a Linux binary runs unsigned.
func sign(context.Context, string, string) error { return nil }

// steersResolver: on Linux the product can be run under a /etc/resolv.conf of the session's own, so a session may name a resolver.
const steersResolver = true

// holder is a session's own network namespace, whose loopback device holds IsolatedNet and a route to CanaryAddr and nothing else, so that no other address has
// a route: the payload that made it and holds it, as root, and the connection whose closing lets it go. The product starts inside it (steered); the judge's
// canaries listen in it (bind).
type holder struct {
	pid     int
	payload string
	conn    *net.UnixConn
}

// isolate starts the holder: the payload under `unshare -n`, as root (sudo when the suite is not), which sets its loopback device up (suite.Hold), dials back
// at a socket under dir and says its pid.
func isolate(dir, payload string) (*holder, error) {
	path := filepath.Join(dir, "netns")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	argv := asRoot("unshare", "-n", payload, "netns", path)
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
	h := &holder{payload: payload, conn: c}
	if _, err := fmt.Fscanf(c, "pid %d\n", &h.pid); err != nil || h.pid <= 1 {
		c.Close()
		return nil, fmt.Errorf("the holder of the session's network namespace said no pid: %v: %s", err, bytes.TrimSpace(stderr.bytes()))
	}
	return h, nil
}

// bind binds network/addr in the namespace, "host" in addr standing for CanaryAddr, through the payload as root inside it (RootBind).
func (h *holder) bind(network, addr string) (net.Listener, net.PacketConn, error) {
	return RootBind(network, addr, h.payload, h.pid)
}

// stop hangs up on the holder, which then exits; the namespace goes once nothing runs in it.
func (h *holder) stop() { h.conn.Close() }

// asRoot is argv through sudo, without a prompt, when the suite is not root.
func asRoot(argv ...string) []string {
	if os.Geteuid() != 0 {
		return append([]string{"sudo", "-n"}, argv...)
	}
	return argv
}

// settle has nothing to wait for: the product resolves through the file steered gave it, and nothing on the host caches that.
func settle() {}

// rootBindArgv is what RootBind runs: the payload's bind verb (suite.Bind) as root, entered into the network namespace that the process ns holds when ns is
// set.
func rootBindArgv(network, addr, path, payload string, ns int) []string {
	var argv []string
	if ns > 0 {
		argv = append(argv, "nsenter", "--net=/proc/"+strconv.Itoa(ns)+"/ns/net")
	}
	return asRoot(append(argv, payload, "bind", network, addr, path)...)
}

// EachProcess calls f with the pid, parent and group of every process on the host, as /proc lists them now.
func EachProcess(f func(pid, ppid, pgid int)) error {
	es, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range es {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // gone between the listing and the read
		}
		fl := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:])) // after the comm, which may hold spaces: state ppid pgrp ...
		if len(fl) < 3 {
			continue
		}
		ppid, err1 := strconv.Atoi(fl[1])
		pgid, err2 := strconv.Atoi(fl[2])
		if err1 == nil && err2 == nil {
			f(pid, ppid, pgid)
		}
	}
	return nil
}

// productProcess finds the product's own process under root, the process the adapter started for a run: root itself, or the deepest of its descendants, whose
// executable is bin (under steering root is sudo; a product that forked a supervisor of its own is found below itself). A process between fork and exec still
// shows its parent's executable, so a caller that finds nothing asks again.
func productProcess(root int, bin string) (int, bool) {
	children := map[int][]int{}
	if EachProcess(func(pid, ppid, _ int) { children[ppid] = append(children[ppid], pid) }) != nil {
		return 0, false
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

// resolverLoader runs in a mount namespace of its own: it makes every mount private, so that nothing it binds shows on the host, binds the session's
// resolv.conf ($1) over /etc/resolv.conf, becomes the user the suite runs as ($2, $3; the loader runs as root, since binding needs that), and becomes the
// product with exactly the environment the suite gives it (the K=V words after the ids, then the command), which then resolves every name with that file's
// resolver.
const resolverLoader = `mount --make-rprivate / && mount --bind "$1" /etc/resolv.conf || { echo "workcell adapter: cannot bind the session's resolv.conf over /etc/resolv.conf" >&2; exit 125; }; u=$2 g=$3; shift 3; exec setpriv --reuid="$u" --regid="$g" --init-groups -- env -i "$@"`

// steered returns the argv that runs argv under a /etc/resolv.conf naming resolver, with env as its whole environment: the loader above in a new mount
// namespace, through sudo when the suite is not root, as a hosted runner grants without a password, and inside the network namespace that the process ns holds
// when ns is set. The resolv.conf is written under dir.
func steered(dir, resolver string, env, argv []string, ns int) ([]string, error) {
	file := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(file, []byte("nameserver "+resolver+"\n"), 0o644); err != nil {
		return nil, fmt.Errorf("write the session's resolv.conf: %w", err)
	}
	var out []string
	if ns > 0 {
		out = append(out, "nsenter", "--net=/proc/"+strconv.Itoa(ns)+"/ns/net")
	}
	out = append(out, "unshare", "-m", "/bin/sh", "-c", resolverLoader, "sh", file, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	for _, kv := range env {
		if strings.Contains(kv, "=") { // a word without one would be read as the command
			out = append(out, kv)
		}
	}
	return asRoot(append(out, argv...)...), nil
}
