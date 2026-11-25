// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const guestArch, vmlinuxURL, vmlinuxSum = "arm64", "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155", "61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be" // The pinned arm64 guest: Firecracker's CI kernel, which boots under Virtualization.framework (measured in U-102). The product drives the framework in-process, so there is no hypervisor binary to fetch, and the binary that does it must carry the virtualization entitlement.
// entitlements is the one entitlement a process needs to start a VM.
const entitlements = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.virtualization</key><true/></dict></plist>`

// hostReady says whether this host can run that guest: the pins are arm64, and codesign must be there to entitle the binary.
func hostReady() error {
	if runtime.GOARCH != "arm64" {
		return fmt.Errorf("the pinned guest is arm64, this host is %s", runtime.GOARCH)
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		return err
	}
	return nil
}

// A Mac has no namespaces to give a session a network and a resolver of its own. The maintainer set this host up instead, once, as root; the adapter relies on it, checks for it and never changes it: lo0 holds landing, Neighbour and the judge's addresses as aliases, so nothing bound at one is reached from off the host (SPEC T8); CanaryAddr is no interface's and in no prefix of one, since the product dials nothing inside a network of the host's, and as macOS binds no socket at such an address a host route keeps it on lo0, where pf hands it to landing; /etc/resolver/<judgeDomain> sends every question for a name under it to the judge's resolver, as `scutil --dns` shows, the product resolving through the system as any program would; and bindHelper, root-owned, which sudo runs for the suite's user without a password, binds a port below 1024 at an alias of lo0 and hands the descriptor over as suite.Bind does. No other sudo exists.
const steersResolver, judgeDomain, bindHelper, landing = true, "escape.test", "/usr/local/libexec/workcell-escape/workcell-bind", "192.175.48.1" // the host's address in IsolatedNet
// steered checks that every question for judgeDomain reaches resolver and nowhere else (T8).
func steered(_, resolver string, _, argv []string, _ int) ([]string, error) {
	if err := LoopbackHolds(resolver); err != nil {
		return nil, err
	}
	out, err := exec.Command("scutil", "--dns").Output()
	if err != nil {
		return nil, fmt.Errorf("scutil --dns: %w", err)
	}
	for _, block := range strings.Split(string(out), "resolver #") {
		words := strings.Join(strings.Fields(block), " ") + " "
		if strings.Contains(words, " domain : "+judgeDomain+" ") && strings.Contains(words, " nameserver[0] : "+resolver+" ") {
			return argv, nil
		}
	}
	return nil, fmt.Errorf("scutil --dns lists no resolver for %s at %s: /etc/resolver/%s must name it, or a question for the suite's names would leave the host", judgeDomain, resolver, judgeDomain)
}

type holder struct{ pid int } // holder is a session's own network on a Mac: the host's own, in the shape isolate checks; pid is the suite's own.
// isolate checks that shape by what it does, and sends nothing before the route is known to end on lo0 (T8).
func isolate(_, _ string, _ bool) (*holder, error) { // unsupported refused OnLink before this
	if err := shaped(); err != nil {
		return nil, fmt.Errorf("%w: the Mac needs lo0 aliases %s and %s/32, no interface prefix around %s, a host route for it to lo0, and pf enabled with `rdr pass on lo0 inet proto { tcp, udp } from any to %[4]s -> %s`", err, IsolatedNet, Neighbour, CanaryAddr, landing)
	}
	return &holder{pid: os.Getpid()}, nil
}
func shaped() error {
	if err := cmp.Or(LoopbackHolds(landing), LoopbackHolds(Neighbour)); err != nil {
		return err
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.Contains(net.ParseIP(CanaryAddr)) {
			return fmt.Errorf("the host holds %s, and the product dials nothing inside a network of the host's", ipn)
		}
	}
	if out, err := exec.Command("route", "-n", "get", CanaryAddr).Output(); !strings.Contains(string(out), "interface: lo0\n") {
		return fmt.Errorf("no route keeps %s on lo0 (route -n get: %v)", CanaryAddr, err)
	}
	ln, err := net.Listen("tcp4", landing+":0")
	if err != nil {
		return err
	}
	defer ln.Close()
	c, err := net.DialTimeout("tcp4", atCanary{ln}.Addr().String(), time.Second)
	if err != nil {
		return fmt.Errorf("nothing hands %s to %s: %w", CanaryAddr, landing, err)
	}
	return c.Close()
}

// bind binds network/addr as root (RootBind), a listener at "host" at landing, which says CanaryAddr: the address the product dials to reach it.
func (h *holder) bind(network, addr string) (net.Listener, net.PacketConn, error) {
	host, port, _ := net.SplitHostPort(addr)
	if host != "host" || network != "tcp4" {
		return RootBind(network, addr, "", h.pid)
	}
	ln, _, err := RootBind(network, net.JoinHostPort(landing, port), "", h.pid)
	if err != nil {
		return nil, nil, err
	}
	return atCanary{ln}, nil, nil
}

type atCanary struct{ net.Listener }

func (l atCanary) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(CanaryAddr), Port: l.Listener.Addr().(*net.TCPAddr).Port}
}
func (*holder) stop() {}

// settle waits out mDNSResponder's cache after a session resolved the suite's names through it: an answer is held 15 s whatever its TTL (U-701) and no user can flush it, else the next session never asks the judge.
func settle() { time.Sleep(16 * time.Second) }

// rootBindArgv is what RootBind runs: bindHelper, through sudo.
func rootBindArgv(network, addr, path, _ string, _ int) []string {
	return []string{"sudo", "-n", bindHelper, network, addr, path}
}

// productProcess is the product's own process under root, the process the adapter started for a run: root itself, since nothing wraps the product here and its VM runs inside it (Virtualization.framework, in-process).
func productProcess(root int, _ string) (int, bool) { return root, true }

func hypervisor(context.Context, string) error { return nil } // hypervisor fetches nothing: Virtualization.framework is part of the OS.
// hostBuild compiles pkg for this Mac, with cgo, which the framework needs, under the build overlay file named when one is.
func hostBuild(ctx context.Context, repo, out, pkg, overlay string) error {
	return goBuild(ctx, repo, out, pkg, overlay, "CGO_ENABLED=1", "GOOS=darwin", "GOARCH=arm64")
}

// sign signs the freshly built bin ad hoc with the virtualization entitlement, from a plist written under dir. It happens once, before the binary ever runs: re-signing one that has run can get it killed (U-102).
func sign(ctx context.Context, dir, bin string) error {
	plist := filepath.Join(dir, "vz.entitlements")
	if err := os.WriteFile(plist, []byte(entitlements), 0o644); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "--entitlements", plist, "-f", bin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("codesign %s: %v: %s", bin, err, bytes.TrimSpace(out))
	}
	return nil
}
