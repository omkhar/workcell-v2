// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
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

// The pinned arm64 guest: Firecracker's CI kernel, which boots under Virtualization.framework (measured in U-102). The product drives the framework in-process,
// so there is no hypervisor binary to fetch, and the binary that does it must carry the virtualization entitlement.
const (
	guestArch  = "arm64"
	vmlinuxURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155"
	vmlinuxSum = "61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be"
)

// entitlements is the one entitlement a process needs to start a VM.
const entitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.virtualization</key>
	<true/>
</dict>
</plist>
`

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

// A Mac has no namespaces to give a session a network and a resolver of its own. The maintainer set this host up instead, once, as root; the adapter relies on
// it, checks for it and never changes it: lo0 holds isolatedAddr and the judge's addresses as aliases, so nothing bound at one is reached from off the host
// (SPEC T8); /etc/resolver/<judgeDomain> sends every question for a name under it to the judge's resolver, as `scutil --dns` shows, the product resolving
// through the system as any program would; and bindHelper, root-owned, which sudo runs for the suite's user without a password, binds a port below 1024 at an
// alias of lo0 and hands the descriptor over as suite.Bind does. No other sudo exists.
const (
	steersResolver = true
	judgeDomain    = "escape.test"
	bindHelper     = "/usr/local/libexec/workcell-escape/workcell-bind"
)

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

// holder is a session's own network on a Mac: the host's own, with isolatedAddr an alias of lo0 that isolate checks; pid is the suite's own.
type holder struct{ pid int }

func isolate(string, string) (*holder, error) {
	if err := LoopbackHolds(isolatedAddr); err != nil {
		return nil, err
	}
	return &holder{pid: os.Getpid()}, nil
}

// bind binds network/addr, "host" standing for isolatedAddr, as root (RootBind).
func (h *holder) bind(network, addr string) (net.Listener, net.PacketConn, error) {
	return RootBind(network, addr, "", h.pid)
}

func (*holder) stop() {}

// settle waits out mDNSResponder's cache after a session resolved the suite's names through it: an answer is held 15 s whatever its TTL (U-701) and no user can
// flush it, else the next session never asks the judge.
func settle() { time.Sleep(16 * time.Second) }

// rootBindArgv is what RootBind runs: bindHelper, through sudo.
func rootBindArgv(network, addr, path, _ string, _ int) []string {
	return []string{"sudo", "-n", bindHelper, network, addr, path}
}

// productProcess is the product's own process under root, the process the adapter started for a run: root itself, since nothing wraps the product here and its
// VM runs inside it (Virtualization.framework, in-process).
func productProcess(root int, _ string) (int, bool) { return root, true }

// hypervisor fetches nothing: Virtualization.framework is part of the OS.
func hypervisor(context.Context, string) error { return nil }

// hostBuild compiles pkg for this Mac, with cgo, which the framework needs, under the build overlay file named when one is.
func hostBuild(ctx context.Context, repo, out, pkg, overlay string) error {
	return goBuild(ctx, repo, out, pkg, overlay, "CGO_ENABLED=1", "GOOS=darwin", "GOARCH=arm64")
}

// sign signs the freshly built bin ad hoc with the virtualization entitlement, from a plist written under dir. It happens once, before the binary ever runs:
// re-signing one that has run can get it killed (U-102).
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
