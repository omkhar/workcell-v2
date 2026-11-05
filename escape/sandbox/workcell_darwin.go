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
)

// The pinned arm64 guest: Firecracker's CI kernel, which boots under
// Virtualization.framework (measured in U-102). The product drives the
// framework in-process, so there is no hypervisor binary to fetch, and the
// binary that does it must carry the virtualization entitlement.
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

// hostReady says whether this host can run that guest: the pins are arm64,
// and codesign must be there to entitle the binary.
func hostReady() error {
	if runtime.GOARCH != "arm64" {
		return fmt.Errorf("the pinned guest is arm64, this host is %s", runtime.GOARCH)
	}
	if _, err := exec.LookPath("codesign"); err != nil {
		return err
	}
	return nil
}

// steersResolver: a Mac has no mount namespace to give the product a
// /etc/resolv.conf of the session's own, so a session that names a resolver
// is refused at Start.
const steersResolver = false

func steered(string, string, []string, []string, int) ([]string, error) {
	return nil, ErrNotImplemented
}

// holder: a session has no network namespace of its own on macOS.
type holder struct{ pid int }

func isolate(string, string) (*holder, error) { return nil, ErrNotImplemented }
func (*holder) bind(string, string) (net.Listener, net.PacketConn, error) {
	return nil, nil, ErrNotImplemented
}
func (*holder) stop() {}

// productProcess is the product's own process under root, the process the
// adapter started for a run. Without steering that is root itself; a
// product that forked a supervisor of its own is not looked for below it
// here (U-701).
func productProcess(root int, _ string) (int, bool) { return root, true }

// hypervisor fetches nothing: Virtualization.framework is part of the OS.
func hypervisor(context.Context, string) error { return nil }

// hostBuild compiles pkg for this Mac, with cgo, which the framework needs,
// under the build overlay file named when one is.
func hostBuild(ctx context.Context, repo, out, pkg, overlay string) error {
	return goBuild(ctx, repo, out, pkg, overlay, "CGO_ENABLED=1", "GOOS=darwin", "GOARCH=arm64")
}

// sign signs the freshly built bin ad hoc with the virtualization
// entitlement, from a plist written under dir. It happens once, before the
// binary ever runs: re-signing one that has run can get it killed (U-102).
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
