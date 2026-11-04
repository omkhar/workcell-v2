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
	"os"
	"path/filepath"
	"runtime"
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
