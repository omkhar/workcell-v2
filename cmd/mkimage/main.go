// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command mkimage builds the guest root image from a pinned OCI base (A6, A10). It
// is a build-time tool, not a workcell verb. It runs nothing and needs no shell (A8).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/omkhar/workcell/v2/internal/pins"
	"github.com/omkhar/workcell/v2/internal/rootfs"
)

func main() {
	pin := flag.String("pin", "pins/debian.json", "pin file of the OCI base image")
	arch := flag.String("arch", runtime.GOARCH, "amd64 or arm64")
	out := flag.String("o", "", "output image path (required)")
	flag.Parse()
	if *out == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: mkimage [-pin file] [-arch amd64|arm64] -o image")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *pin, *arch, *out); err != nil {
		fmt.Fprintln(os.Stderr, "mkimage:", err)
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context, pinFile, arch, out string) error {
	b, err := os.ReadFile(pinFile)
	if err != nil {
		return err
	}
	var p pins.Pin
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("%s: %w", pinFile, err)
	}
	img, err := imageFromPin(p, arch)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	res, err := rootfs.Build(ctx, http.DefaultClient, img, f)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(out)
		return err
	}
	fmt.Println(res.Digest, res.Size, out)
	return nil
}

// imageFromPin turns an OCI pin row into the image to pull for arch.
func imageFromPin(p pins.Pin, arch string) (rootfs.Image, error) {
	if p.Source != pins.OCI {
		return rootfs.Image{}, errors.New("the pin is not an OCI image")
	}
	bad := errors.New("the pin locator is not https://host/v2/repository")
	u, err := url.Parse(p.Locator)
	if err != nil {
		return rootfs.Image{}, bad
	}
	repo, ok := strings.CutPrefix(u.Path, "/v2/")
	if u.Scheme != "https" || u.Host == "" || !ok || repo == "" || u.RawQuery != "" || u.User != nil {
		return rootfs.Image{}, bad
	}
	return rootfs.Image{Registry: "https://" + u.Host, Repository: repo, Digest: "sha256:" + p.Artifacts[arch].SHA256, OS: "linux", Arch: arch}, nil
}
