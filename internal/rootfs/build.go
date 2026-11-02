// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"time"
)

// maxGuest caps the guest image (A6). A base that would expand past it is refused.
const maxGuest = 400 << 20

// Result describes one finished build.
type Result struct {
	Manifest string // digest of the per-platform image manifest that was pulled
	Digest   string // sha256:<hex> of the ext4 image bytes
	Size     int64  // length of the ext4 image in bytes
}

// Build pulls img and writes it to w as a read-only root image. The same pinned
// input gives the same bytes and so the same Digest (A6). Nothing is run and
// nothing touches the disk here: w is the caller's (A8).
func Build(ctx context.Context, client *http.Client, img Image, w io.Writer) (Result, error) {
	t := NewTree()
	manifest, err := Pull(ctx, client, img, t)
	if err != nil {
		return Result{}, err
	}
	lw := &limitWriter{ctx: ctx, w: w, h: sha256.New(), limit: maxGuest}
	if err := t.WriteExt4(lw, time.Time{}); err != nil {
		return Result{}, err
	}
	return Result{Manifest: manifest, Digest: "sha256:" + hex.EncodeToString(lw.h.Sum(nil)), Size: lw.n}, nil
}

// limitWriter hashes and counts what it passes on, and fails once the context is
// done or more than limit bytes have been written.
type limitWriter struct {
	ctx   context.Context
	w     io.Writer
	h     hash.Hash
	n     int64
	limit int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if err := l.ctx.Err(); err != nil {
		return 0, bare(err)
	}
	if int64(len(p)) > l.limit-l.n {
		return 0, fmt.Errorf("%w: the image would pass %d MiB", ErrTooLarge, l.limit>>20)
	}
	n, err := l.w.Write(p)
	l.h.Write(p[:n])
	l.n += int64(n)
	return n, err
}
