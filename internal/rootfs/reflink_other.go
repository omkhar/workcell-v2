// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package rootfs

import (
	"errors"
	"os"
)

// cloneRange is unsupported here, so every file is copied. macOS clonefile(2) clones a
// whole file to a new path; it cannot place a file's blocks inside an image.
func cloneRange(dst, src *os.File, srcOff, n, dstOff int64) error {
	return errors.ErrUnsupported
}
