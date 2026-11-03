// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneRange shares n bytes of src, from srcOff, with dst at dstOff, without copying them
// (FICLONERANGE: btrfs, XFS with reflink, bcachefs). Both offsets are multiples of the
// block size, and n is too unless the range ends at the end of src. Any error, such as
// EXDEV or EOPNOTSUPP, means nothing was shared and the caller copies.
func cloneRange(dst, src *os.File, srcOff, n, dstOff int64) error {
	return unix.IoctlFileCloneRange(int(dst.Fd()), &unix.FileCloneRange{
		Src_fd: int64(src.Fd()), Src_offset: uint64(srcOff), Src_length: uint64(n), Dest_offset: uint64(dstOff)})
}
