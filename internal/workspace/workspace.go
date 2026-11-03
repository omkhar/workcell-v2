// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package workspace exports a repository to a guest as an ext4 image (clone mode, A5). The
// repository is attacker content (R6): the walk goes by directory descriptors and never
// follows a symlink, so the guest cannot be handed a host path outside the directory (I1).
// A symlink is copied as the link it is, a file is shared with the image where the
// filesystem can reflink and copied where it cannot, and a socket, FIFO or device is
// left out. Everything else goes in: .git, ignored files, all of it. Every entry is
// owned by root in the image, because that is who the agent is in the guest, and git
// refuses a repository that another user owns.
package workspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/omkhar/workcell/v2/internal/rootfs"
	"golang.org/x/sys/unix"
)

// Stats is what an export did.
type Stats struct {
	Files          int   // regular files, each name of a hard link counted
	Bytes          int64 // their data, a hard-linked file once
	Cloned, Copied int   // files whose data was shared with the image, and files whose data was copied
	Elapsed        time.Duration
}

// Export writes the directory dir to a new file at imagePath as an ext4 image with free
// bytes of room for the guest to write. The image is sparse, and it is removed again if
// the export fails.
func Export(ctx context.Context, dir, imagePath string, free int64) (st Stats, err error) {
	start := time.Now()
	root, err := filepath.Abs(dir)
	if err != nil {
		return st, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return st, fmt.Errorf("open %s: %w", root, err)
	}
	img, err := os.OpenFile(imagePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = unix.Close(fd)
		return st, err
	}
	defer func() {
		if cerr := img.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(imagePath)
		}
	}()
	var self unix.Stat_t // the image may lie inside dir; it is not part of the export
	if err := unix.Fstat(int(img.Fd()), &self); err != nil {
		_ = unix.Close(fd)
		return st, err
	}
	w := &walker{ctx: ctx, root: root, tree: rootfs.NewTree(), self: self, links: map[[2]uint64]string{}}
	var rs unix.Stat_t
	if err := unix.Fstat(fd, &rs); err != nil {
		_ = unix.Close(fd)
		return st, err
	}
	w.tree.Lookup("/").Mode = uint32(rs.Mode) & 0o7777
	if err := w.dir(fd, ""); err != nil {
		return st, err
	}
	fs, err := w.tree.WriteExt4File(img, time.Now(), free)
	if err != nil {
		return st, err
	}
	return Stats{w.files, w.bytes, fs.Cloned, fs.Copied, time.Since(start)}, nil
}

type walker struct {
	ctx   context.Context
	root  string
	tree  *rootfs.Tree
	self  unix.Stat_t
	links map[[2]uint64]string // (device, inode) of a file with more than one name, to its first path
	files int
	bytes int64
}

// dir adds the entries of the directory open as fd, whose path in the tree is rel, and closes fd.
func (w *walker) dir(fd int, rel string) error {
	d := os.NewFile(uintptr(fd), rel)
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Join(w.root, rel), err)
	}
	for _, name := range names {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		if err := w.entry(fd, rel, name); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) entry(fd int, rel, name string) error {
	p := rel + "/" + name
	host := filepath.Join(w.root, p)
	var st unix.Stat_t
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s: %w", host, err)
	}
	if st.Dev == w.self.Dev && st.Ino == w.self.Ino {
		return nil
	}
	n := rootfs.Node{Mode: uint32(st.Mode) & 0o7777}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFDIR:
		cfd, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", host, err)
		}
		n.Kind = rootfs.Dir
		if err := w.tree.Put(p, n); err != nil {
			_ = unix.Close(cfd)
			return err
		}
		return w.dir(cfd, p)
	case unix.S_IFLNK:
		buf := make([]byte, 4097)
		l, err := unix.Readlinkat(fd, name, buf)
		if err != nil {
			return fmt.Errorf("read link %s: %w", host, err)
		}
		n.Kind, n.Target = rootfs.Symlink, string(buf[:l])
	case unix.S_IFREG:
		w.files++
		key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
		if first, ok := w.links[key]; ok {
			return w.tree.Link(first, p)
		}
		if uint64(st.Nlink) > 1 {
			w.links[key] = p
		}
		n.Kind = rootfs.File
		if st.Size > 0 {
			n.Source = &rootfs.HostFile{Path: host, Size: st.Size, Dev: uint64(st.Dev), Ino: uint64(st.Ino)}
			w.bytes += st.Size
		}
	default:
		return nil // a socket, FIFO or device: nothing a guest could use
	}
	if err := w.tree.Put(p, n); err != nil {
		return fmt.Errorf("%s: %w", host, err)
	}
	return nil
}
