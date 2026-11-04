// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || darwin

package guest

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Walk describes what lies under the directory open as root, which it closes: one Entry
// per member, in name order, every directory before what it holds. It goes by directory
// descriptors and reports a symlink as the link it is, never following one; it leaves out
// sockets, FIFOs and devices, and anything named .git in any case. The init walks the
// guest's workspace with it and the host walks its own directory with it, so both see a
// tree by the same rules; it describes, and enforces nothing (A1).
func Walk(root int, visit func(Entry) error) error { return walk(root, "", visit) }

func walk(fd int, rel string, visit func(Entry) error) error {
	d := os.NewFile(uintptr(fd), cmp.Or(rel, "."))
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("read %s: %w", d.Name(), err)
	}
	slices.Sort(names)
	for _, name := range names {
		if strings.EqualFold(name, ".git") {
			continue
		}
		p := name
		if rel != "" {
			p = rel + "/" + name
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		e, cfd := Entry{Path: p}, -1
		switch uint32(st.Mode) & unix.S_IFMT {
		case unix.S_IFDIR:
			if cfd, err = unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err != nil {
				return fmt.Errorf("open %s: %w", p, err)
			}
			e.Kind = KindDir
		case unix.S_IFLNK:
			buf := make([]byte, MaxPath+1)
			n, err := unix.Readlinkat(fd, name, buf)
			if err != nil {
				return fmt.Errorf("read link %s: %w", p, err)
			}
			e.Kind, e.Target = KindLink, string(buf[:n])
		case unix.S_IFREG:
			e.Kind, e.Exec, e.Size = KindFile, st.Mode&0o100 != 0, st.Size
		default:
			continue
		}
		if err := visit(e); err != nil {
			if cfd >= 0 {
				_ = unix.Close(cfd)
			}
			return err
		}
		if cfd >= 0 {
			if err := walk(cfd, p, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
