// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"io"
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

// openFlags are the only OPEN and CREATE flags the guest chooses; the host adds its own.
const openFlags = unix.O_ACCMODE | unix.O_TRUNC | unix.O_APPEND

// op serves one request that may use a descriptor. It runs with life held for reading.
func (s *Server) op(r request) ([]byte, syscall.Errno) {
	switch r.Opcode {
	case opLookup:
		p, e := s.dirAt(r.NodeID)
		if e != 0 {
			return nil, e
		}
		return s.lookup(p, r.Name)
	case opGetattr:
		var st unix.Stat_t
		if r.Flags&getattrFh != 0 {
			h, e := s.fh(r.NodeID, r.Fh)
			if e != 0 {
				return nil, e
			}
			if err := unix.Fstat(h.fd, &st); err != nil {
				return nil, errno(err)
			}
			return attrOut(validity, attrOf(&st)), 0
		}
		l, e := s.at(r.NodeID)
		if e != 0 {
			return nil, e
		}
		if st, e = stat(l); e != 0 {
			return nil, e
		}
		return attrOut(validity, attrOf(&st)), 0
	case opSetattr:
		return s.setattr(r)
	case opReadlink:
		l, e := s.at(r.NodeID)
		if e != 0 {
			return nil, e
		}
		if l.mode != unix.S_IFLNK {
			return nil, syscall.EINVAL
		}
		buf := make([]byte, pathMax)
		n, err := unix.Readlinkat(l.pfd, l.name, buf)
		if err != nil {
			return nil, errno(err)
		}
		return buf[:n], 0
	case opSymlink, opMkdir:
		p, e := s.dirAt(r.NodeID)
		if e != 0 {
			return nil, e
		}
		var err error
		if r.Opcode == opSymlink {
			err = unix.Symlinkat(r.Name2, p.fd, r.Name)
		} else {
			err = unix.Mkdirat(p.fd, r.Name, r.Mode&0o777)
		}
		if err != nil {
			return nil, errno(err)
		}
		return s.lookup(p, r.Name)
	case opUnlink, opRmdir:
		p, e := s.dirAt(r.NodeID)
		if e != 0 {
			return nil, e
		}
		flags := 0
		if r.Opcode == opRmdir {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(p.fd, r.Name, flags); err != nil {
			return nil, errno(err)
		}
		s.mu.Lock()
		s.detach(s.index[key{p.id, r.Name}])
		s.mu.Unlock()
		return nil, 0
	case opOpen:
		return s.open(r)
	case opCreate:
		return s.create(r)
	case opRead:
		h, e := s.fh(r.NodeID, r.Fh)
		if e != 0 {
			return nil, e
		}
		size := min(r.Size, MaxWrite)
		switch {
		case h.dir:
			return nil, syscall.EISDIR
		case r.Offset > math.MaxInt64-uint64(size):
			return nil, syscall.EINVAL
		}
		buf := make([]byte, size)
		n, err := unix.Pread(h.fd, buf, int64(r.Offset))
		if err != nil {
			return nil, errno(err)
		}
		return buf[:n], 0
	case opWrite:
		h, e := s.fh(r.NodeID, r.Fh)
		if e != 0 {
			return nil, e
		}
		switch {
		case h.dir:
			return nil, syscall.EISDIR
		case r.Offset > math.MaxInt64-uint64(len(r.Data)):
			return nil, syscall.EINVAL
		}
		for done := 0; done < len(r.Data); {
			n, err := unix.Pwrite(h.fd, r.Data[done:], int64(r.Offset)+int64(done))
			if err != nil {
				return nil, errno(err)
			}
			done += n
		}
		return writeOut(uint32(len(r.Data))), 0
	case opStatfs:
		l, e := s.at(rootID)
		if e != 0 {
			return nil, e
		}
		var st unix.Statfs_t
		if err := unix.Fstatfs(l.fd, &st); err != nil {
			return nil, errno(err)
		}
		return kstatfs{Blocks: st.Blocks, Bfree: st.Bfree, Bavail: st.Bavail, Files: st.Files, Ffree: st.Ffree,
			Bsize: uint32(st.Bsize), Namelen: uint32(st.Namelen), Frsize: uint32(st.Frsize)}.bytes(), 0
	case opFlush:
		_, e := s.fh(r.NodeID, r.Fh)
		return nil, e
	case opFsync, opFsyncdir:
		h, e := s.fh(r.NodeID, r.Fh)
		if e != 0 {
			return nil, e
		}
		return nil, errno(unix.Fsync(h.fd))
	case opOpendir:
		l, e := s.dirAt(r.NodeID)
		if e != 0 {
			return nil, e
		}
		fd, e := s.openFD(l.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if e != 0 {
			return nil, e
		}
		return openOut(s.newFH(&handle{fd: fd, node: l.id, dir: true})), 0
	case opReaddir, opReaddirplus:
		return s.readdir(r)
	case opAccess:
		return nil, 0
	}
	return nil, syscall.ENOSYS
}

func stat(l loc) (unix.Stat_t, syscall.Errno) {
	var st unix.Stat_t
	var err error
	if l.fd >= 0 {
		err = unix.Fstat(l.fd, &st)
	} else {
		err = unix.Fstatat(l.pfd, l.name, &st, unix.AT_SYMLINK_NOFOLLOW)
	}
	return st, errno(err)
}

func (s *Server) lookup(p loc, name string) ([]byte, syscall.Errno) {
	var st unix.Stat_t
	if err := unix.Fstatat(p.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, errno(err)
	}
	id, e := s.child(p, name, &st)
	if e != 0 {
		return nil, e
	}
	return entryOut(id, validity, attrOf(&st)), 0
}

// rename runs with life held for writing: the entry moves on disk and in the tables as one
// step, so a request racing it resolves against the old or the new shape, never a mix. A
// directory never moves under itself, so the parent chain stays acyclic whatever the disk says.
func (s *Server) rename(r request) syscall.Errno {
	op, e := s.dirAt(r.NodeID)
	if e != 0 {
		return e
	}
	np, e := s.dirAt(r.NewDir)
	if e != 0 {
		return e
	}
	s.mu.Lock()
	m := s.index[key{op.id, r.Name}]
	for n := s.nodes[np.id]; n != nil && m != nil; n = n.parent {
		if n == m {
			s.mu.Unlock()
			return syscall.EINVAL
		}
	}
	s.mu.Unlock()
	if err := unix.Renameat(op.fd, r.Name, np.fd, r.Name2); err != nil {
		return errno(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	to := key{np.id, r.Name2}
	s.detach(s.index[to])
	if newParent := s.nodes[np.id]; m != nil && newParent != nil {
		delete(s.index, key{op.id, r.Name})
		m.parent.kids--
		newParent.kids++
		m.parent, m.name = newParent, r.Name2
		s.index[to] = m
	}
	return 0
}

func (s *Server) open(r request) ([]byte, syscall.Errno) {
	l, e := s.namedAt(r.NodeID)
	switch {
	case e != 0:
	case l.mode == unix.S_IFLNK:
		e = syscall.ELOOP
	case l.mode == unix.S_IFDIR:
		e = syscall.EISDIR
	case l.mode != unix.S_IFREG:
		e = syscall.EPERM
	}
	if e != 0 {
		return nil, e
	}
	fd, _, e := s.openFile(l.pfd, l.name, int(r.Flags)&openFlags, 0)
	if e != 0 {
		return nil, e
	}
	return openOut(s.newFH(&handle{fd: fd, node: l.id})), 0
}

func (s *Server) create(r request) ([]byte, syscall.Errno) {
	p, e := s.dirAt(r.NodeID)
	if e != 0 {
		return nil, e
	}
	fd, st, e := s.openFile(p.fd, r.Name, int(r.Flags)&openFlags|unix.O_CREAT|unix.O_EXCL, r.Mode&0o777)
	if e != 0 {
		return nil, e
	}
	id, e := s.child(p, r.Name, &st)
	if e != 0 {
		s.closeFD(fd)
		return nil, e
	}
	return append(entryOut(id, validity, attrOf(&st)), openOut(s.newFH(&handle{fd: fd, node: id}))...), 0
}

// setattr changes mode, size or times. Owner is the host user and stays so: uid and gid are
// EPERM. Mode and size reach a file through a descriptor opened O_NOFOLLOW, so a symbolic
// link is EPERM and its target untouched; times reach the entry itself, never a target.
func (s *Server) setattr(r request) ([]byte, syscall.Errno) {
	a := r.Setattr
	const times = fattrAtime | fattrMtime | fattrAtimeNow | fattrMtimeNow
	switch {
	case a.Valid&(fattrUID|fattrGID) != 0:
		return nil, syscall.EPERM
	case a.Valid&fattrSize != 0 && a.Size > math.MaxInt64:
		return nil, syscall.EINVAL
	}
	fd, l := -1, loc{}
	if a.Valid&fattrFh != 0 {
		h, e := s.fh(r.NodeID, a.Fh)
		if e != 0 {
			return nil, e
		}
		if h.dir {
			return nil, syscall.EISDIR
		}
		fd = h.fd
	}
	if fd < 0 || a.Valid&times != 0 {
		var e syscall.Errno
		if l, e = s.at(r.NodeID); e != 0 {
			return nil, e
		}
		if fd < 0 {
			fd = l.fd
		}
	}
	if fd < 0 && a.Valid&(fattrMode|fattrSize) != 0 {
		if l.mode != unix.S_IFREG {
			return nil, syscall.EPERM
		}
		flags := unix.O_RDONLY
		if a.Valid&fattrSize != 0 {
			flags = unix.O_WRONLY
		}
		var e syscall.Errno
		if fd, _, e = s.openFile(l.pfd, l.name, flags, 0); e != 0 {
			return nil, e
		}
		defer s.closeFD(fd)
	}
	if a.Valid&fattrMode != 0 {
		if err := unix.Fchmod(fd, a.Mode&0o777); err != nil {
			return nil, errno(err)
		}
	}
	if a.Valid&fattrSize != 0 {
		if l.mode == unix.S_IFDIR {
			return nil, syscall.EISDIR
		}
		if err := unix.Ftruncate(fd, int64(a.Size)); err != nil {
			return nil, errno(err)
		}
	}
	if a.Valid&times != 0 {
		ts := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
		for i, t := range []struct {
			set, now  uint32
			sec, nsec uint64
		}{{fattrAtime, fattrAtimeNow, a.Atime, uint64(a.Atimensec)}, {fattrMtime, fattrMtimeNow, a.Mtime, uint64(a.Mtimensec)}} {
			switch {
			case a.Valid&t.now != 0:
				ts[i].Nsec = unix.UTIME_NOW
			case a.Valid&t.set != 0:
				ts[i] = unix.Timespec{Sec: int64(t.sec), Nsec: int64(t.nsec)}
			}
		}
		var err error
		if l.fd >= 0 {
			err = unix.UtimesNanoAt(l.fd, ".", ts, 0)
		} else {
			err = unix.UtimesNanoAt(l.pfd, l.name, ts, unix.AT_SYMLINK_NOFOLLOW)
		}
		if err != nil {
			return nil, errno(err)
		}
	}
	var st unix.Stat_t
	var e syscall.Errno
	if fd >= 0 {
		e = errno(unix.Fstat(fd, &st))
	} else {
		st, e = stat(l)
	}
	if e != 0 {
		return nil, e
	}
	return attrOut(validity, attrOf(&st)), 0
}

// readdir lists from the handle's own descriptor, positioned at the offset the kernel gives
// back, which is the cookie of the entry after the last one it took. Nothing is cached, so a
// directory of any size costs one 8 KiB buffer per call. READDIRPLUS makes a node per entry,
// as a LOOKUP would; an entry that cannot get one (cap reached) goes out with node 0, so the
// listing stays complete and the kernel's own LOOKUP reports the error.
func (s *Server) readdir(r request) ([]byte, syscall.Errno) {
	h, e := s.fh(r.NodeID, r.Fh)
	if e != 0 {
		return nil, e
	}
	if !h.dir {
		return nil, syscall.ENOTDIR
	}
	l, e := s.dirAt(r.NodeID)
	switch {
	case e != 0:
		return nil, e
	case r.Offset > math.MaxInt64:
		return nil, syscall.EINVAL
	}
	plus := r.Opcode == opReaddirplus
	size := int(min(r.Size, MaxWrite))
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := unix.Seek(h.fd, int64(r.Offset), io.SeekStart); err != nil {
		return nil, errno(err)
	}
	buf := make([]byte, 8192)
	var out []byte
	for {
		n, err := unix.ReadDirent(h.fd, buf)
		if err != nil {
			return nil, errno(err)
		}
		if n == 0 {
			return out, 0
		}
		for b := buf[:n]; len(b) >= 19; {
			reclen := int(le.Uint16(b[16:]))
			if reclen < 19 || reclen > len(b) {
				return nil, syscall.EIO
			}
			ino, off, typ := le.Uint64(b), le.Uint64(b[8:]), uint32(b[18])
			name := b[19:reclen]
			for i, c := range name {
				if c == 0 {
					name = name[:i]
					break
				}
			}
			b = b[reclen:]
			if checkName(string(name)) != nil { // "." and ".." carry nothing a guest needs
				continue
			}
			if len(out)+direntSize(string(name), plus) > size {
				return out, 0
			}
			var entry []byte
			if plus {
				var st unix.Stat_t
				if unix.Fstatat(l.fd, string(name), &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
					continue // gone since getdents
				}
				entry = make([]byte, entryOutLen)
				if id, e := s.child(l, string(name), &st); e == 0 {
					entry = entryOut(id, validity, attrOf(&st))
				}
				ino, typ = st.Ino, (st.Mode&unix.S_IFMT)>>12
			}
			out = appendDirent(out, entry, ino, off, typ, string(name))
		}
	}
}

// attrOf is what the guest sees of st: owner root, no device numbers.
func attrOf(st *unix.Stat_t) attr {
	return attr{Ino: st.Ino, Size: uint64(st.Size), Blocks: uint64(st.Blocks),
		Atime: uint64(st.Atim.Sec), Mtime: uint64(st.Mtim.Sec), Ctime: uint64(st.Ctim.Sec),
		Atimensec: uint32(st.Atim.Nsec), Mtimensec: uint32(st.Mtim.Nsec), Ctimensec: uint32(st.Ctim.Nsec),
		Mode: st.Mode, Nlink: uint32(st.Nlink), Blk: uint32(st.Blksize)}
}
