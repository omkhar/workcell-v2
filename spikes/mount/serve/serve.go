// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Package serve is the U-502a spike's host side of a FUSE mount: it answers the guest
// kernel's raw FUSE requests, which arrive verbatim in wire frames, against one exported
// directory. Every path operation is relative to a directory descriptor and never follows
// a symbolic link (R6); a node is (parent, name), and only LOOKUP, CREATE, MKDIR, SYMLINK,
// UNLINK, RMDIR and RENAME carry names.
package serve

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"github.com/omkhar/workcell/v2/spikes/mount/fuse"
	"golang.org/x/sys/unix"
)

const (
	workers = 16   // requests served at once
	maxFDs  = 4096 // descriptors the guest can make this process hold (I10)
)

type node struct {
	id      uint64
	parent  *node  // nil for the root
	name    string // "" once unlinked or replaced
	ino     uint64
	mode    uint32 // the S_IFMT bits
	fd      int    // a directory's own descriptor, else -1
	nlookup uint64
	kids    int // nodes whose parent this is
}

type key struct {
	parent uint64
	name   string
}

type handle struct {
	fd   int     // an open file; -1 for a directory
	dir  uint64  // a directory's node
	ents []entry // a directory's listing, read once at OPENDIR
}

type entry struct {
	name string
	st   unix.Stat_t
}

// loc is a copy of what a syscall on one node needs.
type loc struct {
	id       uint64
	pfd, fd  int // the parent's descriptor (-1 for the root); the node's own (-1 unless a directory)
	name     string
	mode     uint32
	detached bool
}

// Step is what the server did since the last call of Step.
type Step struct {
	Requests, Errors int64
	Ops              [fuse.MaxOpcode]int64
	FirstError       string
	InflightPeak     int
}

func (s Step) String() string {
	var ops []string
	for op, n := range s.Ops {
		if n > 0 {
			ops = append(ops, fmt.Sprintf("%s:%d", fuse.OpName(uint32(op)), n))
		}
	}
	first := s.FirstError
	if first == "" {
		first = "none"
	}
	return fmt.Sprintf("fs_requests=%d fs_ops=%s fs_errors=%d fs_first_error=%s fs_inflight_peak=%d", s.Requests,
		strings.Join(ops, ","), s.Errors, first, s.InflightPeak)
}

// Server is one export. Its methods are safe for concurrent use.
type Server struct {
	life sync.RWMutex // held for writing only where a descriptor may close
	mu   sync.Mutex   // nodes, index, fhs, every node's fields, the counters below
	// nodes and handles
	nodes          map[uint64]*node
	index          map[key]*node
	fhs            map[uint64]*handle
	nextID, nextFH uint64
	fds            int
	valid          atomic.Int64 // entry and attribute timeout, ns
	// counters
	step, total                   Step
	inflight                      int
	nodesPeak, filesPeak, fdsPeak int
	initIn                        fuse.InitIn
	initFlags                     uint32
	inited                        bool
	writeErr                      error
	badFrames                     int64 // of another type, or shorter than a header
}

// New opens the export, which must be a directory and not a symbolic link.
func New(root string, valid time.Duration) (*Server, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open export %s: %w", root, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	r := &node{id: fuse.RootID, ino: st.Ino, mode: unix.S_IFDIR, fd: fd, nlookup: 1}
	s := &Server{nodes: map[uint64]*node{fuse.RootID: r}, index: map[key]*node{}, fhs: map[uint64]*handle{},
		nextID: fuse.RootID, fds: 1, fdsPeak: 1, nodesPeak: 1}
	s.SetValid(valid)
	return s, nil
}

// SetValid sets the entry and attribute timeout of every later reply.
func (s *Server) SetValid(d time.Duration) { s.valid.Store(int64(d)) }

func (s *Server) timeout() time.Duration { return time.Duration(s.valid.Load()) }

// Step returns the counters since the last call and starts new ones.
func (s *Server) Step() Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.step
	s.step = Step{}
	return st
}

// Totals is the log line of the whole mount's peaks.
func (s *Server) Totals() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("fs_nodes_peak=%d fs_open_files_peak=%d host_fds_peak=%d fs_nodes_end=%d host_fds_end=%d fs_requests_total=%d fs_errors_total=%d fs_bad_frames=%d fs_reply_write_err=%v",
		s.nodesPeak, s.filesPeak, s.fdsPeak, len(s.nodes), s.fds, s.total.Requests, s.total.Errors, s.badFrames,
		s.writeErr != nil)
}

// Init is the kernel's INIT and the flags returned, once the handshake happened.
func (s *Server) Init() (fuse.InitIn, uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initIn, s.initFlags, s.inited
}

// Close releases every descriptor. Call it after Serve returned.
func (s *Server) Close() {
	s.life.Lock()
	defer s.life.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		if n.fd >= 0 {
			_ = unix.Close(n.fd)
		}
	}
	for _, h := range s.fhs {
		if h.fd >= 0 {
			_ = unix.Close(h.fd)
		}
	}
	s.nodes, s.fhs, s.index, s.fds = map[uint64]*node{}, map[uint64]*handle{}, map[key]*node{}, 0
}

// Serve answers requests until the stream ends: nil at a clean end of stream.
func (s *Server) Serve(c *wire.Conn) error {
	var wmu sync.Mutex
	send := func(b []byte) {
		wmu.Lock()
		err := c.WriteFrame(wire.Frame{Type: fuse.FrameType, Payload: b})
		wmu.Unlock()
		if err != nil {
			s.mu.Lock()
			if s.writeErr == nil {
				s.writeErr = err
			}
			s.mu.Unlock()
		}
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		f, err := c.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if f.Type != fuse.FrameType {
			s.count(func() { s.badFrames++ })
			continue
		}
		r, err := fuse.Parse(f.Payload)
		if errors.Is(err, fuse.ErrShort) {
			s.count(func() { s.badFrames++ })
			continue
		}
		s.count(func() {
			s.step.Requests++
			s.total.Requests++
			if r.Opcode < fuse.MaxOpcode {
				s.step.Ops[r.Opcode]++
			}
		})
		if err != nil {
			if r.Opcode != fuse.OpForget && r.Opcode != fuse.OpBatchForget && r.Opcode != fuse.OpInterrupt {
				send(s.out(r, syscall.EINVAL, nil))
			}
			continue
		}
		if r.Opcode == fuse.OpInit {
			body, flags := fuse.InitOut(r.Init)
			s.count(func() { s.initIn, s.initFlags, s.inited = r.Init, flags, true })
			send(s.out(r, 0, body))
			continue
		}
		sem <- struct{}{}
		s.count(func() { s.inflight++; s.step.InflightPeak = max(s.step.InflightPeak, s.inflight) })
		wg.Go(func() {
			defer func() { <-sem }()
			b := s.handle(r)
			s.count(func() { s.inflight-- })
			if b != nil {
				send(b)
			}
		})
	}
}

func (s *Server) count(f func()) {
	s.mu.Lock()
	f()
	s.mu.Unlock()
}

// out is the reply to r, and counts an error.
func (s *Server) out(r fuse.Request, e syscall.Errno, body []byte) []byte {
	if e != 0 {
		body = nil
		s.count(func() {
			s.step.Errors++
			s.total.Errors++
			if s.step.FirstError == "" {
				s.step.FirstError = fuse.OpName(r.Opcode) + ":" + unix.ErrnoName(e)
			}
		})
	}
	return fuse.Out(r.Unique, e, body)
}

// handle serves one request; nil means no reply.
func (s *Server) handle(r fuse.Request) []byte {
	switch r.Opcode {
	case fuse.OpForget, fuse.OpBatchForget:
		s.forget(r.Forgets)
		return nil
	case fuse.OpInterrupt:
		return nil
	case fuse.OpRelease, fuse.OpReleasedir:
		return s.out(r, s.release(r.Fh), nil)
	}
	s.life.RLock()
	defer s.life.RUnlock()
	body, e := s.op(r)
	return s.out(r, e, body)
}

func (s *Server) op(r fuse.Request) ([]byte, syscall.Errno) {
	switch r.Opcode {
	case fuse.OpLookup:
		p, e := s.dirLoc(r.NodeID)
		if e != 0 {
			return nil, e
		}
		return s.lookup(p, r.Name)
	case fuse.OpGetattr:
		if r.Flags&fuse.GetattrFh != 0 {
			if fd, e := s.fileFD(r.Fh); e == 0 {
				var st unix.Stat_t
				if err := unix.Fstat(fd, &st); err != nil {
					return nil, errno(err)
				}
				return fuse.AttrOut(s.timeout(), attr(&st)), 0
			}
		}
		l, e := s.loc(r.NodeID)
		if e != 0 {
			return nil, e
		}
		st, e := stat(l)
		if e != 0 {
			return nil, e
		}
		return fuse.AttrOut(s.timeout(), attr(&st)), 0
	case fuse.OpSetattr:
		return s.setattr(r)
	case fuse.OpReadlink:
		l, e := s.named(r.NodeID)
		if e != 0 {
			return nil, e
		}
		buf := make([]byte, fuse.PathMax)
		n, err := unix.Readlinkat(l.pfd, l.name, buf)
		if err != nil {
			return nil, errno(err)
		}
		return buf[:n], 0
	case fuse.OpSymlink, fuse.OpMkdir:
		p, e := s.dirLoc(r.NodeID)
		if e != 0 {
			return nil, e
		}
		var err error
		if r.Opcode == fuse.OpSymlink {
			err = unix.Symlinkat(r.Name2, p.fd, r.Name)
		} else {
			err = unix.Mkdirat(p.fd, r.Name, r.Mode&0o7777)
		}
		if err != nil {
			return nil, errno(err)
		}
		return s.lookup(p, r.Name)
	case fuse.OpUnlink, fuse.OpRmdir:
		p, e := s.dirLoc(r.NodeID)
		if e != 0 {
			return nil, e
		}
		flags := 0
		if r.Opcode == fuse.OpRmdir {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(p.fd, r.Name, flags); err != nil {
			return nil, errno(err)
		}
		s.mu.Lock()
		s.detach(s.index[key{p.id, r.Name}])
		s.mu.Unlock()
		return nil, 0
	case fuse.OpRename:
		return s.rename(r)
	case fuse.OpOpen:
		return s.open(r)
	case fuse.OpCreate:
		return s.create(r)
	case fuse.OpRead:
		fd, e := s.fileFD(r.Fh)
		if e != 0 {
			return nil, e
		}
		buf := make([]byte, min(int(r.Size), fuse.MaxReply-fuse.OutHeaderLen))
		n, err := unix.Pread(fd, buf, int64(r.Offset))
		if err != nil {
			return nil, errno(err)
		}
		return buf[:n], 0
	case fuse.OpWrite:
		fd, e := s.fileFD(r.Fh)
		if e != 0 {
			return nil, e
		}
		n, err := unix.Pwrite(fd, r.Data, int64(r.Offset))
		if err != nil {
			return nil, errno(err)
		}
		return fuse.WriteOut(uint32(n)), 0
	case fuse.OpStatfs:
		var st unix.Statfs_t
		if err := unix.Fstatfs(s.rootFD(), &st); err != nil {
			return nil, errno(err)
		}
		return fuse.Kstatfs{Blocks: st.Blocks, Bfree: st.Bfree, Bavail: st.Bavail, Files: st.Files, Ffree: st.Ffree,
			Bsize: uint32(st.Bsize), Namelen: uint32(st.Namelen), Frsize: uint32(st.Frsize)}.Bytes(), 0
	case fuse.OpFlush:
		_, e := s.fileFD(r.Fh)
		return nil, e
	case fuse.OpFsync:
		fd, e := s.fileFD(r.Fh)
		if e != 0 {
			return nil, e
		}
		return nil, errno(unix.Fsync(fd))
	case fuse.OpOpendir:
		return s.opendir(r)
	case fuse.OpReaddir, fuse.OpReaddirplus:
		return s.readdir(r)
	case fuse.OpAccess:
		return nil, 0
	}
	return nil, syscall.ENOSYS
}

func (s *Server) rootFD() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodes[fuse.RootID].fd
}

func (s *Server) loc(id uint64) (loc, syscall.Errno) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.nodes[id]
	if n == nil {
		return loc{}, syscall.EINVAL
	}
	l := loc{id: id, pfd: -1, fd: n.fd, name: n.name, mode: n.mode}
	if n.parent != nil {
		l.pfd, l.detached = n.parent.fd, n.name == ""
	}
	return l, 0
}

// dirLoc is a directory's location; only a directory node has a descriptor.
func (s *Server) dirLoc(id uint64) (loc, syscall.Errno) {
	l, e := s.loc(id)
	if e == 0 && l.fd < 0 {
		e = syscall.ENOTDIR
	}
	return l, e
}

// named is the location of a node that has a parent and still a name.
func (s *Server) named(id uint64) (loc, syscall.Errno) {
	l, e := s.loc(id)
	switch {
	case e != 0:
	case l.pfd < 0:
		e = syscall.EISDIR
	case l.detached:
		e = syscall.ENOENT
	}
	return l, e
}

func stat(l loc) (unix.Stat_t, syscall.Errno) {
	var st unix.Stat_t
	var err error
	switch {
	case l.fd >= 0:
		err = unix.Fstat(l.fd, &st)
	case l.detached:
		return st, syscall.ENOENT
	default:
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
	return fuse.EntryOut(id, s.timeout(), attr(&st)), 0
}

// child is the node of name in directory p, with one more lookup counted. A directory gets
// its own descriptor, and st is refreshed from it.
func (s *Server) child(p loc, name string, st *unix.Stat_t) (uint64, syscall.Errno) {
	fd := -1
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		var e syscall.Errno
		if fd, e = s.openFD(p.fd, name, unix.O_RDONLY|unix.O_DIRECTORY, 0); e != 0 {
			return 0, e
		}
		if err := unix.Fstat(fd, st); err != nil {
			s.closeFD(fd)
			return 0, errno(err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := s.nodes[p.id]
	if parent == nil {
		s.closeFDLocked(fd)
		return 0, syscall.EINVAL
	}
	k := key{p.id, name}
	if n := s.index[k]; n != nil {
		if n.ino == st.Ino && n.mode == st.Mode&unix.S_IFMT {
			n.nlookup++
			s.closeFDLocked(fd) // private until now, so no one can be using it
			return n.id, 0
		}
		s.detach(n)
	}
	s.nextID++
	n := &node{id: s.nextID, parent: parent, name: name, ino: st.Ino, mode: st.Mode & unix.S_IFMT, fd: fd, nlookup: 1}
	parent.kids++
	s.nodes[n.id], s.index[k] = n, n
	s.nodesPeak = max(s.nodesPeak, len(s.nodes))
	return n.id, 0
}

// detach takes n's name away: it was unlinked or replaced. Call with mu held.
func (s *Server) detach(n *node) {
	if n == nil || n.parent == nil || n.name == "" {
		return
	}
	if k := (key{n.parent.id, n.name}); s.index[k] == n {
		delete(s.index, k)
	}
	n.name = ""
}

func (s *Server) forget(fs []fuse.Forget) {
	s.life.Lock()
	defer s.life.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range fs {
		n := s.nodes[f.NodeID]
		if n == nil || n.parent == nil {
			continue
		}
		n.nlookup -= min(f.N, n.nlookup)
		for n != nil && n.parent != nil && n.nlookup == 0 && n.kids == 0 {
			s.detach(n)
			delete(s.nodes, n.id)
			s.closeFDLocked(n.fd)
			n.parent.kids--
			n = n.parent
		}
	}
}

func (s *Server) rename(r fuse.Request) ([]byte, syscall.Errno) {
	op, e := s.dirLoc(r.NodeID)
	if e != 0 {
		return nil, e
	}
	np, e := s.dirLoc(r.NewDir)
	if e != 0 {
		return nil, e
	}
	if err := unix.Renameat(op.fd, r.Name, np.fd, r.Name2); err != nil {
		return nil, errno(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	to := key{np.id, r.Name2}
	s.detach(s.index[to])
	newParent := s.nodes[np.id]
	if m := s.index[key{op.id, r.Name}]; m != nil && newParent != nil {
		delete(s.index, key{op.id, r.Name})
		m.parent.kids--
		newParent.kids++
		m.parent, m.name = newParent, r.Name2
		s.index[to] = m
	}
	return nil, 0
}

func (s *Server) open(r fuse.Request) ([]byte, syscall.Errno) {
	l, e := s.named(r.NodeID)
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
	fd, e := s.openFD(l.pfd, l.name, int(r.Flags)&(unix.O_ACCMODE|unix.O_TRUNC|unix.O_APPEND), 0)
	if e != 0 {
		return nil, e
	}
	return fuse.OpenOut(s.newFH(&handle{fd: fd})), 0
}

func (s *Server) create(r fuse.Request) ([]byte, syscall.Errno) {
	p, e := s.dirLoc(r.NodeID)
	if e != 0 {
		return nil, e
	}
	flags := int(r.Flags)&(unix.O_ACCMODE|unix.O_TRUNC|unix.O_APPEND) | unix.O_CREAT | unix.O_EXCL
	fd, e := s.openFD(p.fd, r.Name, flags, r.Mode&0o7777)
	if e != 0 {
		return nil, e
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		s.closeFD(fd)
		return nil, errno(err)
	}
	id, e := s.child(p, r.Name, &st)
	if e != 0 {
		s.closeFD(fd)
		return nil, e
	}
	return append(fuse.EntryOut(id, s.timeout(), attr(&st)), fuse.OpenOut(s.newFH(&handle{fd: fd}))...), 0
}

func (s *Server) setattr(r fuse.Request) ([]byte, syscall.Errno) {
	a := r.Setattr
	l, e := s.loc(r.NodeID)
	if e != 0 {
		return nil, e
	}
	if a.Valid&(fuse.FattrUID|fuse.FattrGID) != 0 {
		return nil, syscall.EPERM
	}
	fd := l.fd // a directory's, or the open file's, or one opened here
	if a.Valid&fuse.FattrFh != 0 && l.fd < 0 {
		if fd, e = s.fileFD(a.Fh); e != 0 {
			return nil, e
		}
	}
	if a.Valid&(fuse.FattrMode|fuse.FattrSize) != 0 && fd < 0 {
		if l, e = s.named(r.NodeID); e != 0 {
			return nil, e
		}
		if l.mode != unix.S_IFREG {
			return nil, syscall.EPERM
		}
		flags := unix.O_RDONLY
		if a.Valid&fuse.FattrSize != 0 {
			flags = unix.O_WRONLY
		}
		if fd, e = s.openFD(l.pfd, l.name, flags, 0); e != 0 {
			return nil, e
		}
		defer s.closeFD(fd)
	}
	if a.Valid&fuse.FattrMode != 0 {
		if err := unix.Fchmod(fd, a.Mode&0o7777); err != nil {
			return nil, errno(err)
		}
	}
	if a.Valid&fuse.FattrSize != 0 {
		if l.mode == unix.S_IFDIR {
			return nil, syscall.EISDIR
		}
		if err := unix.Ftruncate(fd, int64(a.Size)); err != nil {
			return nil, errno(err)
		}
	}
	if a.Valid&(fuse.FattrAtime|fuse.FattrMtime|fuse.FattrAtimeNow|fuse.FattrMtimeNow) != 0 {
		ts := []unix.Timespec{{Nsec: unix.UTIME_OMIT}, {Nsec: unix.UTIME_OMIT}}
		for i, t := range []struct {
			set, now  uint32
			sec, nsec uint64
		}{{fuse.FattrAtime, fuse.FattrAtimeNow, a.Atime, uint64(a.Atimensec)}, {fuse.FattrMtime, fuse.FattrMtimeNow, a.Mtime, uint64(a.Mtimensec)}} {
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
		} else if l, e = s.named(r.NodeID); e != 0 {
			return nil, e
		} else {
			err = unix.UtimesNanoAt(l.pfd, l.name, ts, unix.AT_SYMLINK_NOFOLLOW)
		}
		if err != nil {
			return nil, errno(err)
		}
	}
	var st unix.Stat_t
	var err error
	if fd >= 0 {
		err = unix.Fstat(fd, &st)
	} else {
		st, e = stat(l)
	}
	if err != nil {
		e = errno(err)
	}
	if e != 0 {
		return nil, e
	}
	return fuse.AttrOut(s.timeout(), attr(&st)), 0
}

func (s *Server) opendir(r fuse.Request) ([]byte, syscall.Errno) {
	l, e := s.dirLoc(r.NodeID)
	if e != 0 {
		return nil, e
	}
	fd, e := s.openFD(l.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != 0 {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "dir")
	names, err := f.Readdirnames(-1)
	_ = f.Close()
	s.count(func() { s.fds-- })
	if err != nil {
		return nil, errno(err)
	}
	slices.Sort(names)
	ents := make([]entry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		if fuse.CheckName(name) == nil && unix.Fstatat(l.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
			ents = append(ents, entry{name, st})
		}
	}
	return fuse.OpenOut(s.newFH(&handle{fd: -1, dir: l.id, ents: ents})), 0
}

func (s *Server) readdir(r fuse.Request) ([]byte, syscall.Errno) {
	s.mu.Lock()
	h := s.fhs[r.Fh]
	s.mu.Unlock()
	if h == nil || h.fd >= 0 {
		return nil, syscall.EINVAL
	}
	l, e := s.dirLoc(h.dir)
	if e != 0 {
		return nil, e
	}
	plus := r.Opcode == fuse.OpReaddirplus
	size := min(int(r.Size), fuse.MaxReply-fuse.OutHeaderLen)
	var b []byte
	for i := r.Offset; i < uint64(len(h.ents)); i++ {
		en := h.ents[i]
		if len(b)+fuse.DirentSize(en.name, plus) > size {
			break
		}
		var out []byte
		if plus {
			st := en.st
			id, e := s.child(l, en.name, &st)
			if e != 0 {
				continue // gone since OPENDIR
			}
			out = fuse.EntryOut(id, s.timeout(), attr(&st))
		}
		b = fuse.AppendDirent(b, out, en.st.Ino, i+1, (en.st.Mode&unix.S_IFMT)>>12, en.name)
	}
	return b, 0
}

func (s *Server) newFH(h *handle) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextFH++
	s.fhs[s.nextFH] = h
	s.filesPeak = max(s.filesPeak, len(s.fhs))
	return s.nextFH
}

func (s *Server) fileFD(fh uint64) (int, syscall.Errno) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.fhs[fh]; h != nil && h.fd >= 0 {
		return h.fd, 0
	}
	return -1, syscall.EINVAL
}

func (s *Server) release(fh uint64) syscall.Errno {
	s.life.Lock()
	defer s.life.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.fhs[fh]
	if h == nil {
		return syscall.EINVAL
	}
	delete(s.fhs, fh)
	s.closeFDLocked(h.fd)
	return 0
}

// openFD opens name in dirfd without following a symbolic link, within the descriptor budget.
func (s *Server) openFD(dirfd int, name string, flags int, mode uint32) (int, syscall.Errno) {
	s.mu.Lock()
	if s.fds >= maxFDs {
		s.mu.Unlock()
		return -1, syscall.ENFILE
	}
	s.fds++
	s.fdsPeak = max(s.fdsPeak, s.fds)
	s.mu.Unlock()
	fd, err := unix.Openat(dirfd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		s.count(func() { s.fds-- })
		return -1, errno(err)
	}
	return fd, 0
}

func (s *Server) closeFD(fd int) {
	s.mu.Lock()
	s.closeFDLocked(fd)
	s.mu.Unlock()
}

func (s *Server) closeFDLocked(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
		s.fds--
	}
}

// attr is what the guest sees of st: owner root, no device numbers.
func attr(st *unix.Stat_t) fuse.Attr {
	return fuse.Attr{Ino: st.Ino, Size: uint64(st.Size), Blocks: uint64(st.Blocks),
		Atime: uint64(st.Atim.Sec), Mtime: uint64(st.Mtim.Sec), Ctime: uint64(st.Ctim.Sec),
		Atimensec: uint32(st.Atim.Nsec), Mtimensec: uint32(st.Mtim.Nsec), Ctimensec: uint32(st.Ctim.Nsec),
		Mode: st.Mode, Nlink: uint32(st.Nlink), Blk: uint32(st.Blksize)}
}

func errno(err error) syscall.Errno {
	var e syscall.Errno
	switch {
	case err == nil:
		return 0
	case errors.As(err, &e):
		return e
	}
	return syscall.EIO
}
