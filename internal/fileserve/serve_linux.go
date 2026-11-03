// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

const (
	// workers is how many requests are served at once; the kernel pipelines that many reads
	// (ADR-005). A 17th waits for a worker.
	workers = 16
	// maxFDs is how many descriptors the guest can make this process hold: a directory node, an
	// open file or an open directory each hold one. ENFILE beyond (I10), below any RLIMIT_NOFILE
	// the Go runtime raises at start, so the proxy and the log keep their headroom.
	maxFDs = 4096
	// maxNodes bounds the node table (I10). A node costs about 200 bytes plus its name, so the
	// table is at most about 60 MiB. ADR-005's walk of 10,100 entries held 10,102 nodes, so this
	// leaves twelve times that for a real tree; only the guest's dentry cache holds a node for
	// long, and it sheds entries under its own memory pressure. ENOMEM beyond.
	maxNodes = 1 << 17
	// frameLimit is how long one frame may take once it has begun (I12), as on the channel.
	frameLimit = 5 * time.Second
	// validity is the entry and attribute timeout the guest kernel caches, as ADR-005 measured.
	validity = time.Second
)

// node is one inode the guest knows by its id: where it is, as (parent, name), and what it
// was when looked up. A directory holds its own descriptor, so every call on its content is
// relative to it. name is "" once the entry was unlinked or replaced: the node then answers
// ENOENT until the guest forgets it, except through a file handle already open on it.
type node struct {
	id       uint64
	parent   *node // nil for the root
	name     string
	ino, dev uint64
	mode     uint32 // the S_IFMT bits
	fd       int    // a directory's own descriptor, else -1
	nlookup  uint64
	kids     int // nodes whose parent this is; they keep it, and its descriptor, alive
}

type key struct {
	parent uint64
	name   string
}

// handle is one open file or directory, bound to the node it was opened on.
type handle struct {
	fd   int
	node uint64
	dir  bool
	mu   sync.Mutex // one READDIR at a time moves the descriptor's position
}

// link is one step of a node's chain: name in the directory open on pfd must still be the
// inode (dev, ino) it was when the node was made.
type link struct {
	pfd      int
	name     string
	ino, dev uint64
}

// loc is what a syscall on one node needs, copied out under the lock.
type loc struct {
	id    uint64
	pfd   int // the parent's descriptor; -1 for the root
	fd    int // the node's own; -1 unless a directory
	name  string
	mode  uint32
	chain []link // the node, if a directory, then its ancestors up to the export, nearest first
}

// Server is one export. Open makes one; Serve runs it; Close ends it.
type Server struct {
	// life is held for reading by every request that may use a descriptor and for writing
	// where one may close (FORGET, RELEASE, Close) or where the tree changes shape (RENAME), so
	// no request can use a reused descriptor number or see a half-moved node.
	life sync.RWMutex
	mu   sync.Mutex // nodes, index, fhs, every node's fields, fds, grown
	// nodes, index and fhs are the tables the (handle, name) grammar indexes.
	nodes          map[uint64]*node
	index          map[key]*node
	fhs            map[uint64]*handle
	nextID, nextFH uint64
	fds            int
	// grown is how far files in the export have been made longer this session, by WRITE past
	// the end or SETATTR size, and limit is its cap in bytes (I10): ENOSPC beyond. Shrinking
	// and unlinking give nothing back, so the host loses at most limit however the guest
	// mixes them, as a clone's image is fixed-size.
	grown, limit int64
}

// Open prepares to serve dir, the export, which must be a directory and not a symbolic
// link, letting its files grow by limit bytes in all. From here on the export is the
// descriptor; the path is never used again.
func Open(dir string, limit int64) (*Server, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open export %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat export %s: %w", dir, err)
	}
	root := &node{id: rootID, ino: st.Ino, dev: st.Dev, mode: unix.S_IFDIR, fd: fd, nlookup: 1}
	return &Server{nodes: map[uint64]*node{rootID: root}, index: map[key]*node{}, fhs: map[uint64]*handle{},
		nextID: rootID, fds: 1, limit: limit}, nil
}

// grow charges the file open on fd for reaching end bytes long, before it does, and is
// ENOSPC once that would take the export past its limit. A request in flight beside another
// on the same file charges as if alone: never less than the growth.
func (s *Server) grow(fd int, end int64) syscall.Errno {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return errno(err)
	}
	if end <= st.Size {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if end-st.Size > s.limit-s.grown {
		return syscall.ENOSPC
	}
	s.grown += end - st.Size
	return 0
}

// Close releases every descriptor. Serve calls it when it returns; a Server that was never
// served needs it once.
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
		_ = unix.Close(h.fd)
	}
	s.nodes, s.index, s.fhs, s.fds = map[uint64]*node{}, map[key]*node{}, map[uint64]*handle{}, 0
}

// Serve answers requests on st until it ends: nil at a clean end of stream, else the stream's
// error. Whatever happens, every descriptor is closed before it returns.
func (s *Server) Serve(st wire.Stream) error {
	defer s.Close()
	c := wire.New(st, frameLimit)
	var wg sync.WaitGroup
	defer wg.Wait()
	var wmu sync.Mutex
	var werr error
	send := func(b []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		if werr == nil {
			werr = c.WriteFrame(wire.Frame{Type: FrameType, Payload: b})
		}
	}
	sem := make(chan struct{}, workers)
	var inited, destroyed bool
	for {
		f, err := c.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		wmu.Lock()
		err = werr
		wmu.Unlock()
		if err != nil {
			return err
		}
		if f.Type != FrameType {
			continue
		}
		r, err := parse(f.Payload)
		if errors.Is(err, errShort) {
			continue
		}
		quiet := r.Opcode == opForget || r.Opcode == opBatchForget || r.Opcode == opInterrupt
		var e syscall.Errno
		switch {
		case err != nil:
			e = syscall.EINVAL
		case destroyed, inited && r.Opcode == opInit, !inited && r.Opcode != opInit:
			e = syscall.EIO
		case r.Opcode == opInit && r.Init.Major != Major:
			e = syscall.EPROTO
		case r.Opcode == opInit:
			body, _ := initOut(r.Init)
			inited = true
			send(Out(r.Unique, 0, body))
			continue
		case r.Opcode == opDestroy:
			destroyed = true
		}
		if e != 0 || r.Opcode == opDestroy {
			if !quiet {
				send(Out(r.Unique, e))
			}
			continue
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			if b := s.handle(r); b != nil {
				send(b)
			}
		})
	}
}

// handle serves one request; nil means no reply.
func (s *Server) handle(r request) []byte {
	switch r.Opcode {
	case opForget, opBatchForget:
		s.forget(r.Forgets)
		return nil
	case opInterrupt:
		return nil
	case opRelease, opReleasedir:
		return Out(r.Unique, s.release(r.NodeID, r.Fh))
	case opRename:
		s.life.Lock()
		defer s.life.Unlock()
		return Out(r.Unique, s.rename(r))
	}
	s.life.RLock()
	defer s.life.RUnlock()
	body, e := s.op(r)
	if e != 0 {
		body = nil
	}
	return Out(r.Unique, e, body)
}

// loc copies what a syscall on node id needs. It is ENOENT for an unknown id and for a node
// whose entry, or whose ancestor's entry, is gone.
func (s *Server) loc(id uint64) (loc, syscall.Errno) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.nodes[id]
	if n == nil {
		return loc{}, syscall.ENOENT
	}
	l := loc{id: id, pfd: -1, fd: n.fd, name: n.name, mode: n.mode}
	switch {
	case n.parent == nil:
		return l, 0
	case n.name == "":
		return l, syscall.ENOENT
	}
	l.pfd = n.parent.fd
	from := n
	if n.fd < 0 {
		from = n.parent
	}
	for c := from; c.parent != nil; c = c.parent {
		if c.name == "" {
			return l, syscall.ENOENT
		}
		l.chain = append(l.chain, link{c.parent.fd, c.name, c.ino, c.dev})
	}
	return l, 0
}

// at is the node's location, checked: every link from the export down to the directory the
// syscall will use still names the inode it did. A directory the host moved out of the
// export, or replaced, is ESTALE until the guest looks it up afresh (R6).
func (s *Server) at(id uint64) (loc, syscall.Errno) {
	l, e := s.loc(id)
	if e != 0 {
		return l, e
	}
	for i, c := range l.chain {
		var st unix.Stat_t
		err := unix.Fstatat(c.pfd, c.name, &st, unix.AT_SYMLINK_NOFOLLOW)
		switch {
		case i == 0 && errors.Is(err, syscall.ENOENT):
			return l, syscall.ENOENT
		case err != nil || st.Ino != c.ino || st.Dev != c.dev:
			return l, syscall.ESTALE
		}
	}
	return l, 0
}

// dirAt is a directory's location; only a directory node has a descriptor.
func (s *Server) dirAt(id uint64) (loc, syscall.Errno) {
	l, e := s.at(id)
	if e == 0 && l.fd < 0 {
		e = syscall.ENOTDIR
	}
	return l, e
}

// namedAt is the location of a node that has a parent: anything but the root.
func (s *Server) namedAt(id uint64) (loc, syscall.Errno) {
	l, e := s.at(id)
	if e == 0 && l.pfd < 0 {
		e = syscall.EISDIR
	}
	return l, e
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
		return 0, syscall.ENOENT
	}
	k := key{p.id, name}
	if n := s.index[k]; n != nil {
		if n.ino == st.Ino && n.dev == st.Dev && n.mode == st.Mode&unix.S_IFMT {
			n.nlookup++
			s.closeFDLocked(fd) // private until now, so no one can be using it
			return n.id, 0
		}
		s.detach(n)
	}
	if len(s.nodes) >= maxNodes {
		s.closeFDLocked(fd)
		return 0, syscall.ENOMEM
	}
	s.nextID++
	n := &node{id: s.nextID, parent: parent, name: name, ino: st.Ino, dev: st.Dev, mode: st.Mode & unix.S_IFMT,
		fd: fd, nlookup: 1}
	parent.kids++
	s.nodes[n.id], s.index[k] = n, n
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

// forget drops lookups. A node goes once it has none and no child; the root never goes, and a
// count beyond the lookups made drops no more than them.
func (s *Server) forget(fs []forget) {
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

func (s *Server) newFH(h *handle) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextFH++
	s.fhs[s.nextFH] = h
	return s.nextFH
}

// fh is the open handle fh, which must have been opened on node: EBADF otherwise.
func (s *Server) fh(node, fh uint64) (*handle, syscall.Errno) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.fhs[fh]; h != nil && h.node == node {
		return h, 0
	}
	return nil, syscall.EBADF
}

// release closes one handle, once: a second RELEASE of it is EBADF and closes nothing.
func (s *Server) release(node, fh uint64) syscall.Errno {
	s.life.Lock()
	defer s.life.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.fhs[fh]
	if h == nil || h.node != node {
		return syscall.EBADF
	}
	delete(s.fhs, fh)
	s.closeFDLocked(h.fd)
	return 0
}

// openFD opens name in dirfd within the descriptor budget: never following a symbolic link,
// never blocking on a FIFO, never inherited.
func (s *Server) openFD(dirfd int, name string, flags int, mode uint32) (int, syscall.Errno) {
	s.mu.Lock()
	if s.fds >= maxFDs {
		s.mu.Unlock()
		return -1, syscall.ENFILE
	}
	s.fds++
	s.mu.Unlock()
	fd, err := unix.Openat(dirfd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if err != nil {
		s.mu.Lock()
		s.fds--
		s.mu.Unlock()
		return -1, errno(err)
	}
	return fd, 0
}

// openFile opens a regular file; anything else, found after the open, is closed and EPERM.
func (s *Server) openFile(dirfd int, name string, flags int, mode uint32) (int, unix.Stat_t, syscall.Errno) {
	var st unix.Stat_t
	fd, e := s.openFD(dirfd, name, flags, mode)
	if e != 0 {
		return -1, st, e
	}
	err := unix.Fstat(fd, &st)
	if e = errno(err); e == 0 && st.Mode&unix.S_IFMT != unix.S_IFREG {
		e = syscall.EPERM
	}
	if e != 0 {
		s.closeFD(fd)
		return -1, st, e
	}
	return fd, st, 0
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
