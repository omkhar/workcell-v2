// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package rootfs turns an in-memory file tree into a read-only ext4 image, in pure Go
// and without running mkfs or a shell (A8). ext4 is the one format both guest kernels
// mount: Firecracker's CI kernel has no erofs and Kata's has no squashfs.
//
// The image has 4 KiB blocks and 256-byte inodes, extents, the filetype, large_file,
// dir_nlink and extra_isize features, and nothing else: no journal, no checksums, no
// resize_inode, no flex_bg, no sparse_super and no htree. Every group, of 32768
// blocks, holds a superblock copy, the group descriptors, its two bitmaps and its inode
// table, then data. Inodes number from the root (2) and then from 11 in a depth-first
// walk with children sorted by name; blocks are handed out in that order. Hard links
// share the inode of the first name met. An empty lost+found directory is added to the
// root when the tree has none, because e2fsck insists on one. The superblock and group
// descriptors leave all space free that the tree does not use, and the last group
// ends at its last used block.
//
// The output is deterministic: the same tree and mtime give the same bytes. Every
// inode's atime, ctime, mtime and crtime, and the superblock's times, are that one
// mtime. WriteExt4 never seeks, so any io.Writer works; WriteExt4File (ext4file.go) takes
// file data from host files, and leaves free space as holes.
//
// A file may be any size the image allows (at most 256 groups, 32 GiB); a file split by
// group metadata becomes several extents, and more than four make a depth-1 extent tree
// with one leaf block, so a file spanning up to 340 groups fits. A hostile tree is a
// non-goal here: the input is built by the host from layers it has already bounded.
package rootfs

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

const (
	blockSize      = 4096
	blocksPerGroup = 8 * blockSize
	inodeSize      = 256
	inodesPerBlock = blockSize / inodeSize
	rootIno        = 2
	firstIno       = 11
	fastLen        = 60 // a symlink target shorter than this lives in i_block
	maxGroups      = 256
	maxImage       = maxGroups * blocksPerGroup * blockSize
	maxLinks       = 65000
	inlineExtents  = 4
	leafExtents    = (blockSize - 12) / 12
	lostFound      = "lost+found"
	extentsFL      = 0x80000

	// DefaultMtime is the Unix time used when WriteExt4 is given the zero time.
	DefaultMtime = 1735689600 // 2025-01-01T00:00:00Z
)

var (
	// ErrMtime means the modification time does not fit ext4's signed 32-bit seconds.
	ErrMtime = errors.New("rootfs: mtime outside 1970 to 2038")

	errNoFit = errors.New("rootfs: does not fit in this many groups")
)

// kindInfo gives, per Kind, the i_mode type bits and the directory entry file type.
var kindInfo = [...]struct {
	mode  uint16
	ftype byte
}{Dir: {0x4000, 2}, File: {0x8000, 1}, Symlink: {0xA000, 7}, CharDev: {0x2000, 3}, BlockDev: {0x6000, 4}, FIFO: {0x1000, 5}}

var le = binary.LittleEndian

type child struct {
	name string
	ino  *inode
}

// inode is one tree node as the writer sees it.
type inode struct {
	num    uint32
	node   *Node
	links  uint32
	parent uint32    // directories only
	kids   []child   // directories only, sorted by name
	body   []byte    // directory blocks, file data, or a long symlink target
	src    *HostFile // a file whose data is in a host file, not in body
}

// length is the size in bytes of what the inode holds in blocks.
func (c *inode) length() int64 {
	if c.src != nil {
		return c.src.Size
	}
	return int64(len(c.body))
}

func (c *inode) blocks() uint32 { return uint32((c.length() + blockSize - 1) / blockSize) }

// WriteExt4 writes the tree as an ext4 image to w. A zero mtime means DefaultMtime.
func (t *Tree) WriteExt4(w io.Writer, mtime time.Time) error {
	list, p, err := t.layout(mtime, 0)
	if err != nil {
		return err
	}
	s := &streamSink{bw: bufio.NewWriterSize(w, 1<<20)}
	if err := p.emit(s, list); err != nil {
		return err
	}
	if err := s.bw.Flush(); err != nil {
		return fmt.Errorf("rootfs: write image: %w", err)
	}
	return nil
}

// layout numbers the tree and plans the smallest image that holds it plus free blocks of
// free space, one inode for every four of them.
func (t *Tree) layout(mtime time.Time, free uint32) ([]*inode, *plan, error) {
	sec := int64(DefaultMtime)
	if !mtime.IsZero() {
		sec = mtime.Unix()
	}
	if sec < 0 || sec > math.MaxInt32 {
		return nil, nil, ErrMtime
	}
	list, err := collect(t)
	if err != nil {
		return nil, nil, err
	}
	data := uint64(free)
	for _, c := range list {
		data += uint64(c.blocks())
	}
	for g := max(1, uint32(data/blocksPerGroup)); g <= maxGroups; g++ {
		p, err := makePlan(list, g, uint32(sec), free)
		if errors.Is(err, errNoFit) {
			continue
		}
		return list, p, err
	}
	return nil, nil, ErrTooLarge
}

// collect numbers the inodes and builds every directory's blocks.
func collect(t *Tree) ([]*inode, error) {
	root := &inode{num: rootIno, node: t.root}
	list := []*inode{root}
	seen := map[*Node]*inode{t.root: root}
	next := uint32(firstIno)
	var visit func(d *inode, parent uint32) error
	visit = func(d *inode, parent uint32) error {
		d.parent, d.links = parent, 2
		names := make([]string, 0, len(d.node.kids)+1)
		for name := range d.node.kids {
			names = append(names, name)
		}
		if d == root && d.node.kids[lostFound] == nil {
			names = append(names, lostFound)
		}
		sort.Strings(names)
		for _, name := range names {
			n := d.node.kids[name]
			if n == nil {
				n = &Node{Kind: Dir, Mode: 0o700}
			}
			c := seen[n]
			if c == nil {
				if len(list) >= maxGroups*blocksPerGroup {
					return ErrTooLarge
				}
				c = &inode{num: next, node: n}
				next++
				seen[n] = c
				list = append(list, c)
				switch {
				case n.Kind == File:
					c.body, c.src = n.Data, n.Source
				case n.Kind == Symlink && len(n.Target) >= fastLen:
					c.body = []byte(n.Target)
				case n.Kind == Dir:
					if err := visit(c, d.num); err != nil {
						return err
					}
				}
				if c.length() > maxImage {
					return ErrTooLarge
				}
			}
			if n.Kind == Dir {
				d.links++
			} else if c.links++; c.links > maxLinks {
				return fmt.Errorf("%w: more than %d links to one file", ErrTooLarge, maxLinks)
			}
			d.kids = append(d.kids, child{name, c})
		}
		d.body = dirBlocks(d)
		if d.links > maxLinks {
			d.links = 1 // dir_nlink: "more than can be counted"
		}
		return nil
	}
	if err := visit(root, rootIno); err != nil {
		return nil, err
	}
	return list, nil
}

// dirBlocks lays out d's linear directory entries. The last entry of each block
// stretches to the end of the block.
func dirBlocks(d *inode) []byte {
	var buf []byte
	last := 0
	add := func(ino uint32, name string, ftype byte) {
		rec := 8 + (len(name)+3)&^3
		if off := len(buf) % blockSize; off != 0 && off+rec > blockSize {
			stretch(buf, last)
			buf = append(buf, make([]byte, (blockSize-off))...)
		}
		last = len(buf)
		buf = append(buf, make([]byte, rec)...)
		le.PutUint32(buf[last:], ino)
		le.PutUint16(buf[last+4:], uint16(rec))
		buf[last+6], buf[last+7] = byte(len(name)), ftype
		copy(buf[last+8:], name)
	}
	add(d.num, ".", kindInfo[Dir].ftype)
	add(d.parent, "..", kindInfo[Dir].ftype)
	for _, k := range d.kids {
		add(k.ino.num, k.name, kindInfo[k.ino.node.Kind].ftype)
	}
	stretch(buf, last)
	return append(buf, make([]byte, (blockSize-len(buf)%blockSize)%blockSize)...)
}

// stretch widens the entry at last to the end of its block (buf is padded after).
func stretch(buf []byte, last int) {
	end := (len(buf) + blockSize - 1) / blockSize * blockSize
	le.PutUint16(buf[last+4:], uint16(end-last))
}

type run struct{ start, n uint32 }

type seg struct {
	start, n uint32
	data     []byte    // zero-padded to n blocks
	src      *HostFile // or the host file that holds this run's data from byte off on
	off      int64
}

// plan is the whole layout for one group count.
type plan struct {
	groups, ipg, gdt, over uint32 // over: metadata blocks at the start of each group
	maxNum                 uint32 // highest inode number in use
	blocks                 uint32 // total blocks
	freeBlocks, freeInodes uint32
	bitmaps                [][]byte // block bitmaps
	free                   []uint32 // free blocks per group
	dirs                   []uint32 // directories per group
	segs                   []seg    // data, in ascending block order
	raw                    [][inodeSize]byte
	mtime                  uint32
}

// makePlan allocates every inode's blocks into the given number of groups, or returns
// errNoFit. The image then ends free blocks after the last block used, and holds free/4
// more inodes than the tree needs.
func makePlan(list []*inode, groups, mtime, free uint32) (*plan, error) {
	p := &plan{groups: groups, mtime: mtime, maxNum: uint32(len(list)) + firstIno - 2}
	p.ipg = (p.maxNum + free/4 + groups - 1) / groups
	p.ipg = (p.ipg + inodesPerBlock - 1) / inodesPerBlock * inodesPerBlock
	p.gdt = (groups*32 + blockSize - 1) / blockSize
	p.over = 1 + p.gdt + 2 + p.ipg/inodesPerBlock
	if p.ipg > blocksPerGroup || p.over >= blocksPerGroup {
		return nil, errNoFit
	}
	p.bitmaps = make([][]byte, groups)
	p.dirs = make([]uint32, groups)
	p.raw = make([][inodeSize]byte, len(list))
	for g := range p.bitmaps {
		p.bitmaps[g] = make([]byte, blockSize)
		for i := uint32(0); i < p.over; i++ {
			setBit(p.bitmaps[g], i)
		}
	}
	grp, off := uint32(0), p.over
	alloc := func(n uint32) ([]run, error) {
		var runs []run
		for n > 0 {
			if off == blocksPerGroup {
				grp, off = grp+1, p.over
			}
			if grp >= groups {
				return nil, errNoFit
			}
			take := min(n, blocksPerGroup-off)
			runs = append(runs, run{grp*blocksPerGroup + off, take})
			for i := off; i < off+take; i++ {
				setBit(p.bitmaps[grp], i)
			}
			off += take
			n -= take
		}
		return runs, nil
	}
	for i, c := range list {
		runs, err := alloc(c.blocks())
		if err != nil {
			return nil, err
		}
		var leaf []run
		if len(runs) > inlineExtents {
			if len(runs) > leafExtents {
				return nil, ErrTooLarge
			}
			if leaf, err = alloc(1); err != nil {
				return nil, err
			}
		}
		p.place(i, c, runs, leaf)
		if c.node.Kind == Dir {
			p.dirs[(c.num-1)/p.ipg]++
		}
	}
	for rest := free; rest > 0; { // the space the guest may fill
		if off == blocksPerGroup {
			grp, off = grp+1, p.over
		}
		if grp >= groups {
			return nil, errNoFit
		}
		take := min(rest, blocksPerGroup-off)
		off += take
		rest -= take
	}
	// The last group ends at its last used block, but is never shorter than its metadata.
	last := grp
	p.blocks = (groups-1)*blocksPerGroup + p.over
	if last == groups-1 {
		p.blocks = last*blocksPerGroup + off
	}
	p.freeInodes = p.ipg*groups - p.maxNum
	p.free = make([]uint32, groups)
	for g := range p.bitmaps {
		size := p.groupBlocks(uint32(g))
		p.free[g] = size - ones(p.bitmaps[g], size)
		p.freeBlocks += p.free[g]
		for i := size; i < blocksPerGroup; i++ { // padding past the end of the last group
			setBit(p.bitmaps[g], i)
		}
	}
	return p, nil
}

func (p *plan) groupBlocks(g uint32) uint32 {
	if g == p.groups-1 {
		return p.blocks - g*blocksPerGroup
	}
	return blocksPerGroup
}

// place fills the raw inode i and queues its data segments; leaf holds the extent
// tree block of a file with more than four extents.
func (p *plan) place(i int, c *inode, runs, leaf []run) {
	n := c.node
	var ib [60]byte
	var leafSeg *seg // allocated after the runs, so queued after them
	flags := uint32(0)
	size := uint64(c.length())
	switch {
	case n.Kind == Symlink && c.body == nil: // fast symlink
		size = uint64(copy(ib[:], n.Target))
	case n.Kind == CharDev || n.Kind == BlockDev:
		le.PutUint32(ib[4:], n.Minor&0xff|n.Major<<8|(n.Minor&^0xff)<<12)
	case n.Kind == FIFO:
	default:
		flags = extentsFL
		le.PutUint16(ib[0:], 0xF30A)
		le.PutUint16(ib[4:], inlineExtents)
		if len(runs) <= inlineExtents {
			le.PutUint16(ib[2:], uint16(len(runs)))
			putExtents(ib[12:], runs)
			break
		}
		le.PutUint16(ib[2:], 1)
		le.PutUint16(ib[6:], 1)
		le.PutUint32(ib[16:], leaf[0].start)
		blk := make([]byte, blockSize)
		le.PutUint16(blk[0:], 0xF30A)
		le.PutUint16(blk[2:], uint16(len(runs)))
		le.PutUint16(blk[4:], leafExtents)
		putExtents(blk[12:], runs)
		leafSeg = &seg{start: leaf[0].start, n: 1, data: blk}
	}
	var off uint32
	for _, r := range runs {
		lo := min(int(off)*blockSize, len(c.body))
		hi := min(int(off+r.n)*blockSize, len(c.body))
		p.segs = append(p.segs, seg{r.start, r.n, c.body[lo:hi], c.src, int64(off) * blockSize})
		off += r.n
	}
	if leafSeg != nil {
		p.segs = append(p.segs, *leafSeg)
	}
	nblk := off + uint32(len(leaf))
	b := p.raw[i][:]
	le.PutUint16(b[0x00:], kindInfo[n.Kind].mode|uint16(n.Mode))
	le.PutUint16(b[0x02:], uint16(n.UID))
	le.PutUint32(b[0x04:], uint32(size))
	for _, o := range []int{0x08, 0x0C, 0x10, 0x90} { // atime, ctime, mtime, crtime
		le.PutUint32(b[o:], p.mtime)
	}
	le.PutUint16(b[0x18:], uint16(n.GID))
	le.PutUint16(b[0x1A:], uint16(c.links))
	le.PutUint32(b[0x1C:], nblk*(blockSize/512))
	le.PutUint32(b[0x20:], flags)
	copy(b[0x28:], ib[:])
	le.PutUint32(b[0x6C:], uint32(size>>32))
	le.PutUint16(b[0x78:], uint16(n.UID>>16))
	le.PutUint16(b[0x7A:], uint16(n.GID>>16))
	le.PutUint16(b[0x80:], 32) // i_extra_isize: through i_crtime_extra and i_version_hi
}

func putExtents(dst []byte, runs []run) {
	var lblk uint32
	for i, r := range runs {
		e := dst[12*i:]
		le.PutUint32(e[0:], lblk)
		le.PutUint16(e[4:], uint16(r.n))
		le.PutUint32(e[8:], r.start)
		lblk += r.n
	}
}

func setBit(b []byte, i uint32) { b[i/8] |= 1 << (i % 8) }

func ones(b []byte, n uint32) (c uint32) {
	for i := uint32(0); i < n; i++ {
		c += uint32(b[i/8] >> (i % 8) & 1)
	}
	return c
}

// sink takes the image in order, from the first byte to the last.
type sink interface {
	put(b []byte) error // write b
	skip(n int64) error // n zero bytes
	file(s seg) error   // the run's bytes from its host file, zero-padded to its blocks
}

// emit writes the image to w: for each group its metadata, then its data, then zeros.
func (p *plan) emit(w sink, list []*inode) error {
	var first error
	keep := func(err error) {
		if first == nil {
			first = err
		}
	}
	gdt := make([]byte, p.gdt*blockSize)
	for g := uint32(0); g < p.groups; g++ {
		d := gdt[g*32:]
		start := g*blocksPerGroup + 1 + p.gdt
		used := min(p.ipg, p.maxNum-min(p.maxNum, g*p.ipg))
		le.PutUint32(d[0:], start)
		le.PutUint32(d[4:], start+1)
		le.PutUint32(d[8:], start+2)
		le.PutUint16(d[12:], uint16(p.free[g]))
		le.PutUint16(d[14:], uint16(p.ipg-used))
		le.PutUint16(d[16:], uint16(p.dirs[g]))
	}
	si, di := 0, 0
	for g := uint32(0); g < p.groups; g++ {
		gs := g * blocksPerGroup
		size := p.groupBlocks(g)
		blk := make([]byte, blockSize)
		if g == 0 {
			p.superblock(blk[1024:], 0)
		} else {
			p.superblock(blk, g)
		}
		keep(w.put(blk))
		keep(w.put(gdt))
		keep(w.put(p.bitmaps[g]))
		ib := make([]byte, blockSize)
		for i := uint32(0); i < blocksPerGroup; i++ {
			if i >= p.ipg || g*p.ipg+i < p.maxNum {
				setBit(ib, i)
			}
		}
		keep(w.put(ib))
		table := make([]byte, p.ipg*inodeSize)
		for ; si < len(list) && (list[si].num-1)/p.ipg == g; si++ {
			copy(table[(list[si].num-1)%p.ipg*inodeSize:], p.raw[si][:])
		}
		keep(w.put(table))
		cur := gs + p.over
		for ; di < len(p.segs) && p.segs[di].start < gs+size; di++ {
			s := p.segs[di]
			keep(w.skip(int64(s.start-cur) * blockSize))
			if s.src != nil {
				keep(w.file(s))
			} else {
				keep(w.put(s.data))
				keep(w.skip(int64(s.n)*blockSize - int64(len(s.data))))
			}
			cur = s.start + s.n
		}
		keep(w.skip(int64(gs+size-cur) * blockSize))
		if first != nil {
			return first
		}
	}
	return nil
}

// streamSink is the sink of WriteExt4: everything goes to one io.Writer.
type streamSink struct{ bw *bufio.Writer }

func (s *streamSink) put(b []byte) error { _, err := s.bw.Write(b); return err }

func (s *streamSink) skip(n int64) error {
	for ; n > 0; n -= int64(len(zeros)) {
		if _, err := s.bw.Write(zeros[:min(n, int64(len(zeros)))]); err != nil {
			return err
		}
	}
	return nil
}

var zeros [64 << 10]byte // read only

func (s *streamSink) file(seg) error {
	return fmt.Errorf("%w: a node with a host file needs WriteExt4File", ErrBadNode)
}

// superblock writes the 1024-byte superblock of group g into b.
func (p *plan) superblock(b []byte, g uint32) {
	le.PutUint32(b[0x00:], p.ipg*p.groups)
	le.PutUint32(b[0x04:], p.blocks)
	le.PutUint32(b[0x0C:], p.freeBlocks)
	le.PutUint32(b[0x10:], p.freeInodes)
	le.PutUint32(b[0x18:], 2) // s_log_block_size: 1024 << 2
	le.PutUint32(b[0x1C:], 2) // s_log_cluster_size, equal without bigalloc
	le.PutUint32(b[0x20:], blocksPerGroup)
	le.PutUint32(b[0x24:], blocksPerGroup)
	le.PutUint32(b[0x28:], p.ipg)
	le.PutUint32(b[0x2C:], p.mtime) // s_mtime
	le.PutUint32(b[0x30:], p.mtime) // s_wtime
	le.PutUint16(b[0x36:], 0xFFFF)  // s_max_mnt_count: -1
	le.PutUint16(b[0x38:], 0xEF53)
	le.PutUint16(b[0x3A:], 1) // s_state: clean
	le.PutUint16(b[0x3C:], 1) // s_errors: continue
	le.PutUint32(b[0x40:], p.mtime)
	le.PutUint32(b[0x4C:], 1) // s_rev_level: dynamic
	le.PutUint32(b[0x54:], firstIno)
	le.PutUint16(b[0x58:], inodeSize)
	le.PutUint16(b[0x5A:], uint16(g))
	le.PutUint32(b[0x60:], 0x0042) // incompat: filetype, extents
	le.PutUint32(b[0x64:], 0x0062) // ro_compat: large_file, dir_nlink, extra_isize
	b[0xFC] = 1                    // s_def_hash_version: half MD4
	le.PutUint32(b[0x108:], p.mtime)
	le.PutUint16(b[0x15C:], 32) // s_min_extra_isize
	le.PutUint16(b[0x15E:], 32) // s_want_extra_isize
}
