// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package fileserve is the host side of mount mode (ADR-005): a FUSE 7 server for one
// exported directory, fed the guest kernel's raw requests over internal/wire by the guest
// init, which parses nothing. The grammar is the (handle, name) model: a request names a
// node or an open file by an index into tables the host holds, and a name appears only in
// LOOKUP, CREATE, MKDIR, UNLINK, RMDIR, RENAME and SYMLINK, where it must be one ordinary
// path component. Every call on the export is relative to a directory descriptor the host
// already holds and never follows a symbolic link (R6). The guest is hostile (A1): what it
// sends is checked byte by byte before any syscall, and what it can make the host hold is
// capped (I10, I12).
//
// This file is the codec: the layouts of include/uapi/linux/fuse.h at protocol 7.37,
// little-endian as on every guest.
package fileserve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
)

// Port is the vsock port the init dials with its FUSE stream; every frame on it has type
// FrameType and carries one request or one reply.
const (
	Port      = 5002
	FrameType = 1
)

// Sizes in bytes, from fuse.h.
const (
	InHeaderLen  = 40
	OutHeaderLen = 16
	entryOutLen  = 128
	attrOutLen   = 104
	openOutLen   = 16
	writeOutLen  = 8
	kstatfsLen   = 80
	initInLen    = 64
	initOutLen   = 64
	direntLen    = 24
	setattrInLen = 88
	readInLen    = 40
	writeInLen   = 40
	releaseInLen = 24
)

// What this server negotiates. MaxWrite is 15 pages, so one WRITE request or one READ reply
// is one wire frame, as measured in ADR-005.
const (
	Major        = 7
	MaxMinor     = 37
	MaxWrite     = 61440
	maxReadahead = 131072
	rootID       = 1
	nameMax      = 255
	pathMax      = 4096
)

// Opcodes this server answers. Anything else is ENOSYS without a syscall.
const (
	opLookup      = 1
	opForget      = 2
	opGetattr     = 3
	opSetattr     = 4
	opReadlink    = 5
	opSymlink     = 6
	opMkdir       = 9
	opUnlink      = 10
	opRmdir       = 11
	opRename      = 12
	opOpen        = 14
	opRead        = 15
	opWrite       = 16
	opStatfs      = 17
	opRelease     = 18
	opFsync       = 20
	opFlush       = 25
	opInit        = 26
	opOpendir     = 27
	opReaddir     = 28
	opReleasedir  = 29
	opFsyncdir    = 30
	opAccess      = 34
	opCreate      = 35
	opInterrupt   = 36
	opDestroy     = 38
	opBatchForget = 42
	opReaddirplus = 44
)

// INIT flags, as measured on kernel B (ADR-005).
const (
	flagAsyncRead      = 1 << 0
	flagAtomicOTrunc   = 1 << 3
	flagBigWrites      = 1 << 5
	flagAutoInvalData  = 1 << 12
	flagDoReaddirplus  = 1 << 13
	flagParallelDirops = 1 << 18
	flagCacheSymlinks  = 1 << 23
	initFlags          = flagAsyncRead | flagAtomicOTrunc | flagBigWrites | flagAutoInvalData | flagDoReaddirplus |
		flagParallelDirops | flagCacheSymlinks
)

// SETATTR valid bits and the GETATTR flag.
const (
	fattrMode     = 1 << 0
	fattrUID      = 1 << 1
	fattrGID      = 1 << 2
	fattrSize     = 1 << 3
	fattrAtime    = 1 << 4
	fattrMtime    = 1 << 5
	fattrFh       = 1 << 6
	fattrAtimeNow = 1 << 7
	fattrMtimeNow = 1 << 8
	getattrFh     = 1 << 0
)

// errShort means fewer bytes than a request header: there is no unique to answer.
var errShort = errors.New("fuse: request shorter than its header")

// errArgs is a request whose arguments do not parse; it is answered EINVAL.
var errArgs = errors.New("fuse: malformed arguments")

type initIn struct{ Major, Minor, MaxReadahead, Flags uint32 }

type forget struct{ NodeID, N uint64 }

type setattrIn struct {
	Valid                uint32
	Fh, Size             uint64
	Atime, Mtime         uint64
	Atimensec, Mtimensec uint32
	Mode, UID, GID       uint32
}

// request is one decoded request.
type request struct {
	Opcode         uint32
	Unique, NodeID uint64
	Name           string // LOOKUP, MKDIR, CREATE, UNLINK, RMDIR, SYMLINK; RENAME's old name
	Name2          string // RENAME's new name, SYMLINK's target
	NewDir         uint64 // RENAME
	Fh, Offset     uint64
	Size           uint32 // READ, READDIR(PLUS), WRITE
	Flags          uint32 // OPEN, OPENDIR, CREATE, GETATTR
	Mode           uint32 // MKDIR, CREATE
	Data           []byte // WRITE; it aliases the request
	Setattr        setattrIn
	Forgets        []forget
	Init           initIn
}

var le = binary.LittleEndian

// parse decodes one request. After errShort nothing is set; after any other error the header
// fields are set and the request is answered EINVAL (or not at all, if it takes no reply).
func parse(b []byte) (request, error) {
	if len(b) < InHeaderLen {
		return request{}, errShort
	}
	r := request{Opcode: le.Uint32(b[4:]), Unique: le.Uint64(b[8:]), NodeID: le.Uint64(b[16:])}
	if int64(le.Uint32(b)) != int64(len(b)) {
		return r, fmt.Errorf("%w: header says %d bytes, frame has %d", errArgs, le.Uint32(b), len(b))
	}
	return r, r.args(b[InHeaderLen:])
}

func (r *request) args(p []byte) error {
	fixed := func(n int) error {
		if len(p) != n {
			return fmt.Errorf("%w: opcode %d takes %d bytes, got %d", errArgs, r.Opcode, n, len(p))
		}
		return nil
	}
	var err error
	switch r.Opcode {
	case opLookup, opUnlink, opRmdir:
		r.Name, err = oneName(p)
	case opMkdir:
		if len(p) < 8 {
			return fixed(8)
		}
		r.Mode = le.Uint32(p)
		r.Name, err = oneName(p[8:])
	case opCreate:
		if len(p) < 16 {
			return fixed(16)
		}
		r.Flags, r.Mode = le.Uint32(p), le.Uint32(p[4:])
		r.Name, err = oneName(p[16:])
	case opSymlink:
		var n []string
		if n, err = split(p, 2); err == nil {
			r.Name, r.Name2, err = n[0], n[1], checkName(n[0])
			if err == nil && (r.Name2 == "" || len(r.Name2) >= pathMax) {
				err = fmt.Errorf("%w: symlink target of %d bytes", errArgs, len(r.Name2))
			}
		}
	case opRename:
		if len(p) < 8 {
			return fixed(8)
		}
		r.NewDir = le.Uint64(p)
		var n []string
		if n, err = split(p[8:], 2); err == nil {
			r.Name, r.Name2 = n[0], n[1]
			err = errors.Join(checkName(n[0]), checkName(n[1]))
		}
	case opForget:
		if err = fixed(8); err == nil {
			r.Forgets = []forget{{r.NodeID, le.Uint64(p)}}
		}
	case opBatchForget:
		if len(p) < 8 || uint64(len(p)-8) != uint64(le.Uint32(p))*16 {
			return fmt.Errorf("%w: batch_forget of %d bytes", errArgs, len(p))
		}
		for q := p[8:]; len(q) >= 16; q = q[16:] {
			r.Forgets = append(r.Forgets, forget{le.Uint64(q), le.Uint64(q[8:])})
		}
	case opGetattr:
		if err = fixed(16); err == nil {
			r.Flags, r.Fh = le.Uint32(p), le.Uint64(p[8:])
		}
	case opSetattr:
		if err = fixed(setattrInLen); err == nil {
			r.Setattr = setattrIn{Valid: le.Uint32(p), Fh: le.Uint64(p[8:]), Size: le.Uint64(p[16:]),
				Atime: le.Uint64(p[32:]), Mtime: le.Uint64(p[40:]), Atimensec: le.Uint32(p[56:]),
				Mtimensec: le.Uint32(p[60:]), Mode: le.Uint32(p[68:]), UID: le.Uint32(p[76:]), GID: le.Uint32(p[80:])}
		}
	case opOpen, opOpendir, opAccess, opInterrupt:
		if err = fixed(8); err == nil {
			r.Flags = le.Uint32(p)
		}
	case opRead, opReaddir, opReaddirplus:
		if err = fixed(readInLen); err == nil {
			r.Fh, r.Offset, r.Size = le.Uint64(p), le.Uint64(p[8:]), le.Uint32(p[16:])
		}
	case opWrite:
		if len(p) < writeInLen || uint64(len(p)-writeInLen) != uint64(le.Uint32(p[16:])) {
			return fmt.Errorf("%w: write of %d bytes", errArgs, len(p))
		}
		r.Fh, r.Offset, r.Size, r.Data = le.Uint64(p), le.Uint64(p[8:]), le.Uint32(p[16:]), p[writeInLen:]
	case opRelease, opReleasedir, opFlush:
		if err = fixed(releaseInLen); err == nil {
			r.Fh = le.Uint64(p)
		}
	case opFsync, opFsyncdir:
		if err = fixed(16); err == nil {
			r.Fh = le.Uint64(p)
		}
	case opInit:
		if len(p) < 16 {
			return fixed(initInLen)
		}
		r.Init = initIn{le.Uint32(p), le.Uint32(p[4:]), le.Uint32(p[8:]), le.Uint32(p[12:])}
	case opStatfs, opReadlink, opDestroy:
		err = fixed(0)
	}
	return err
}

// split cuts p into exactly n NUL-terminated strings with nothing after the last.
func split(p []byte, n int) ([]string, error) {
	if len(p) == 0 || p[len(p)-1] != 0 {
		return nil, fmt.Errorf("%w: names not NUL-terminated", errArgs)
	}
	s := strings.Split(string(p[:len(p)-1]), "\x00")
	if len(s) != n {
		return nil, fmt.Errorf("%w: %d names, want %d", errArgs, len(s), n)
	}
	return s, nil
}

func oneName(p []byte) (string, error) {
	s, err := split(p, 1)
	if err != nil {
		return "", err
	}
	return s[0], checkName(s[0])
}

// checkName refuses anything that is not one ordinary path component: empty, ".", "..", a
// slash or NUL anywhere, or more than nameMax bytes.
func checkName(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > nameMax || strings.ContainsAny(s, "/\x00") {
		return fmt.Errorf("%w: name %q", errArgs, s[:min(len(s), 40)])
	}
	return nil
}

// Out is a reply: the header, then the body. errno 0 is success.
func Out(unique uint64, errno syscall.Errno, body ...[]byte) []byte {
	b := make([]byte, OutHeaderLen, OutHeaderLen+64)
	for _, p := range body {
		b = append(b, p...)
	}
	le.PutUint32(b, uint32(len(b)))
	le.PutUint32(b[4:], uint32(-int32(errno)))
	le.PutUint64(b[8:], unique)
	return b
}

// attr is fuse_attr.
type attr struct {
	Ino, Size, Blocks                uint64
	Atime, Mtime, Ctime              uint64
	Atimensec, Mtimensec, Ctimensec  uint32
	Mode, Nlink, UID, GID, Rdev, Blk uint32
}

func (a attr) append(b []byte) []byte {
	for _, v := range []uint64{a.Ino, a.Size, a.Blocks, a.Atime, a.Mtime, a.Ctime} {
		b = le.AppendUint64(b, v)
	}
	for _, v := range []uint32{a.Atimensec, a.Mtimensec, a.Ctimensec, a.Mode, a.Nlink, a.UID, a.GID, a.Rdev, a.Blk, 0} {
		b = le.AppendUint32(b, v)
	}
	return b
}

func appendValid(b []byte, d time.Duration) []byte {
	return le.AppendUint64(b, uint64(d/time.Second))
}

// entryOut is fuse_entry_out; generation is always 0 because node IDs are never reused.
func entryOut(nodeID uint64, valid time.Duration, a attr) []byte {
	b := le.AppendUint64(make([]byte, 0, entryOutLen), nodeID)
	b = appendValid(appendValid(le.AppendUint64(b, 0), valid), valid)
	ns := uint32(valid % time.Second)
	return a.append(le.AppendUint32(le.AppendUint32(b, ns), ns))
}

// attrOut is fuse_attr_out.
func attrOut(valid time.Duration, a attr) []byte {
	b := appendValid(make([]byte, 0, attrOutLen), valid)
	return a.append(le.AppendUint32(le.AppendUint32(b, uint32(valid%time.Second)), 0))
}

// openOut is fuse_open_out with no open flags: the page cache is used.
func openOut(fh uint64) []byte {
	b := make([]byte, openOutLen)
	le.PutUint64(b, fh)
	return b
}

// writeOut is fuse_write_out.
func writeOut(n uint32) []byte {
	b := make([]byte, writeOutLen)
	le.PutUint32(b, n)
	return b
}

// kstatfs is fuse_kstatfs.
type kstatfs struct {
	Blocks, Bfree, Bavail, Files, Ffree uint64
	Bsize, Namelen, Frsize              uint32
}

func (k kstatfs) bytes() []byte {
	b := make([]byte, 0, kstatfsLen)
	for _, v := range []uint64{k.Blocks, k.Bfree, k.Bavail, k.Files, k.Ffree} {
		b = le.AppendUint64(b, v)
	}
	b = le.AppendUint32(le.AppendUint32(le.AppendUint32(b, k.Bsize), k.Namelen), k.Frsize)
	return append(b, make([]byte, kstatfsLen-len(b))...) // padding, spare[6]
}

// initOut is the reply to in: protocol 7.min(kernel minor, MaxMinor), the flags of this
// server that the kernel offered, and the returned flags.
func initOut(in initIn) []byte {
	b := make([]byte, initOutLen)
	le.PutUint32(b, Major)
	le.PutUint32(b[4:], min(in.Minor, MaxMinor))
	le.PutUint32(b[8:], maxReadahead)
	le.PutUint32(b[12:], in.Flags&initFlags)
	le.PutUint16(b[16:], 12) // max_background
	le.PutUint16(b[18:], 9)  // congestion_threshold
	le.PutUint32(b[20:], MaxWrite)
	le.PutUint32(b[24:], 1) // time_gran
	return b
}

// direntSize is the bytes one entry of name takes in a READDIR or READDIRPLUS reply.
func direntSize(name string, plus bool) int {
	n := direntLen + len(name)
	if plus {
		n += entryOutLen
	}
	return (n + 7) &^ 7
}

// appendDirent appends one fuse_dirent (entry nil) or fuse_direntplus (entry a 128-byte
// entryOut). off is the offset of the next entry; typ is the S_IFMT bits shifted down by 12.
func appendDirent(b, entry []byte, ino, off uint64, typ uint32, name string) []byte {
	end := len(b) + direntSize(name, entry != nil)
	b = append(b, entry...)
	b = le.AppendUint32(le.AppendUint32(le.AppendUint64(le.AppendUint64(b, ino), off), uint32(len(name))), typ)
	b = append(b, name...)
	return append(b, make([]byte, end-len(b))...)
}
