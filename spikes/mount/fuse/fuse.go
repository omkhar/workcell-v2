// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package fuse is the U-502a spike's raw FUSE protocol: the opcodes, the
// request decoder the host runs on guest-controlled bytes, the reply encoders,
// and Copy, the guest's pass-through between /dev/fuse and the vsock stream.
// Layouts are those of include/uapi/linux/fuse.h at v6.1 (protocol 7.37),
// little-endian as on every guest this spike boots.
package fuse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
)

// Port is the vsock port of the FUSE stream; every frame on it has type FrameType.
const (
	Port      = 5002
	FrameType = 1
)

// Sizes in bytes, from fuse.h.
const (
	InHeaderLen   = 40
	OutHeaderLen  = 16
	AttrLen       = 88
	EntryOutLen   = 128
	AttrOutLen    = 104
	OpenOutLen    = 16
	WriteOutLen   = 8
	KstatfsLen    = 80
	InitInLen     = 64
	InitOutLen    = 64
	DirentLen     = 24
	DirentPlusLen = EntryOutLen + DirentLen
	SetattrInLen  = 88
	ReadInLen     = 40
	WriteInLen    = 40
	ReleaseInLen  = 24
	MinReadBuffer = 8192
)

// What this server negotiates.
const (
	Major        = 7
	MaxMinor     = 37
	RootID       = 1
	NameMax      = 255
	PathMax      = 4096
	MaxWrite     = 61440 // 15 pages: one WRITE or READ is one wire frame
	MaxReadahead = 131072
	MaxReply     = wire.MaxPayload // a reply is one frame, header included
)

// Opcodes.
const (
	OpLookup      = 1
	OpForget      = 2
	OpGetattr     = 3
	OpSetattr     = 4
	OpReadlink    = 5
	OpSymlink     = 6
	OpMknod       = 8
	OpMkdir       = 9
	OpUnlink      = 10
	OpRmdir       = 11
	OpRename      = 12
	OpLink        = 13
	OpOpen        = 14
	OpRead        = 15
	OpWrite       = 16
	OpStatfs      = 17
	OpRelease     = 18
	OpFsync       = 20
	OpFlush       = 25
	OpInit        = 26
	OpOpendir     = 27
	OpReaddir     = 28
	OpReleasedir  = 29
	OpFsyncdir    = 30
	OpAccess      = 34
	OpCreate      = 35
	OpInterrupt   = 36
	OpDestroy     = 38
	OpBatchForget = 42
	OpReaddirplus = 44
	OpRename2     = 45
	MaxOpcode     = 64 // counters cover opcodes below this
)

var opNames = map[uint32]string{OpLookup: "lookup", OpForget: "forget", OpGetattr: "getattr", OpSetattr: "setattr",
	OpReadlink: "readlink", OpSymlink: "symlink", OpMknod: "mknod", OpMkdir: "mkdir", OpUnlink: "unlink",
	OpRmdir: "rmdir", OpRename: "rename", OpLink: "link", OpOpen: "open", OpRead: "read", OpWrite: "write",
	OpStatfs: "statfs", OpRelease: "release", OpFsync: "fsync", OpFlush: "flush", OpInit: "init",
	OpOpendir: "opendir", OpReaddir: "readdir", OpReleasedir: "releasedir", OpFsyncdir: "fsyncdir",
	OpAccess: "access", OpCreate: "create", OpInterrupt: "interrupt", OpDestroy: "destroy",
	OpBatchForget: "batch_forget", OpReaddirplus: "readdirplus", OpRename2: "rename2"}

// OpName is a short name for an opcode, or its number.
func OpName(op uint32) string {
	if s, ok := opNames[op]; ok {
		return s
	}
	return fmt.Sprint("op", op)
}

// INIT flags.
const (
	FlagAsyncRead      = 1 << 0
	FlagAtomicOTrunc   = 1 << 3
	FlagBigWrites      = 1 << 5
	FlagAutoInvalData  = 1 << 12
	FlagDoReaddirplus  = 1 << 13
	FlagParallelDirops = 1 << 18
	FlagCacheSymlinks  = 1 << 23
	Flags              = FlagAsyncRead | FlagAtomicOTrunc | FlagBigWrites | FlagAutoInvalData | FlagDoReaddirplus |
		FlagParallelDirops | FlagCacheSymlinks
)

// SETATTR valid bits and the GETATTR flag.
const (
	FattrMode     = 1 << 0
	FattrUID      = 1 << 1
	FattrGID      = 1 << 2
	FattrSize     = 1 << 3
	FattrAtime    = 1 << 4
	FattrMtime    = 1 << 5
	FattrFh       = 1 << 6
	FattrAtimeNow = 1 << 7
	FattrMtimeNow = 1 << 8
	GetattrFh     = 1 << 0
)

// ErrShort means fewer bytes than a request header: there is no unique to answer.
var ErrShort = errors.New("fuse: request shorter than its header")

// errArgs is a request whose arguments do not parse; it is answered EINVAL.
var errArgs = errors.New("fuse: malformed arguments")

// InitIn is the kernel's half of the handshake.
type InitIn struct{ Major, Minor, MaxReadahead, Flags uint32 }

// Forget is one node and the count to drop from it.
type Forget struct{ NodeID, N uint64 }

// Setattr is fuse_setattr_in.
type Setattr struct {
	Valid                uint32
	Fh, Size             uint64
	Atime, Mtime         uint64
	Atimensec, Mtimensec uint32
	Mode, UID, GID       uint32
}

// Request is one decoded request.
type Request struct {
	Opcode         uint32
	Unique, NodeID uint64
	UID, GID, PID  uint32
	Name           string // LOOKUP, MKDIR, CREATE, UNLINK, RMDIR, SYMLINK; RENAME's old name
	Name2          string // RENAME's new name, SYMLINK's target
	NewDir         uint64 // RENAME
	Fh, Offset     uint64
	Size           uint32 // READ, READDIR(PLUS), WRITE
	Flags          uint32 // OPEN, OPENDIR, CREATE, GETATTR
	Mode           uint32 // MKDIR, CREATE
	Data           []byte // WRITE; it aliases the request
	Setattr        Setattr
	Forgets        []Forget
	Init           InitIn
}

var le = binary.LittleEndian

// Parse decodes one request. After ErrShort nothing is set; after any other error the
// header fields are set and the request is answered EINVAL (or not at all, if it takes no reply).
func Parse(b []byte) (Request, error) {
	if len(b) < InHeaderLen {
		return Request{}, ErrShort
	}
	r := Request{Opcode: le.Uint32(b[4:]), Unique: le.Uint64(b[8:]), NodeID: le.Uint64(b[16:]),
		UID: le.Uint32(b[24:]), GID: le.Uint32(b[28:]), PID: le.Uint32(b[32:])}
	if int64(le.Uint32(b)) != int64(len(b)) {
		return r, fmt.Errorf("%w: header says %d bytes, frame has %d", errArgs, le.Uint32(b), len(b))
	}
	return r, r.args(b[InHeaderLen:])
}

func (r *Request) args(p []byte) error {
	fixed := func(n int) error {
		if len(p) != n {
			return fmt.Errorf("%w: %s takes %d bytes, got %d", errArgs, OpName(r.Opcode), n, len(p))
		}
		return nil
	}
	var err error
	switch r.Opcode {
	case OpLookup, OpUnlink, OpRmdir:
		r.Name, err = names(p, 1)
	case OpMkdir:
		if len(p) < 8 {
			return fixed(8)
		}
		r.Mode = le.Uint32(p)
		r.Name, err = names(p[8:], 1)
	case OpCreate:
		if len(p) < 16 {
			return fixed(16)
		}
		r.Flags, r.Mode = le.Uint32(p), le.Uint32(p[4:])
		r.Name, err = names(p[16:], 1)
	case OpSymlink:
		var n []string
		if n, err = split(p, 2); err == nil {
			r.Name, r.Name2, err = n[0], n[1], CheckName(n[0])
			if err == nil && (r.Name2 == "" || len(r.Name2) >= PathMax) {
				err = fmt.Errorf("%w: symlink target of %d bytes", errArgs, len(r.Name2))
			}
		}
	case OpRename:
		if len(p) < 8 {
			return fixed(8)
		}
		r.NewDir = le.Uint64(p)
		var n []string
		if n, err = split(p[8:], 2); err == nil {
			r.Name, r.Name2 = n[0], n[1]
			err = errors.Join(CheckName(n[0]), CheckName(n[1]))
		}
	case OpForget:
		if err = fixed(8); err == nil {
			r.Forgets = []Forget{{r.NodeID, le.Uint64(p)}}
		}
	case OpBatchForget:
		if len(p) < 8 || uint64(len(p)-8) != uint64(le.Uint32(p))*16 {
			return fmt.Errorf("%w: batch_forget of %d bytes", errArgs, len(p))
		}
		for q := p[8:]; len(q) >= 16; q = q[16:] {
			r.Forgets = append(r.Forgets, Forget{le.Uint64(q), le.Uint64(q[8:])})
		}
	case OpGetattr:
		if err = fixed(16); err == nil {
			r.Flags, r.Fh = le.Uint32(p), le.Uint64(p[8:])
		}
	case OpSetattr:
		if err = fixed(SetattrInLen); err == nil {
			r.Setattr = Setattr{Valid: le.Uint32(p), Fh: le.Uint64(p[8:]), Size: le.Uint64(p[16:]),
				Atime: le.Uint64(p[32:]), Mtime: le.Uint64(p[40:]), Atimensec: le.Uint32(p[56:]),
				Mtimensec: le.Uint32(p[60:]), Mode: le.Uint32(p[68:]), UID: le.Uint32(p[76:]), GID: le.Uint32(p[80:])}
		}
	case OpOpen, OpOpendir, OpAccess, OpInterrupt:
		if err = fixed(8); err == nil {
			r.Flags = le.Uint32(p)
		}
	case OpRead, OpReaddir, OpReaddirplus:
		if err = fixed(ReadInLen); err == nil {
			r.Fh, r.Offset, r.Size = le.Uint64(p), le.Uint64(p[8:]), le.Uint32(p[16:])
		}
	case OpWrite:
		if len(p) < WriteInLen || uint64(len(p)-WriteInLen) != uint64(le.Uint32(p[16:])) {
			return fmt.Errorf("%w: write of %d bytes", errArgs, len(p))
		}
		r.Fh, r.Offset, r.Size, r.Data = le.Uint64(p), le.Uint64(p[8:]), le.Uint32(p[16:]), p[WriteInLen:]
	case OpRelease, OpReleasedir, OpFlush:
		if err = fixed(ReleaseInLen); err == nil {
			r.Fh = le.Uint64(p)
		}
	case OpFsync, OpFsyncdir:
		if err = fixed(16); err == nil {
			r.Fh = le.Uint64(p)
		}
	case OpInit:
		if len(p) < 16 {
			return fixed(InitInLen)
		}
		r.Init = InitIn{le.Uint32(p), le.Uint32(p[4:]), le.Uint32(p[8:]), le.Uint32(p[12:])}
	case OpStatfs, OpReadlink, OpDestroy:
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

func names(p []byte, n int) (string, error) {
	s, err := split(p, n)
	if err != nil {
		return "", err
	}
	return s[0], CheckName(s[0])
}

// CheckName refuses anything that is not one ordinary path component.
func CheckName(s string) error {
	if s == "" || s == "." || s == ".." || len(s) > NameMax || strings.ContainsAny(s, "/\x00") {
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

// Attr is fuse_attr.
type Attr struct {
	Ino, Size, Blocks                uint64
	Atime, Mtime, Ctime              uint64
	Atimensec, Mtimensec, Ctimensec  uint32
	Mode, Nlink, UID, GID, Rdev, Blk uint32
}

func (a Attr) append(b []byte) []byte {
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

// EntryOut is fuse_entry_out; generation is always 0 because node IDs are never reused.
func EntryOut(nodeID uint64, valid time.Duration, a Attr) []byte {
	b := le.AppendUint64(make([]byte, 0, EntryOutLen), nodeID)
	b = appendValid(appendValid(le.AppendUint64(b, 0), valid), valid)
	ns := uint32(valid % time.Second)
	return a.append(le.AppendUint32(le.AppendUint32(b, ns), ns))
}

// AttrOut is fuse_attr_out.
func AttrOut(valid time.Duration, a Attr) []byte {
	b := appendValid(make([]byte, 0, AttrOutLen), valid)
	return a.append(le.AppendUint32(le.AppendUint32(b, uint32(valid%time.Second)), 0))
}

// OpenOut is fuse_open_out with no open flags: the page cache is used.
func OpenOut(fh uint64) []byte {
	b := make([]byte, OpenOutLen)
	le.PutUint64(b, fh)
	return b
}

// WriteOut is fuse_write_out.
func WriteOut(n uint32) []byte {
	b := make([]byte, WriteOutLen)
	le.PutUint32(b, n)
	return b
}

// Kstatfs is fuse_kstatfs.
type Kstatfs struct {
	Blocks, Bfree, Bavail, Files, Ffree uint64
	Bsize, Namelen, Frsize              uint32
}

func (k Kstatfs) Bytes() []byte {
	b := make([]byte, 0, KstatfsLen)
	for _, v := range []uint64{k.Blocks, k.Bfree, k.Bavail, k.Files, k.Ffree} {
		b = le.AppendUint64(b, v)
	}
	b = le.AppendUint32(le.AppendUint32(le.AppendUint32(b, k.Bsize), k.Namelen), k.Frsize)
	return append(b, make([]byte, KstatfsLen-len(b))...) // padding, spare[6]
}

// InitOut is the reply to in: protocol 7.min(kernel minor, 37), the flags of this server
// that the kernel offered, and the returned flags.
func InitOut(in InitIn) ([]byte, uint32) {
	b := make([]byte, InitOutLen)
	flags := in.Flags & Flags
	le.PutUint32(b, Major)
	le.PutUint32(b[4:], min(in.Minor, MaxMinor))
	le.PutUint32(b[8:], MaxReadahead)
	le.PutUint32(b[12:], flags)
	le.PutUint16(b[16:], 12) // max_background
	le.PutUint16(b[18:], 9)  // congestion_threshold
	le.PutUint32(b[20:], MaxWrite)
	le.PutUint32(b[24:], 1) // time_gran
	return b, flags
}

// DirentSize is the bytes one entry of name takes in a READDIR or READDIRPLUS reply.
func DirentSize(name string, plus bool) int {
	n := DirentLen + len(name)
	if plus {
		n += EntryOutLen
	}
	return (n + 7) &^ 7
}

// AppendDirent appends one fuse_dirent (entry nil) or fuse_direntplus (entry a 128-byte EntryOut).
// off is the offset of the next entry; typ is the S_IFMT bits shifted down by 12.
func AppendDirent(b, entry []byte, ino, off uint64, typ uint32, name string) []byte {
	end := len(b) + DirentSize(name, entry != nil)
	b = append(b, entry...)
	b = le.AppendUint32(le.AppendUint32(le.AppendUint64(le.AppendUint64(b, ino), off), uint32(len(name))), typ)
	b = append(b, name...)
	return append(b, make([]byte, end-len(b))...)
}

// Copy is the guest's whole FUSE part: each request read from dev goes to the host as
// one frame, and each frame from the host is written to dev as one reply. It parses
// nothing but the length and opcode it logs for the first 20 requests, and the unique of
// a request too long for one frame, which it answers E2BIG itself. It returns when the
// mount ends (nil) or the stream fails.
func Copy(dev *os.File, c *wire.Conn, logf func(string, ...any)) error {
	errc := make(chan error, 2)
	go func() {
		buf := make([]byte, 1<<20)
		for i := 0; ; i++ {
			n, err := dev.Read(buf)
			switch {
			case errors.Is(err, syscall.ENODEV):
				errc <- nil
				return
			case errors.Is(err, syscall.EINTR):
				continue
			case err == nil && n < InHeaderLen:
				err = fmt.Errorf("%d bytes", n)
				fallthrough
			case err != nil:
				logf("fuse read %v", err)
				errc <- fmt.Errorf("read /dev/fuse: %w", err)
				return
			}
			if i < 20 && n >= 8 {
				logf("fuse request %d %s len=%d", i, OpName(le.Uint32(buf[4:])), n)
			}
			if n > wire.MaxPayload {
				logf("fuse request of %d bytes answered E2BIG", n)
				if _, err := dev.Write(Out(le.Uint64(buf[8:]), syscall.E2BIG)); err != nil {
					logf("fuse write %v", err)
				}
				continue
			}
			if err := c.WriteFrame(wire.Frame{Type: FrameType, Payload: buf[:n]}); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		for {
			f, err := c.ReadFrame()
			if err != nil {
				errc <- err
				return
			}
			if _, err := dev.Write(f.Payload); err != nil && !errors.Is(err, syscall.ENOENT) {
				logf("fuse write %v", err) // EINVAL: a reply the kernel refused
			}
		}
	}()
	return <-errc
}
