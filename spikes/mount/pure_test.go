// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package mount

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/spikes/mount/fuse"
)

var le = binary.LittleEndian

// req is a request as the kernel writes it: the 40-byte header, then the arguments.
func req(op uint32, unique, node uint64, args ...[]byte) []byte {
	b := make([]byte, fuse.InHeaderLen)
	for _, a := range args {
		b = append(b, a...)
	}
	le.PutUint32(b, uint32(len(b)))
	le.PutUint32(b[4:], op)
	le.PutUint64(b[8:], unique)
	le.PutUint64(b[16:], node)
	return b
}

func cstr(s ...string) []byte { return []byte(strings.Join(s, "\x00") + "\x00") }

func u32(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = le.AppendUint32(b, x)
	}
	return b
}

func u64(v ...uint64) []byte {
	var b []byte
	for _, x := range v {
		b = le.AppendUint64(b, x)
	}
	return b
}

func TestSizes(t *testing.T) {
	a := fuse.Attr{Ino: 7, Size: 16, Mode: 0o100644, Nlink: 1, Blk: 4096}
	entry := fuse.EntryOut(42, 1500*time.Millisecond, a)
	attr := fuse.AttrOut(time.Second, a)
	ini, _ := fuse.InitOut(fuse.InitIn{Major: 7, Minor: 37})
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"fuse_entry_out", len(entry), fuse.EntryOutLen},
		{"fuse_entry_out.nodeid", int(le.Uint64(entry)), 42},
		{"fuse_entry_out.entry_valid", int(le.Uint64(entry[16:])), 1},
		{"fuse_entry_out.attr_valid", int(le.Uint64(entry[24:])), 1},
		{"fuse_entry_out.entry_valid_nsec", int(le.Uint32(entry[32:])), 500_000_000},
		{"fuse_entry_out.attr.ino", int(le.Uint64(entry[40:])), 7},
		{"fuse_entry_out.attr.mode", int(le.Uint32(entry[40+60:])), 0o100644},
		{"fuse_entry_out.attr.blksize", int(le.Uint32(entry[40+80:])), 4096},
		{"fuse_attr_out", len(attr), fuse.AttrOutLen},
		{"fuse_attr_out.attr.size", int(le.Uint64(attr[16+8:])), 16},
		{"fuse_attr_out.attr.nlink", int(le.Uint32(attr[16+64:])), 1},
		{"fuse_attr", fuse.AttrOutLen - 16, fuse.AttrLen},
		{"fuse_open_out", len(fuse.OpenOut(9)), fuse.OpenOutLen},
		{"fuse_write_out", len(fuse.WriteOut(5)), fuse.WriteOutLen},
		{"fuse_kstatfs", len(fuse.Kstatfs{Bsize: 4096}.Bytes()), fuse.KstatfsLen},
		{"fuse_kstatfs.bsize", int(le.Uint32(fuse.Kstatfs{Bsize: 4096}.Bytes()[40:])), 4096},
		{"fuse_init_out", len(ini), fuse.InitOutLen},
		{"fuse_out_header", len(fuse.Out(1, 0)), fuse.OutHeaderLen},
		{"fuse_out_header.len with body", int(le.Uint32(fuse.Out(1, 0, make([]byte, 8)))), 24},
		{"fuse_out_header.error", int(int32(le.Uint32(fuse.Out(1, syscall.ENOENT)[4:]))), -2},
		{"fuse_out_header.unique", int(le.Uint64(fuse.Out(77, 0)[8:])), 77},
		{"dirent a", fuse.DirentSize("a", false), 32},
		{"dirent 8", fuse.DirentSize("abcdefgh", false), 32},
		{"dirent 9", fuse.DirentSize("abcdefghi", false), 40},
		{"direntplus a", fuse.DirentSize("a", true), 160},
		{"direntplus 9", fuse.DirentSize("abcdefghi", true), 168},
		{"append dirent", len(fuse.AppendDirent(nil, nil, 1, 1, 8, "abcdefghi")), 40},
		{"append direntplus", len(fuse.AppendDirent(nil, entry, 1, 1, 8, "abcdefghi")), 168},
		{"direntplus.namelen", int(le.Uint32(fuse.AppendDirent(nil, entry, 1, 1, 8, "abc")[128+16:])), 3},
		{"one READ reply fits a frame", fuse.OutHeaderLen + fuse.MaxWrite, min(fuse.OutHeaderLen+fuse.MaxWrite, fuse.MaxReply)},
		{"one WRITE request fits a frame", fuse.InHeaderLen + fuse.WriteInLen + fuse.MaxWrite,
			min(fuse.InHeaderLen+fuse.WriteInLen+fuse.MaxWrite, fuse.MaxReply)},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestInitOut(t *testing.T) {
	for _, tc := range []struct {
		name               string
		in                 fuse.InitIn
		wantMinor, wantFlg uint32
	}{
		{"newer kernel offers everything", fuse.InitIn{Major: 7, Minor: 44, MaxReadahead: 1 << 20, Flags: ^uint32(0)}, 37, fuse.Flags},
		{"6.1 kernel", fuse.InitIn{Major: 7, Minor: 37, MaxReadahead: 131072, Flags: fuse.Flags | 1<<16}, 37, fuse.Flags},
		{"older kernel, fewer flags", fuse.InitIn{Major: 7, Minor: 31, MaxReadahead: 131072, Flags: fuse.FlagAsyncRead | fuse.FlagBigWrites}, 31,
			fuse.FlagAsyncRead | fuse.FlagBigWrites},
	} {
		b, flags := fuse.InitOut(tc.in)
		got := []uint32{le.Uint32(b), le.Uint32(b[4:]), le.Uint32(b[8:]), le.Uint32(b[12:]), uint32(le.Uint16(b[16:])),
			uint32(le.Uint16(b[18:])), le.Uint32(b[20:]), le.Uint32(b[24:]), uint32(le.Uint16(b[28:]))}
		want := []uint32{7, tc.wantMinor, fuse.MaxReadahead, tc.wantFlg, 12, 9, fuse.MaxWrite, 1, 0}
		if flags != tc.wantFlg || !equal(got, want) || !bytes.Equal(b[32:], make([]byte, 32)) {
			t.Errorf("%s: %v flags %#x, want %v", tc.name, got, flags, want)
		}
	}
}

func equal(a, b []uint32) bool { return len(a) == len(b) && string(u32(a...)) == string(u32(b...)) }

func TestCheckName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true}, {"..a", true}, {"a b", true}, {strings.Repeat("x", 255), true}, {"\xff", true},
		{"", false}, {".", false}, {"..", false}, {"a/b", false}, {"/", false}, {"a\x00", false},
		{strings.Repeat("x", 256), false},
	} {
		if err := fuse.CheckName(tc.name); (err == nil) != tc.ok {
			t.Errorf("%q: %v, want ok=%t", tc.name, err, tc.ok)
		}
	}
}

// parseCases are well-formed and malformed requests; the valid ones seed the fuzz target.
var parseCases = []struct {
	name  string
	b     []byte
	ok    bool
	check func(fuse.Request) bool
}{
	{"short", make([]byte, 39), false, nil},
	{"length mismatch", append(req(fuse.OpStatfs, 1, 1), 0), false, nil},
	{"lookup", req(fuse.OpLookup, 2, 1, cstr("a.txt")), true, func(r fuse.Request) bool { return r.Name == "a.txt" && r.Unique == 2 }},
	{"lookup dotdot", req(fuse.OpLookup, 3, 1, cstr("..")), false, nil},
	{"lookup slash", req(fuse.OpLookup, 3, 1, cstr("a/b")), false, nil},
	{"lookup empty", req(fuse.OpLookup, 3, 1, cstr("")), false, nil},
	{"lookup no NUL", req(fuse.OpLookup, 3, 1, []byte("a")), false, nil},
	{"lookup two names", req(fuse.OpLookup, 3, 1, cstr("a", "b")), false, nil},
	{"lookup 256", req(fuse.OpLookup, 3, 1, cstr(strings.Repeat("x", 256))), false, nil},
	{"unlink", req(fuse.OpUnlink, 4, 5, cstr("f")), true, func(r fuse.Request) bool { return r.Name == "f" && r.NodeID == 5 }},
	{"mkdir", req(fuse.OpMkdir, 5, 1, u32(0o755, 0o22), cstr("d")), true, func(r fuse.Request) bool { return r.Mode == 0o755 && r.Name == "d" }},
	{"mkdir short", req(fuse.OpMkdir, 5, 1, u32(0o755)), false, nil},
	{"create", req(fuse.OpCreate, 6, 1, u32(2, 0o644, 0o22, 0), cstr("n")), true, func(r fuse.Request) bool {
		return r.Flags == 2 && r.Mode == 0o644 && r.Name == "n"
	}},
	{"symlink", req(fuse.OpSymlink, 7, 1, cstr("ln", "/etc/passwd")), true, func(r fuse.Request) bool {
		return r.Name == "ln" && r.Name2 == "/etc/passwd"
	}},
	{"symlink empty target", req(fuse.OpSymlink, 7, 1, cstr("ln", "")), false, nil},
	{"symlink bad name", req(fuse.OpSymlink, 7, 1, cstr("a/b", "t")), false, nil},
	{"rename", req(fuse.OpRename, 8, 1, u64(9), cstr("a", "b")), true, func(r fuse.Request) bool {
		return r.NewDir == 9 && r.Name == "a" && r.Name2 == "b"
	}},
	{"rename bad new name", req(fuse.OpRename, 8, 1, u64(9), cstr("a", "..")), false, nil},
	{"forget", req(fuse.OpForget, 9, 5, u64(3)), true, func(r fuse.Request) bool {
		return len(r.Forgets) == 1 && r.Forgets[0] == fuse.Forget{NodeID: 5, N: 3}
	}},
	{"forget short", req(fuse.OpForget, 9, 5, u32(3)), false, nil},
	{"batch forget", req(fuse.OpBatchForget, 0, 0, u32(2, 0), u64(5, 1, 6, 2)), true, func(r fuse.Request) bool {
		return len(r.Forgets) == 2 && r.Forgets[1] == fuse.Forget{NodeID: 6, N: 2}
	}},
	{"batch forget count too high", req(fuse.OpBatchForget, 0, 0, u32(3, 0), u64(5, 1, 6, 2)), false, nil},
	{"batch forget count huge", req(fuse.OpBatchForget, 0, 0, u32(1<<31, 0)), false, nil},
	{"getattr", req(fuse.OpGetattr, 10, 1, u32(1, 0), u64(4)), true, func(r fuse.Request) bool { return r.Flags == 1 && r.Fh == 4 }},
	{"setattr", req(fuse.OpSetattr, 11, 5, u32(fuse.FattrSize, 0), u64(0, 2), make([]byte, 64)), true, func(r fuse.Request) bool {
		return r.Setattr.Valid == fuse.FattrSize && r.Setattr.Size == 2
	}},
	{"setattr short", req(fuse.OpSetattr, 11, 5, make([]byte, 80)), false, nil},
	{"open", req(fuse.OpOpen, 12, 5, u32(2, 0)), true, func(r fuse.Request) bool { return r.Flags == 2 }},
	{"read", req(fuse.OpRead, 13, 5, u64(1, 4096), u32(61440, 0), u64(0), u32(0, 0)), true, func(r fuse.Request) bool {
		return r.Fh == 1 && r.Offset == 4096 && r.Size == 61440
	}},
	{"readdirplus", req(fuse.OpReaddirplus, 14, 1, u64(3, 2), u32(4096, 0), u64(0), u32(0, 0)), true, func(r fuse.Request) bool {
		return r.Fh == 3 && r.Offset == 2
	}},
	{"write", req(fuse.OpWrite, 15, 5, u64(1, 0), u32(5, 0), u64(0), u32(0, 0), []byte("hello")), true, func(r fuse.Request) bool {
		return string(r.Data) == "hello" && r.Size == 5
	}},
	{"write size mismatch", req(fuse.OpWrite, 15, 5, u64(1, 0), u32(6, 0), u64(0), u32(0, 0), []byte("hello")), false, nil},
	{"release", req(fuse.OpRelease, 16, 5, u64(1), u32(0, 0), u64(0)), true, func(r fuse.Request) bool { return r.Fh == 1 }},
	{"fsync", req(fuse.OpFsync, 17, 5, u64(1), u32(0, 0)), true, func(r fuse.Request) bool { return r.Fh == 1 }},
	{"init", req(fuse.OpInit, 18, 0, u32(7, 37, 131072, 0x3ffffffb), make([]byte, 48)), true, func(r fuse.Request) bool {
		return r.Init == fuse.InitIn{Major: 7, Minor: 37, MaxReadahead: 131072, Flags: 0x3ffffffb}
	}},
	{"init short", req(fuse.OpInit, 18, 0, u32(7, 37, 131072)), false, nil},
	{"statfs", req(fuse.OpStatfs, 19, 1), true, func(r fuse.Request) bool { return r.Opcode == fuse.OpStatfs }},
	{"statfs with bytes", req(fuse.OpStatfs, 19, 1, []byte{0}), false, nil},
	{"unknown opcode", req(99, 20, 1, []byte("anything")), true, func(r fuse.Request) bool { return r.Opcode == 99 }},
}

func TestParse(t *testing.T) {
	for _, tc := range parseCases {
		r, err := fuse.Parse(tc.b)
		if (err == nil) != tc.ok || (tc.check != nil && !tc.check(r)) {
			t.Errorf("%s: %+v, %v; want ok=%t", tc.name, r, err, tc.ok)
		}
		if tc.name == "short" && !errors.Is(err, fuse.ErrShort) {
			t.Errorf("short: %v, want ErrShort", err)
		}
	}
}

// FuzzRequest holds the decoder of guest-controlled bytes (T5): it never panics, and what it
// accepts is consistent with the bytes.
func FuzzRequest(f *testing.F) {
	for _, tc := range parseCases {
		f.Add(tc.b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := fuse.Parse(b)
		if err != nil {
			return
		}
		switch r.Opcode {
		case fuse.OpLookup, fuse.OpUnlink, fuse.OpRmdir, fuse.OpMkdir, fuse.OpCreate, fuse.OpSymlink:
			if fuse.CheckName(r.Name) != nil {
				t.Fatalf("accepted name %q", r.Name)
			}
		case fuse.OpRename:
			if fuse.CheckName(r.Name) != nil || fuse.CheckName(r.Name2) != nil {
				t.Fatalf("accepted names %q %q", r.Name, r.Name2)
			}
		case fuse.OpWrite:
			if len(r.Data) != int(r.Size) || len(b) != fuse.InHeaderLen+fuse.WriteInLen+len(r.Data) {
				t.Fatalf("write of %d bytes, size %d, frame %d", len(r.Data), r.Size, len(b))
			}
		case fuse.OpBatchForget:
			if len(b) != fuse.InHeaderLen+8+16*len(r.Forgets) {
				t.Fatalf("%d forgets in %d bytes", len(r.Forgets), len(b))
			}
		}
	})
}
