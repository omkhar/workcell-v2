// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package fileserve

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

// req is a request as the kernel writes it: the 40-byte header, then the arguments.
func req(op uint32, unique, node uint64, args ...[]byte) []byte {
	b := make([]byte, InHeaderLen)
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
	a := attr{Ino: 7, Size: 16, Mode: 0o100644, Nlink: 1, Blk: 4096}
	entry := entryOut(42, 1500*time.Millisecond, a)
	ao := attrOut(time.Second, a)
	ini, _ := initOut(initIn{Major: 7, Minor: 37})
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"fuse_entry_out", len(entry), entryOutLen},
		{"fuse_entry_out.nodeid", int(le.Uint64(entry)), 42},
		{"fuse_entry_out.entry_valid", int(le.Uint64(entry[16:])), 1},
		{"fuse_entry_out.attr_valid", int(le.Uint64(entry[24:])), 1},
		{"fuse_entry_out.entry_valid_nsec", int(le.Uint32(entry[32:])), 500_000_000},
		{"fuse_entry_out.attr.ino", int(le.Uint64(entry[40:])), 7},
		{"fuse_entry_out.attr.mode", int(le.Uint32(entry[40+60:])), 0o100644},
		{"fuse_entry_out.attr.blksize", int(le.Uint32(entry[40+80:])), 4096},
		{"fuse_attr_out", len(ao), attrOutLen},
		{"fuse_attr_out.attr.size", int(le.Uint64(ao[16+8:])), 16},
		{"fuse_attr_out.attr.nlink", int(le.Uint32(ao[16+64:])), 1},
		{"fuse_attr", attrOutLen - 16, attrLen},
		{"fuse_open_out", len(openOut(9)), openOutLen},
		{"fuse_write_out", len(writeOut(5)), writeOutLen},
		{"fuse_kstatfs", len(kstatfs{Bsize: 4096}.bytes()), kstatfsLen},
		{"fuse_kstatfs.bsize", int(le.Uint32(kstatfs{Bsize: 4096}.bytes()[40:])), 4096},
		{"fuse_init_out", len(ini), initOutLen},
		{"fuse_out_header", len(Out(1, 0)), OutHeaderLen},
		{"fuse_out_header.len with body", int(le.Uint32(Out(1, 0, make([]byte, 8)))), 24},
		{"fuse_out_header.error", int(int32(le.Uint32(Out(1, syscall.ENOENT)[4:]))), -2},
		{"fuse_out_header.unique", int(le.Uint64(Out(77, 0)[8:])), 77},
		{"dirent a", direntSize("a", false), 32},
		{"dirent 8", direntSize("abcdefgh", false), 32},
		{"dirent 9", direntSize("abcdefghi", false), 40},
		{"direntplus a", direntSize("a", true), 160},
		{"direntplus 9", direntSize("abcdefghi", true), 168},
		{"append dirent", len(appendDirent(nil, nil, 1, 1, 8, "abcdefghi")), 40},
		{"append direntplus", len(appendDirent(nil, entry, 1, 1, 8, "abcdefghi")), 168},
		{"direntplus.namelen", int(le.Uint32(appendDirent(nil, entry, 1, 1, 8, "abc")[128+16:])), 3},
		{"one READ reply fits a frame", OutHeaderLen + MaxWrite, min(OutHeaderLen+MaxWrite, 64<<10)},
		{"one WRITE request fits a frame", InHeaderLen + writeInLen + MaxWrite, min(InHeaderLen+writeInLen+MaxWrite, 64<<10)},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestInitOut(t *testing.T) {
	for _, tc := range []struct {
		name               string
		in                 initIn
		wantMinor, wantFlg uint32
	}{
		{"newer kernel offers everything", initIn{Major: 7, Minor: 44, MaxReadahead: 1 << 20, Flags: ^uint32(0)}, 37, initFlags},
		{"kernel B as measured", initIn{Major: 7, Minor: 37, MaxReadahead: 131072, Flags: 0x73fffffb}, 37, 0x843029},
		{"older kernel, fewer flags", initIn{Major: 7, Minor: 31, MaxReadahead: 131072, Flags: flagAsyncRead | flagBigWrites}, 31,
			flagAsyncRead | flagBigWrites},
	} {
		b, flags := initOut(tc.in)
		got := []uint32{le.Uint32(b), le.Uint32(b[4:]), le.Uint32(b[8:]), le.Uint32(b[12:]), uint32(le.Uint16(b[16:])),
			uint32(le.Uint16(b[18:])), le.Uint32(b[20:]), le.Uint32(b[24:]), uint32(le.Uint16(b[28:]))}
		want := []uint32{7, tc.wantMinor, maxReadahead, tc.wantFlg, 12, 9, MaxWrite, 1, 0}
		if flags != tc.wantFlg || !bytes.Equal(u32(got...), u32(want...)) || !bytes.Equal(b[32:], make([]byte, 32)) {
			t.Errorf("%s: %v flags %#x, want %v and %#x", tc.name, got, flags, want, tc.wantFlg)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true}, {"..a", true}, {"a b", true}, {strings.Repeat("x", 255), true}, {"\xff", true},
		{"", false}, {".", false}, {"..", false}, {"a/b", false}, {"/", false}, {"a\x00", false},
		{"../secret", false}, {"sub/../../secret", false}, {strings.Repeat("x", 256), false},
	} {
		if err := checkName(tc.name); (err == nil) != tc.ok {
			t.Errorf("%q: %v, want ok=%t", tc.name, err, tc.ok)
		}
	}
}

// parseCases are well-formed and malformed requests; the valid ones seed the fuzz target.
var parseCases = []struct {
	name  string
	b     []byte
	ok    bool
	check func(request) bool
}{
	{"short", make([]byte, 39), false, nil},
	{"length mismatch", append(req(opStatfs, 1, 1), 0), false, nil},
	{"lookup", req(opLookup, 2, 1, cstr("a.txt")), true, func(r request) bool { return r.Name == "a.txt" && r.Unique == 2 }},
	{"lookup dotdot", req(opLookup, 3, 1, cstr("..")), false, nil},
	{"lookup dot", req(opLookup, 3, 1, cstr(".")), false, nil},
	{"lookup slash", req(opLookup, 3, 1, cstr("a/b")), false, nil},
	{"lookup empty", req(opLookup, 3, 1, cstr("")), false, nil},
	{"lookup embedded NUL", req(opLookup, 3, 1, cstr("a\x00../secret")), false, nil},
	{"lookup no NUL", req(opLookup, 3, 1, []byte("a")), false, nil},
	{"lookup trailing bytes", req(opLookup, 3, 1, cstr("a"), []byte("x")), false, nil},
	{"lookup two names", req(opLookup, 3, 1, cstr("a", "b")), false, nil},
	{"lookup 255", req(opLookup, 3, 1, cstr(strings.Repeat("x", 255))), true, nil},
	{"lookup 256", req(opLookup, 3, 1, cstr(strings.Repeat("x", 256))), false, nil},
	{"unlink", req(opUnlink, 4, 5, cstr("f")), true, func(r request) bool { return r.Name == "f" && r.NodeID == 5 }},
	{"unlink no NUL", req(opUnlink, 4, 5, []byte("f")), false, nil},
	{"rmdir trailing bytes", req(opRmdir, 4, 5, cstr("d"), []byte{0}), false, nil},
	{"mkdir", req(opMkdir, 5, 1, u32(0o755, 0o22), cstr("d")), true, func(r request) bool { return r.Mode == 0o755 && r.Name == "d" }},
	{"mkdir short", req(opMkdir, 5, 1, u32(0o755)), false, nil},
	{"mkdir dot", req(opMkdir, 5, 1, u32(0o755, 0o22), cstr(".")), false, nil},
	{"mkdir no NUL", req(opMkdir, 5, 1, u32(0o755, 0o22), []byte("d")), false, nil},
	{"create", req(opCreate, 6, 1, u32(2, 0o644, 0o22, 0), cstr("n")), true, func(r request) bool {
		return r.Flags == 2 && r.Mode == 0o644 && r.Name == "n"
	}},
	{"create dotdot", req(opCreate, 6, 1, u32(2, 0o644, 0o22, 0), cstr("..")), false, nil},
	{"create trailing bytes", req(opCreate, 6, 1, u32(2, 0o644, 0o22, 0), cstr("n"), []byte("x")), false, nil},
	{"symlink", req(opSymlink, 7, 1, cstr("ln", "/etc/passwd")), true, func(r request) bool {
		return r.Name == "ln" && r.Name2 == "/etc/passwd"
	}},
	{"symlink empty target", req(opSymlink, 7, 1, cstr("ln", "")), false, nil},
	{"symlink target 4095", req(opSymlink, 7, 1, cstr("ln", strings.Repeat("t", 4095))), true, nil},
	{"symlink target 4096", req(opSymlink, 7, 1, cstr("ln", strings.Repeat("t", 4096))), false, nil},
	{"symlink bad name", req(opSymlink, 7, 1, cstr("a/b", "t")), false, nil},
	{"symlink dot name", req(opSymlink, 7, 1, cstr(".", "t")), false, nil},
	{"rename", req(opRename, 8, 1, u64(9), cstr("a", "b")), true, func(r request) bool {
		return r.NewDir == 9 && r.Name == "a" && r.Name2 == "b"
	}},
	{"rename one name", req(opRename, 8, 1, u64(9), cstr("a")), false, nil},
	{"rename new name dotdot", req(opRename, 8, 1, u64(9), cstr("a", "..")), false, nil},
	{"rename new name slash", req(opRename, 8, 1, u64(9), cstr("a", "b/c")), false, nil},
	{"forget", req(opForget, 9, 5, u64(3)), true, func(r request) bool {
		return len(r.Forgets) == 1 && r.Forgets[0] == forget{NodeID: 5, N: 3}
	}},
	{"forget short", req(opForget, 9, 5, u32(3)), false, nil},
	{"batch forget", req(opBatchForget, 0, 0, u32(2, 0), u64(5, 1, 6, 2)), true, func(r request) bool {
		return len(r.Forgets) == 2 && r.Forgets[1] == forget{NodeID: 6, N: 2}
	}},
	{"batch forget count too high", req(opBatchForget, 0, 0, u32(3, 0), u64(5, 1, 6, 2)), false, nil},
	{"batch forget count huge", req(opBatchForget, 0, 0, u32(1<<31, 0)), false, nil},
	{"getattr", req(opGetattr, 10, 1, u32(1, 0), u64(4)), true, func(r request) bool { return r.Flags == 1 && r.Fh == 4 }},
	{"setattr", req(opSetattr, 11, 5, u32(fattrSize, 0), u64(0, 2), make([]byte, 64)), true, func(r request) bool {
		return r.Setattr.Valid == fattrSize && r.Setattr.Size == 2
	}},
	{"setattr short", req(opSetattr, 11, 5, make([]byte, 80)), false, nil},
	{"open", req(opOpen, 12, 5, u32(2, 0)), true, func(r request) bool { return r.Flags == 2 }},
	{"read", req(opRead, 13, 5, u64(1, 4096), u32(61440, 0), u64(0), u32(0, 0)), true, func(r request) bool {
		return r.Fh == 1 && r.Offset == 4096 && r.Size == 61440
	}},
	{"readdirplus", req(opReaddirplus, 14, 1, u64(3, 2), u32(4096, 0), u64(0), u32(0, 0)), true, func(r request) bool {
		return r.Fh == 3 && r.Offset == 2
	}},
	{"write", req(opWrite, 15, 5, u64(1, 0), u32(5, 0), u64(0), u32(0, 0), []byte("hello")), true, func(r request) bool {
		return string(r.Data) == "hello" && r.Size == 5
	}},
	{"write size larger than payload", req(opWrite, 15, 5, u64(1, 0), u32(6, 0), u64(0), u32(0, 0), []byte("hello")), false, nil},
	{"write size smaller than payload", req(opWrite, 15, 5, u64(1, 0), u32(4, 0), u64(0), u32(0, 0), []byte("hello")), false, nil},
	{"release", req(opRelease, 16, 5, u64(1), u32(0, 0), u64(0)), true, func(r request) bool { return r.Fh == 1 }},
	{"fsync", req(opFsync, 17, 5, u64(1), u32(0, 0)), true, func(r request) bool { return r.Fh == 1 }},
	{"init", req(opInit, 18, 0, u32(7, 37, 131072, 0x3ffffffb), make([]byte, 48)), true, func(r request) bool {
		return r.Init == initIn{Major: 7, Minor: 37, MaxReadahead: 131072, Flags: 0x3ffffffb}
	}},
	{"init short", req(opInit, 18, 0, u32(7, 37, 131072)), false, nil},
	{"statfs", req(opStatfs, 19, 1), true, func(r request) bool { return r.Opcode == opStatfs }},
	{"statfs with bytes", req(opStatfs, 19, 1, []byte{0}), false, nil},
	{"unknown opcode", req(99, 20, 1, []byte("anything")), true, func(r request) bool { return r.Opcode == 99 }},
}

func TestParse(t *testing.T) {
	for _, tc := range parseCases {
		r, err := parse(tc.b)
		if (err == nil) != tc.ok || (tc.check != nil && !tc.check(r)) {
			t.Errorf("%s: %+v, %v; want ok=%t", tc.name, r, err, tc.ok)
		}
		if tc.name == "short" && !errors.Is(err, errShort) {
			t.Errorf("short: %v, want errShort", err)
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
		r, err := parse(b)
		if err != nil {
			return
		}
		if int(le.Uint32(b)) != len(b) {
			t.Fatalf("accepted a header length of %d for %d bytes", le.Uint32(b), len(b))
		}
		switch r.Opcode {
		case opLookup, opUnlink, opRmdir, opMkdir, opCreate, opSymlink:
			if checkName(r.Name) != nil {
				t.Fatalf("accepted name %q", r.Name)
			}
		case opRename:
			if checkName(r.Name) != nil || checkName(r.Name2) != nil {
				t.Fatalf("accepted names %q %q", r.Name, r.Name2)
			}
		case opWrite:
			if len(r.Data) != int(r.Size) || len(b) != InHeaderLen+writeInLen+len(r.Data) {
				t.Fatalf("write of %d bytes, size %d, frame %d", len(r.Data), r.Size, len(b))
			}
		case opBatchForget:
			if len(b) != InHeaderLen+8+16*len(r.Forgets) {
				t.Fatalf("%d forgets in %d bytes", len(r.Forgets), len(b))
			}
		}
	})
}
