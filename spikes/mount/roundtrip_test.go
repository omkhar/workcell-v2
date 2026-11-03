// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package mount

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"github.com/omkhar/workcell/v2/spikes/mount/fuse"
	"github.com/omkhar/workcell/v2/spikes/mount/serve"
)

// rt is what one step of the round trip remembers for the next.
type rt struct{ a, n, s, ln, fh1, fh2, dfh uint64 }

// TestRoundTrip plays the guest kernel against the server over a pipe, one request at a
// time, on a temporary export with a symbolic link that points out of it.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	export := filepath.Join(dir, "export")
	outside := filepath.Join(dir, "outside")
	for _, err := range []error{os.Mkdir(export, 0o755), os.WriteFile(outside, []byte("secret"), 0o600),
		os.WriteFile(filepath.Join(export, "a.txt"), []byte("abc"), 0o644), os.Mkdir(filepath.Join(export, "d"), 0o755),
		os.Symlink(outside, filepath.Join(export, "ln"))} {
		if err != nil {
			t.Fatal(err)
		}
	}
	srv, err := serve.New(export, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	host, kern := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(wire.New(host, 5*time.Second)) }()
	k := wire.New(kern, 5*time.Second)
	var st rt
	id := func(b []byte) uint64 { return le.Uint64(b) }
	read := func(fh *uint64, size uint32) func(*rt) []byte {
		return func(s *rt) []byte { return req(fuse.OpRead, 0, 0, u64(*fh, 0), u32(size, 0), u64(0), u32(0, 0)) }
	}
	for i, tc := range []struct {
		name  string
		build func(*rt) []byte
		errno syscall.Errno
		size  int // the body; -1: any
		after func(*rt, []byte) bool
	}{
		{"init", func(*rt) []byte { return req(fuse.OpInit, 0, 0, u32(7, 44, 131072, ^uint32(0)), make([]byte, 48)) }, 0,
			fuse.InitOutLen, func(_ *rt, b []byte) bool { return le.Uint32(b[4:]) == 37 && le.Uint32(b[12:]) == fuse.Flags }},
		{"lookup a.txt", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, cstr("a.txt")) }, 0, fuse.EntryOutLen,
			func(s *rt, b []byte) bool { s.a = id(b); return le.Uint64(b[40+8:]) == 3 }},
		{"lookup a.txt again: same node", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, cstr("a.txt")) }, 0, fuse.EntryOutLen,
			func(s *rt, b []byte) bool { return id(b) == s.a }},
		{"getattr a", func(s *rt) []byte { return req(fuse.OpGetattr, 0, s.a, u32(0, 0), u64(0)) }, 0, fuse.AttrOutLen,
			func(_ *rt, b []byte) bool {
				return le.Uint64(b[16+8:]) == 3 && le.Uint32(b[16+60:])&syscall.S_IFMT == syscall.S_IFREG
			}},
		{"open a", func(s *rt) []byte { return req(fuse.OpOpen, 0, s.a, u32(syscall.O_RDWR, 0)) }, 0, fuse.OpenOutLen,
			func(s *rt, b []byte) bool { s.fh1 = id(b); return s.fh1 != 0 }},
		{"read a", read(&st.fh1, 4096), 0, 3, func(_ *rt, b []byte) bool { return string(b) == "abc" }},
		{"create new", func(*rt) []byte {
			return req(fuse.OpCreate, 0, 1, u32(syscall.O_RDWR, 0o644, 0o22, 0), cstr("new"))
		}, 0, fuse.EntryOutLen + fuse.OpenOutLen, func(s *rt, b []byte) bool { s.n, s.fh2 = id(b), id(b[fuse.EntryOutLen:]); return s.n != s.a }},
		{"create existing", func(*rt) []byte { return req(fuse.OpCreate, 0, 1, u32(syscall.O_RDWR, 0o644, 0, 0), cstr("a.txt")) },
			syscall.EEXIST, 0, nil},
		{"write new", func(s *rt) []byte {
			return req(fuse.OpWrite, 0, s.n, u64(s.fh2, 0), u32(5, 0), u64(0), u32(0, 0), []byte("hello"))
		}, 0, fuse.WriteOutLen, func(_ *rt, b []byte) bool { return le.Uint32(b) == 5 }},
		{"read new", read(&st.fh2, 61440), 0, 5, func(_ *rt, b []byte) bool { return string(b) == "hello" }},
		{"read bad fh", func(*rt) []byte { return req(fuse.OpRead, 0, 0, u64(999, 0), u32(10, 0), u64(0), u32(0, 0)) },
			syscall.EINVAL, 0, nil},
		{"lookup ln", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, cstr("ln")) }, 0, fuse.EntryOutLen,
			func(s *rt, b []byte) bool {
				s.ln = id(b)
				return le.Uint32(b[40+60:])&syscall.S_IFMT == syscall.S_IFLNK
			}},
		{"open ln refused", func(s *rt) []byte { return req(fuse.OpOpen, 0, s.ln, u32(syscall.O_RDONLY, 0)) }, syscall.ELOOP, 0, nil},
		{"readlink ln", func(s *rt) []byte { return req(fuse.OpReadlink, 0, s.ln) }, 0, len(outside),
			func(_ *rt, b []byte) bool { return string(b) == outside }},
		{"setattr ln mode refused", func(s *rt) []byte {
			return req(fuse.OpSetattr, 0, s.ln, u32(fuse.FattrMode, 0), make([]byte, 60), u32(0o777), make([]byte, 16))
		}, syscall.EPERM, 0, nil},
		{"lookup dotdot", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, cstr("..")) }, syscall.EINVAL, 0, nil},
		{"lookup missing", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, cstr("missing")) }, syscall.ENOENT, 0, nil},
		{"lookup in a file", func(s *rt) []byte { return req(fuse.OpLookup, 0, s.a, cstr("x")) }, syscall.ENOTDIR, 0, nil},
		{"lookup unknown node", func(*rt) []byte { return req(fuse.OpLookup, 0, 12345, cstr("x")) }, syscall.EINVAL, 0, nil},
		{"mkdir sub", func(*rt) []byte { return req(fuse.OpMkdir, 0, 1, u32(0o755, 0o22), cstr("sub")) }, 0, fuse.EntryOutLen,
			func(s *rt, b []byte) bool { s.s = id(b); return le.Uint32(b[40+60:])&syscall.S_IFMT == syscall.S_IFDIR }},
		{"rename new to sub/moved", func(s *rt) []byte { return req(fuse.OpRename, 0, 1, u64(s.s), cstr("new", "moved")) }, 0, 0, nil},
		{"getattr moved node", func(s *rt) []byte { return req(fuse.OpGetattr, 0, s.n, u32(0, 0), u64(0)) }, 0, fuse.AttrOutLen,
			func(_ *rt, b []byte) bool { return le.Uint64(b[16+8:]) == 5 }},
		{"setattr size", func(s *rt) []byte {
			return req(fuse.OpSetattr, 0, s.n, u32(fuse.FattrSize, 0), u64(0, 2), make([]byte, 64))
		}, 0, fuse.AttrOutLen, func(_ *rt, b []byte) bool { return le.Uint64(b[16+8:]) == 2 }},
		{"opendir root", func(*rt) []byte { return req(fuse.OpOpendir, 0, 1, u32(0, 0)) }, 0, fuse.OpenOutLen,
			func(s *rt, b []byte) bool { s.dfh = id(b); return true }},
		{"readdirplus root", func(s *rt) []byte {
			return req(fuse.OpReaddirplus, 0, 1, u64(s.dfh, 0), u32(4096, 0), u64(0), u32(0, 0))
		}, 0, -1, func(_ *rt, b []byte) bool { return slices.Equal(names(b), []string{"a.txt", "d", "ln", "sub"}) }},
		{"readdirplus from 3", func(s *rt) []byte {
			return req(fuse.OpReaddirplus, 0, 1, u64(s.dfh, 3), u32(4096, 0), u64(0), u32(0, 0))
		}, 0, fuse.DirentSize("sub", true), func(_ *rt, b []byte) bool { return slices.Equal(names(b), []string{"sub"}) }},
		{"readdirplus past the end", func(s *rt) []byte {
			return req(fuse.OpReaddirplus, 0, 1, u64(s.dfh, 4), u32(4096, 0), u64(0), u32(0, 0))
		}, 0, 0, nil},
		{"readdirplus too small for one", func(s *rt) []byte {
			return req(fuse.OpReaddirplus, 0, 1, u64(s.dfh, 0), u32(100, 0), u64(0), u32(0, 0))
		}, 0, 0, nil},
		{"unlink moved", func(s *rt) []byte { return req(fuse.OpUnlink, 0, s.s, cstr("moved")) }, 0, 0, nil},
		{"getattr unlinked node", func(s *rt) []byte { return req(fuse.OpGetattr, 0, s.n, u32(0, 0), u64(0)) }, syscall.ENOENT, 0, nil},
		{"getattr unlinked by fh", func(s *rt) []byte { return req(fuse.OpGetattr, 0, s.n, u32(fuse.GetattrFh, 0), u64(s.fh2)) }, 0,
			fuse.AttrOutLen, nil},
		{"rmdir sub", func(*rt) []byte { return req(fuse.OpRmdir, 0, 1, cstr("sub")) }, 0, 0, nil},
		{"symlink made", func(*rt) []byte { return req(fuse.OpSymlink, 0, 1, cstr("ln2", "../../etc")) }, 0, fuse.EntryOutLen, nil},
		{"statfs", func(*rt) []byte { return req(fuse.OpStatfs, 0, 1) }, 0, fuse.KstatfsLen, nil},
		{"unknown opcode", func(*rt) []byte { return req(99, 0, 1) }, syscall.ENOSYS, 0, nil},
		{"malformed", func(*rt) []byte { return req(fuse.OpLookup, 0, 1, []byte("x")) }, syscall.EINVAL, 0, nil},
		{"release", func(s *rt) []byte { return req(fuse.OpRelease, 0, s.a, u64(s.fh1), u32(0, 0), u64(0)) }, 0, 0, nil},
		{"release again", func(s *rt) []byte { return req(fuse.OpRelease, 0, s.a, u64(s.fh1), u32(0, 0), u64(0)) }, syscall.EINVAL, 0, nil},
		{"releasedir", func(s *rt) []byte { return req(fuse.OpReleasedir, 0, 1, u64(s.dfh), u32(0, 0), u64(0)) }, 0, 0, nil},
	} {
		b := tc.build(&st)
		le.PutUint64(b[8:], uint64(1000+i)) // unique
		if err := k.WriteFrame(wire.Frame{Type: fuse.FrameType, Payload: b}); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		f, err := k.ReadFrame()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		p := f.Payload
		if len(p) < fuse.OutHeaderLen || int(le.Uint32(p)) != len(p) || le.Uint64(p[8:]) != uint64(1000+i) {
			t.Fatalf("%s: bad reply header % x", tc.name, p[:min(len(p), 16)])
		}
		e, body := syscall.Errno(-int32(le.Uint32(p[4:]))), p[fuse.OutHeaderLen:]
		if e != tc.errno || (e != 0 && len(body) != 0) || (tc.size >= 0 && len(body) != tc.size) {
			t.Errorf("%s: errno %v body %d bytes, want %v and %d", tc.name, e, len(body), tc.errno, tc.size)
			continue
		}
		if tc.after != nil && !tc.after(&st, body) {
			t.Errorf("%s: unexpected reply % x", tc.name, body[:min(len(body), 64)])
		}
	}
	// What takes no reply, and what is not a request, leaves the stream usable.
	for _, b := range [][]byte{req(fuse.OpForget, 0, st.a, u64(2)), req(fuse.OpInterrupt, 0, 0, u64(1)), make([]byte, 10)} {
		if err := k.WriteFrame(wire.Frame{Type: fuse.FrameType, Payload: b}); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.WriteFrame(wire.Frame{Type: fuse.FrameType, Payload: req(fuse.OpStatfs, 7, 1)}); err != nil {
		t.Fatal(err)
	}
	if f, err := k.ReadFrame(); err != nil || le.Uint64(f.Payload[8:]) != 7 {
		t.Fatalf("statfs after the no-reply requests: %v", err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "secret" {
		t.Errorf("outside the export: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(export, "a.txt")); err != nil || string(b) != "abc" {
		t.Errorf("a.txt: %q %v", b, err)
	}
	_ = kern.Close()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

// names lists the names of a READDIRPLUS reply.
func names(b []byte) []string {
	var out []string
	for len(b) >= fuse.DirentPlusLen {
		n := int(le.Uint32(b[fuse.EntryOutLen+16:]))
		name := string(b[fuse.DirentPlusLen : fuse.DirentPlusLen+n])
		out = append(out, name)
		b = b[fuse.DirentSize(name, true):]
	}
	return out
}
