// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// step is one row: a host-side action, one request, the errno it must get, and a check of
// the body. Rows are numbered after the redteam's adversarial list.
type step struct {
	name  string
	pre   func()
	req   func() []byte
	want  syscall.Errno
	after func(t *testing.T, body []byte)
}

// TestAdversarial plays the redteam's list against one export, in order, over a pipe. The
// secret beside the export must be unchanged at the end, and nothing new may lie beside it.
// A directory the host moved away answers ENOENT for its own entry (row 23, direct) and
// ESTALE when an ancestor moved or the entry was replaced (rows 23 deep and 14).
func TestAdversarial(t *testing.T) {
	fx := newFixture(t)
	k, stop := start(t, fx.export)
	id := map[string]uint64{"root": rootID}
	n := func(name string) uint64 { return id[name] }
	save := func(name string) func(*testing.T, []byte) {
		return func(_ *testing.T, b []byte) { id[name] = le.Uint64(b) }
	}
	saveFile := func(node, fh string) func(*testing.T, []byte) { // a CREATE reply: entry, then open
		return func(_ *testing.T, b []byte) { id[node], id[fh] = le.Uint64(b), le.Uint64(b[entryOutLen:]) }
	}
	kind := func(name string, mode uint32) func(*testing.T, []byte) {
		return func(t *testing.T, b []byte) {
			id[name] = le.Uint64(b)
			if entryMode(b) != mode {
				t.Errorf("mode %#o, want %#o", entryMode(b), mode)
			}
		}
	}
	bytesAre := func(want string) func(*testing.T, []byte) {
		return func(t *testing.T, b []byte) {
			if string(b) != want {
				t.Errorf("body %q, want %q", b, want)
			}
		}
	}
	lenIs := func(want int) func(*testing.T, []byte) {
		return func(t *testing.T, b []byte) {
			if len(b) != want {
				t.Errorf("body of %d bytes, want %d", len(b), want)
			}
		}
	}
	same := func(name string) func(*testing.T, []byte) {
		return func(t *testing.T, b []byte) {
			if le.Uint64(b) != id[name] {
				t.Errorf("node %d, want %s=%d", le.Uint64(b), name, id[name])
			}
		}
	}
	host := func(errs ...func() error) func() {
		return func() {
			for _, f := range errs {
				if err := f(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	ex := func(p string) string { return filepath.Join(fx.export, p) }
	rm := func(p string) func() error { return func() error { return os.Remove(ex(p)) } }
	ln := func(target, p string) func() error { return func() error { return os.Symlink(target, ex(p)) } }
	mv := func(p, beside string) func() error {
		return func() error { return os.Rename(ex(p), filepath.Join(fx.dir, beside)) }
	}
	steps := []step{
		{name: "52 lookup before init", req: func() []byte { return reqLookup(1, "a.txt") }, want: syscall.EIO},
		{name: "52 init major 6", req: func() []byte { return reqInit(6, 37) }, want: syscall.EPROTO},
		{name: "52 init major 8 minor max", req: func() []byte { return reqInit(8, math.MaxUint32) }, want: syscall.EPROTO},
		{name: "init", req: func() []byte { return reqInit(7, 44) }, after: func(t *testing.T, b []byte) {
			if len(b) != initOutLen || le.Uint32(b[4:]) != 37 || le.Uint32(b[12:]) != initFlags || le.Uint32(b[20:]) != MaxWrite {
				t.Errorf("init reply % x", b)
			}
		}},
		{name: "52 second init", req: func() []byte { return reqInit(7, 37) }, want: syscall.EIO},
		{name: "lookup a.txt", req: func() []byte { return reqLookup(1, "a.txt") }, after: kind("a", unix.S_IFREG)},
		{name: "lookup d", req: func() []byte { return reqLookup(1, "d") }, after: kind("d", unix.S_IFDIR)},
		{name: "1 lookup root ..", req: func() []byte { return reqLookup(1, "..") }, want: syscall.EINVAL},
		{name: "1 lookup child ..", req: func() []byte { return reqLookup(n("d"), "..") }, want: syscall.EINVAL},
		{name: "2 lookup root .", req: func() []byte { return reqLookup(1, ".") }, want: syscall.EINVAL},
		{name: "3 lookup empty", req: func() []byte { return reqLookup(1, "") }, want: syscall.EINVAL},
		{name: "3 lookup NUL only", req: func() []byte { return req(opLookup, 0, 1, []byte{0}) }, want: syscall.EINVAL},
		{name: "4 lookup ../secret", req: func() []byte { return reqLookup(1, "../secret") }, want: syscall.EINVAL},
		{name: "4 lookup sub/../../secret", req: func() []byte { return reqLookup(1, "sub/../../secret") }, want: syscall.EINVAL},
		{name: "5 lookup embedded NUL", req: func() []byte { return reqLookup(1, "a\x00../secret") }, want: syscall.EINVAL},
		{name: "6 name of 255 bytes", req: func() []byte { return reqLookup(1, longName) }, after: kind("long", unix.S_IFREG)},
		{name: "6 name of 256 bytes", req: func() []byte { return reqLookup(1, longName+"x") }, want: syscall.EINVAL},
		{name: "7 lookup without NUL", req: func() []byte { return req(opLookup, 0, 1, []byte("a.txt")) }, want: syscall.EINVAL},
		{name: "7 lookup trailing bytes", req: func() []byte { return req(opLookup, 0, 1, cstr("a.txt"), []byte("x")) }, want: syscall.EINVAL},
		{name: "7 mkdir without NUL", req: func() []byte { return req(opMkdir, 0, 1, u32(0o755, 0), []byte("m")) }, want: syscall.EINVAL},
		{name: "7 create trailing bytes", req: func() []byte { return req(opCreate, 0, 1, u32(2, 0o644, 0, 0), cstr("c"), []byte{1}) }, want: syscall.EINVAL},
		{name: "7 unlink without NUL", req: func() []byte { return req(opUnlink, 0, 1, []byte("a.txt")) }, want: syscall.EINVAL},
		{name: "7 rmdir trailing bytes", req: func() []byte { return req(opRmdir, 0, 1, cstr("d"), []byte{0}) }, want: syscall.EINVAL},
		{name: "8 rename one name", req: func() []byte { return req(opRename, 0, 1, u64(1), cstr("a.txt")) }, want: syscall.EINVAL},
		{name: "8 rename to ..", req: func() []byte { return reqRename(1, "a.txt", 1, "..") }, want: syscall.EINVAL},
		{name: "8 rename to a slash", req: func() []byte { return reqRename(1, "a.txt", 1, "../secret") }, want: syscall.EINVAL},
		{name: "67 mkdir .", req: func() []byte { return reqMkdir(1, ".") }, want: syscall.EINVAL},
		{name: "67 create ..", req: func() []byte { return reqCreate(1, "..", unix.O_RDWR, 0o644) }, want: syscall.EINVAL},
		{name: "67 symlink .", req: func() []byte { return reqSymlink(1, ".", "x") }, want: syscall.EINVAL},
		{name: "lookup ln", req: func() []byte { return reqLookup(1, "ln") }, after: kind("ln", unix.S_IFLNK)},
		{name: "9 symlink to ../secret", req: func() []byte { return reqSymlink(1, "l", "../secret") }, after: kind("l", unix.S_IFLNK)},
		{name: "9 readlink", req: func() []byte { return reqReadlink(n("l")) }, after: bytesAre("../secret")},
		{name: "9 open symlink", req: func() []byte { return reqOpen(n("l"), unix.O_RDONLY) }, want: syscall.ELOOP},
		{name: "10 symlink absolute", req: func() []byte { return reqSymlink(1, "abs", "/etc/passwd") }, after: kind("abs", unix.S_IFLNK)},
		{name: "10 open absolute symlink", req: func() []byte { return reqOpen(n("abs"), unix.O_RDONLY) }, want: syscall.ELOOP},
		{name: "10 symlink target 4095", req: func() []byte { return reqSymlink(1, "t4095", strings.Repeat("t", 4095)) }},
		{name: "10 symlink target 4096", req: func() []byte { return reqSymlink(1, "t4096", strings.Repeat("t", 4096)) }, want: syscall.EINVAL},
		{name: "11 lookup through symlink", req: func() []byte { return reqLookup(n("ln"), "secret") }, want: syscall.ENOTDIR},
		{name: "12 lookup up", req: func() []byte { return reqLookup(1, "up") }, after: kind("up", unix.S_IFLNK)},
		{name: "12 opendir symlink to ..", req: func() []byte { return reqOpendir(n("up")) }, want: syscall.ENOTDIR},
		{name: "12 readdir symlink to ..", req: func() []byte { return reqReaddir(n("up"), 12345, 0, 4096, false) }, want: syscall.EBADF},
		{name: "12 readdirplus symlink to ..", req: func() []byte { return reqReaddir(n("up"), 12345, 0, 4096, true) }, want: syscall.EBADF},
		{name: "13 chmod symlink", req: func() []byte { return reqSetattr(n("ln"), fattrMode, 0, 0, 0o777) }, want: syscall.EPERM},
		{name: "13 truncate symlink", req: func() []byte { return reqSetattr(n("ln"), fattrSize, 0, 0, 0) }, want: syscall.EPERM},
		{name: "13 utimens symlink", req: func() []byte { return reqSetattr(n("ln"), fattrMtimeNow|fattrAtimeNow, 0, 0, 0) }},
		{name: "14 lookup swap", req: func() []byte { return reqLookup(1, "swap") }, after: kind("swap", unix.S_IFDIR)},
		{name: "14 create in a dir the host swapped for a symlink", pre: host(rm("swap"), ln("..", "swap")),
			req: func() []byte { return reqCreate(n("swap"), "written", unix.O_RDWR, 0o644) }, want: syscall.ESTALE},
		{name: "14 lookup swap again is the symlink", req: func() []byte { return reqLookup(1, "swap") }, after: kind("swap2", unix.S_IFLNK)},
		{name: "15 lookup victim", req: func() []byte { return reqLookup(1, "victim") }, after: kind("victim", unix.S_IFREG)},
		{name: "15 open a file the host swapped for a symlink", pre: host(rm("victim"), ln("../secret", "victim")),
			req: func() []byte { return reqOpen(n("victim"), unix.O_RDWR) }, want: syscall.ELOOP},
		{name: "16 symlink loop a", req: func() []byte { return reqLookup(1, "loop1") }, after: kind("loop1", unix.S_IFLNK)},
		{name: "16 symlink loop b", req: func() []byte { return reqLookup(1, "loop2") }, after: kind("loop2", unix.S_IFLNK)},
		{name: "17 link", req: func() []byte { return req(13, 0, 1, u64(n("a")), cstr("hlx")) }, want: syscall.ENOSYS},
		{name: "18 hard link to a file beside the export", req: func() []byte { return reqLookup(1, "hl") }, after: func(t *testing.T, b []byte) {
			kind("hl", unix.S_IFREG)(t, b)
			if entryNlink(b) != 2 {
				t.Errorf("nlink %d, want 2", entryNlink(b))
			}
		}},
		{name: "18 lookup through the hard link", req: func() []byte { return reqLookup(n("hl"), "secret") }, want: syscall.ENOTDIR},
		{name: "18 the link beside the export has no name here", req: func() []byte { return reqLookup(1, "hl2") }, want: syscall.ENOENT},
		{name: "19 mknod", req: func() []byte { return req(8, 0, 1, u32(unix.S_IFCHR|0o600, 0x0800, 0, 0), cstr("dev")) }, want: syscall.ENOSYS},
		{name: "20 lookup fifo", req: func() []byte { return reqLookup(1, "fifo") }, after: kind("fifo", unix.S_IFIFO)},
		{name: "20 open fifo", req: func() []byte { return reqOpen(n("fifo"), unix.O_RDONLY) }, want: syscall.EPERM},
		{name: "21 lookup socket", req: func() []byte { return reqLookup(1, "sock") }, after: kind("sock", unix.S_IFSOCK)},
		{name: "21 open socket", req: func() []byte { return reqOpen(n("sock"), unix.O_RDWR) }, want: syscall.EPERM},
		{name: "22 lookup a", req: func() []byte { return reqLookup(1, "a") }, after: kind("dira", unix.S_IFDIR)},
		{name: "22 lookup a/b", req: func() []byte { return reqLookup(n("dira"), "b") }, after: kind("dirb", unix.S_IFDIR)},
		{name: "22 rename a to x", req: func() []byte { return reqRename(1, "a", 1, "x") }},
		{name: "22 symlink a to ..", req: func() []byte { return reqSymlink(1, "a", "..") }, after: kind("a-link", unix.S_IFLNK)},
		{name: "22 create through b lands in x/b", req: func() []byte { return reqCreate(n("dirb"), "written", unix.O_RDWR, 0o644) },
			after: func(t *testing.T, _ []byte) {
				if !exists(ex("x/b/written")) || exists(filepath.Join(fx.dir, "written")) {
					t.Error("written is not in x/b, or is beside the export")
				}
			}},
		{name: "23 lookup sub", req: func() []byte { return reqLookup(1, "sub") }, after: kind("sub", unix.S_IFDIR)},
		{name: "23 create in a dir the host moved beside the export", pre: host(mv("sub", "sub-moved")),
			req: func() []byte { return reqCreate(n("sub"), "f", unix.O_RDWR, 0o644) }, want: syscall.ENOENT},
		{name: "23 mkdir in it", req: func() []byte { return reqMkdir(n("sub"), "d") }, want: syscall.ENOENT},
		{name: "23 lookup in it", req: func() []byte { return reqLookup(n("sub"), "f") }, want: syscall.ENOENT},
		{name: "23 getattr of it", req: func() []byte { return reqGetattr(n("sub")) }, want: syscall.ENOENT},
		{name: "23 opendir of it", req: func() []byte { return reqOpendir(n("sub")) }, want: syscall.ENOENT},
		{name: "23 the name is gone", req: func() []byte { return reqLookup(1, "sub") }, want: syscall.ENOENT},
		{name: "23 lookup p", req: func() []byte { return reqLookup(1, "p") }, after: kind("p", unix.S_IFDIR)},
		{name: "23 lookup p/q", req: func() []byte { return reqLookup(n("p"), "q") }, after: kind("q", unix.S_IFDIR)},
		{name: "23 create under a moved ancestor", pre: host(mv("p", "p-moved")),
			req: func() []byte { return reqCreate(n("q"), "f", unix.O_RDWR, 0o644) }, want: syscall.ESTALE},
		{name: "24 lookup r1", req: func() []byte { return reqLookup(1, "r1") }, after: kind("r1", unix.S_IFDIR)},
		{name: "24 lookup r1/r2", req: func() []byte { return reqLookup(n("r1"), "r2") }, after: kind("r2", unix.S_IFDIR)},
		{name: "24 rename into own descendant", req: func() []byte { return reqRename(1, "r1", n("r2"), "c") }, want: syscall.EINVAL},
		{name: "24 the chain still works", req: func() []byte { return reqGetattr(n("r2")) }},
		{name: "25 lookup e2", req: func() []byte { return reqLookup(1, "e2") }, after: kind("e2", unix.S_IFDIR)},
		{name: "25 rename over a dir with children", req: func() []byte { return reqRename(1, "e1", 1, "e2") }, want: syscall.ENOTEMPTY},
		{name: "25 e2 is unchanged", req: func() []byte { return reqLookup(1, "e2") }, after: same("e2")},
		{name: "26 create o1", req: func() []byte { return reqCreate(1, "o1", unix.O_RDWR, 0o644) }, after: saveFile("o1", "fh-o1")},
		{name: "26 write o1", req: func() []byte { return reqWrite(n("o1"), n("fh-o1"), 0, []byte("one")) }},
		{name: "26 create o2", req: func() []byte { return reqCreate(1, "o2", unix.O_RDWR, 0o644) }, after: saveFile("o2", "fh-o2")},
		{name: "26 write o2", req: func() []byte { return reqWrite(n("o2"), n("fh-o2"), 0, []byte("two")) }},
		{name: "26 rename o2 over open o1", req: func() []byte { return reqRename(1, "o2", 1, "o1") }},
		{name: "26 old fh reads the old inode", req: func() []byte { return reqRead(n("o1"), n("fh-o1"), 0, 100) }, after: bytesAre("one")},
		{name: "26 the name is the moved node", req: func() []byte { return reqLookup(1, "o1") }, after: same("o2")},
		{name: "26 the replaced node is gone", req: func() []byte { return reqGetattr(n("o1")) }, want: syscall.ENOENT},
		{name: "28 lookup fg", req: func() []byte { return reqLookup(1, "fg") }, after: save("fg")},
		{name: "28 forget fg", req: func() []byte { return reqForget(n("fg"), 1) }, after: nil},
		{name: "28 getattr forgotten", req: func() []byte { return reqGetattr(n("fg")) }, want: syscall.ENOENT},
		{name: "28 open forgotten", req: func() []byte { return reqOpen(n("fg"), unix.O_RDONLY) }, want: syscall.ENOENT},
		{name: "28 lookup in forgotten", req: func() []byte { return reqLookup(n("fg"), "x") }, want: syscall.ENOENT},
		{name: "28 a new node never takes the slot", req: func() []byte { return reqLookup(1, "fg") }, after: func(t *testing.T, b []byte) {
			if le.Uint64(b) == id["fg"] {
				t.Error("node id reused")
			}
		}},
		{name: "29 lookup fgd", req: func() []byte { return reqLookup(1, "fgd") }, after: save("fgd")},
		{name: "29 lookup fgd/fgc", req: func() []byte { return reqLookup(n("fgd"), "fgc") }, after: save("fgc")},
		{name: "29 forget fgd too many times", req: func() []byte { return reqForget(n("fgd"), 100) }},
		{name: "32 the child keeps its parent", req: func() []byte { return reqGetattr(n("fgc")) }},
		{name: "32 forget the child", req: func() []byte { return reqForget(n("fgc"), 1) }},
		{name: "32 then the parent goes", req: func() []byte { return reqGetattr(n("fgd")) }, want: syscall.ENOENT},
		{name: "30 forget root", req: func() []byte { return reqForget(1, 5) }},
		{name: "30 batch forget root", req: func() []byte { return req(opBatchForget, 0, 0, u32(1, 0), u64(1, 5)) }},
		{name: "30 root remains", req: func() []byte { return reqLookup(1, "a.txt") }, after: same("a")},
		{name: "31 batch forget count beyond payload", req: func() []byte { return req(opBatchForget, 0, 0, u32(3, 0), u64(n("a"), 1, n("d"), 1)) }},
		{name: "31 nothing was dropped", req: func() []byte { return reqGetattr(n("a")) }},
		{name: "33 create u", req: func() []byte { return reqCreate(1, "u", unix.O_RDWR, 0o644) }, after: saveFile("u", "fh-u")},
		{name: "33 write u", req: func() []byte { return reqWrite(n("u"), n("fh-u"), 0, []byte("uuu")) }},
		{name: "33 unlink u", req: func() []byte { return reqUnlink(1, "u") }},
		{name: "33 getattr unlinked", req: func() []byte { return reqGetattr(n("u")) }, want: syscall.ENOENT},
		{name: "33 open unlinked", req: func() []byte { return reqOpen(n("u"), unix.O_RDONLY) }, want: syscall.ENOENT},
		{name: "33 the open fh still reads u", req: func() []byte { return reqRead(n("u"), n("fh-u"), 0, 10) }, after: bytesAre("uuu")},
		{name: "33 getattr by fh", req: func() []byte { return reqGetattrFh(n("u"), n("fh-u")) }},
		{name: "34 mkdir rd", req: func() []byte { return reqMkdir(1, "rd") }, after: kind("rd", unix.S_IFDIR)},
		{name: "34 opendir rd", req: func() []byte { return reqOpendir(n("rd")) }, after: save("dfh-rd")},
		{name: "34 rmdir rd", req: func() []byte { return reqRmdir(1, "rd") }},
		{name: "34 readdir on the stale handle", req: func() []byte { return reqReaddir(n("rd"), n("dfh-rd"), 0, 4096, true) }, want: syscall.ENOENT},
		{name: "34 releasedir", req: func() []byte { return reqReleasedir(n("rd"), n("dfh-rd")) }},
		{name: "35 open a", req: func() []byte { return reqOpen(n("a"), unix.O_RDWR) }, after: save("fh1")},
		{name: "35 release", req: func() []byte { return reqRelease(n("a"), n("fh1")) }},
		{name: "35 read released", req: func() []byte { return reqRead(n("a"), n("fh1"), 0, 10) }, want: syscall.EBADF},
		{name: "35 write released", req: func() []byte { return reqWrite(n("a"), n("fh1"), 0, []byte("x")) }, want: syscall.EBADF},
		{name: "35 fsync released", req: func() []byte { return reqFsync(n("a"), n("fh1")) }, want: syscall.EBADF},
		{name: "35 flush released", req: func() []byte { return reqFlush(n("a"), n("fh1")) }, want: syscall.EBADF},
		{name: "35 open a again", req: func() []byte { return reqOpen(n("a"), unix.O_RDWR) }, after: func(t *testing.T, b []byte) {
			if id["fh2"] = le.Uint64(b); id["fh2"] == id["fh1"] {
				t.Error("fh reused")
			}
		}},
		{name: "35 the old fh does not reach the new descriptor", req: func() []byte { return reqRead(n("a"), n("fh1"), 0, 10) }, want: syscall.EBADF},
		{name: "36 release fh2", req: func() []byte { return reqRelease(n("a"), n("fh2")) }},
		{name: "36 release fh2 again", req: func() []byte { return reqRelease(n("a"), n("fh2")) }, want: syscall.EBADF},
		{name: "36 open a third time", req: func() []byte { return reqOpen(n("a"), unix.O_RDONLY) }, after: save("fh3")},
		{name: "36 the third descriptor is intact", req: func() []byte { return reqRead(n("a"), n("fh3"), 0, 10) }, after: bytesAre("abc")},
		{name: "39 open a for 39", req: func() []byte { return reqOpen(n("a"), unix.O_RDWR) }, after: save("fhA")},
		{name: "39 read with another node's fh", req: func() []byte { return reqRead(n("d"), n("fhA"), 0, 10) }, want: syscall.EBADF},
		{name: "39 truncate with another node's fh", req: func() []byte { return reqSetattr(1, fattrFh|fattrSize, n("fhA"), 0, 0) }, want: syscall.EBADF},
		{name: "39 a.txt is whole", req: func() []byte { return reqRead(n("a"), n("fhA"), 0, 10) }, after: bytesAre("abc")},
		{name: "40 opendir root", req: func() []byte { return reqOpendir(1) }, after: save("dfh")},
		{name: "40 read a directory fh", req: func() []byte { return reqRead(1, n("dfh"), 0, 10) }, want: syscall.EISDIR},
		{name: "40 write a directory fh", req: func() []byte { return reqWrite(1, n("dfh"), 0, []byte("x")) }, want: syscall.EISDIR},
		{name: "40 readdir a file fh", req: func() []byte { return reqReaddir(n("a"), n("fhA"), 0, 4096, false) }, want: syscall.ENOTDIR},
		{name: "41 write to a read-only fh", req: func() []byte { return reqWrite(n("a"), n("fh3"), 0, []byte("zzz")) }, want: syscall.EBADF},
		{name: "42 lookup big", req: func() []byte { return reqLookup(1, "big") }, after: save("big")},
		{name: "42 open big", req: func() []byte { return reqOpen(n("big"), unix.O_RDONLY) }, after: save("fhB")},
		{name: "42 read of 4 GiB is clamped", req: func() []byte { return reqRead(n("big"), n("fhB"), 0, math.MaxUint32) }, after: lenIs(MaxWrite)},
		{name: "43 readdir of 4 GiB fits a frame", req: func() []byte { return reqReaddir(1, n("dfh"), 0, math.MaxUint32, false) },
			after: func(t *testing.T, b []byte) {
				if len(b) > MaxWrite || !slices.Contains(dirNames(b, false), "a.txt") {
					t.Errorf("%d bytes, names %v", len(b), dirNames(b, false))
				}
			}},
		{name: "43 readdirplus of 4 GiB fits a frame", req: func() []byte { return reqReaddir(1, n("dfh"), 0, math.MaxUint32, true) },
			after: func(t *testing.T, b []byte) {
				if len(b) > MaxWrite || !slices.Contains(dirNames(b, true), "big") {
					t.Errorf("%d bytes, names %v", len(b), dirNames(b, true))
				}
			}},
		{name: "44 write size above payload", req: func() []byte {
			return req(opWrite, 0, n("a"), u64(n("fhA"), 0), u32(9, 0), u64(0), u32(0, 0), []byte("xyz"))
		}, want: syscall.EINVAL},
		{name: "44 write size below payload", req: func() []byte {
			return req(opWrite, 0, n("a"), u64(n("fhA"), 0), u32(1, 0), u64(0), u32(0, 0), []byte("xyz"))
		}, want: syscall.EINVAL},
		{name: "45 write at 2^63", req: func() []byte { return reqWrite(n("a"), n("fhA"), 1<<63, []byte("x")) }, want: syscall.EINVAL},
		{name: "45 write at 2^64-1", req: func() []byte { return reqWrite(n("a"), n("fhA"), math.MaxUint64, []byte("x")) }, want: syscall.EINVAL},
		{name: "46 read past 2^64", req: func() []byte { return reqRead(n("big"), n("fhB"), math.MaxUint64-10, 100) }, want: syscall.EINVAL},
		{name: "47 truncate to 2^63", req: func() []byte { return reqSetattr(n("a"), fattrSize, 0, 1<<63, 0) }, want: syscall.EINVAL},
		{name: "44-47 a.txt is unchanged", req: func() []byte { return reqRead(n("a"), n("fhA"), 0, 10) }, after: bytesAre("abc")},
		{name: "48 header length disagrees", req: func() []byte { return append(reqStatfs(), 0) }, want: syscall.EINVAL},
		{name: "48 arguments too short", req: func() []byte { return req(opGetattr, 0, 1, u32(0)) }, want: syscall.EINVAL},
		{name: "54 interrupt for an unknown unique", req: func() []byte { return req(opInterrupt, 0, 0, u64(999)) }},
		{name: "62 create with setuid bits", req: func() []byte { return reqCreate(1, "suid", unix.O_RDWR, 0o6755) }, after: func(t *testing.T, b []byte) {
			if entryPerm(b) != 0o755 {
				t.Errorf("mode %#o, want 0755", entryPerm(b))
			}
		}},
		{name: "62 create with device bits", req: func() []byte { return reqCreate(1, "chr", unix.O_RDWR, unix.S_IFCHR|0o644) }, after: kind("chr", unix.S_IFREG)},
		{name: "63 create with stray flags", req: func() []byte {
			return reqCreate(1, "flagged", unix.O_PATH|unix.O_TMPFILE|unix.O_DIRECTORY|unix.O_NOCTTY|unix.O_ASYNC|unix.O_RDWR, 0o644)
		}, after: saveFile("flagged", "fh-flagged")},
		{name: "63 it is a plain writable file", req: func() []byte { return reqWrite(n("flagged"), n("fh-flagged"), 0, []byte("ok")) }},
		{name: "63 open with O_DIRECTORY on a file", req: func() []byte { return reqOpen(n("a"), unix.O_DIRECTORY|unix.O_RDONLY) }, after: save("fh-dir")},
		{name: "64 chown", req: func() []byte { return reqSetattr(n("a"), fattrUID|fattrGID, 0, 0, 0) }, want: syscall.EPERM},
		{name: "64 owner reads 0:0", req: func() []byte { return reqGetattr(n("a")) }, after: func(t *testing.T, b []byte) {
			if u, g := attrOwner(b); u != 0 || g != 0 || attrSize(b) != 3 || attrMode(b) != unix.S_IFREG {
				t.Errorf("owner %d:%d size %d", u, g, attrSize(b))
			}
		}},
		{name: "68 readlink of a file", req: func() []byte { return reqReadlink(n("a")) }, want: syscall.EINVAL},
		{name: "68 readlink of the root", req: func() []byte { return reqReadlink(1) }, want: syscall.EINVAL},
		{name: "68 readlink of a dir", req: func() []byte { return reqReadlink(n("d")) }, want: syscall.EINVAL},
	}
	steps = append(steps, badIDs(n)...)
	steps = append(steps, step{name: "53 destroy", req: func() []byte { return req(opDestroy, 0, 0) }},
		step{name: "53 nothing after destroy", req: func() []byte { return reqStatfs() }, want: syscall.EIO})
	quiet := map[uint32]bool{opForget: true, opBatchForget: true, opInterrupt: true}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.pre != nil {
				st.pre()
			}
			b := st.req()
			if quiet[le.Uint32(b[4:])] { // no reply: the next request's reply shows the stream is intact
				k.send(b)
				if e, _ := k.call(reqStatfs()); e != 0 {
					t.Fatalf("statfs after a quiet request: %v", e)
				}
				return
			}
			e, body := k.call(b)
			if e != st.want {
				t.Fatalf("%v, want %v", e, st.want)
			}
			if st.after != nil {
				st.after(t, body)
			}
		})
	}
	if err := stop(); err != nil {
		t.Errorf("Serve: %v", err)
	}
	fx.checkSecret(t)
	if got := fx.beside(t); strings.Join(got, ",") != "export,hl2,other,p-moved,secret,sub-moved" {
		t.Errorf("beside the export: %v", got)
	}
	for _, p := range []string{"hlx", "dev", "t4096", "x/f"} {
		if exists(ex(p)) {
			t.Errorf("%s was created", p)
		}
	}
	if b, err := os.ReadFile(ex("a.txt")); err != nil || string(b) != "abc" {
		t.Errorf("a.txt: %q %v", b, err)
	}
	for _, p := range []string{"sub-moved", "p-moved/q"} {
		if ents, err := os.ReadDir(filepath.Join(fx.dir, p)); err != nil || len(ents) != 0 {
			t.Errorf("%s holds %d entries, %v", p, len(ents), err)
		}
	}
}

// badIDs are rows 37 and 38: node ids and file handles that index nothing.
func badIDs(n func(string) uint64) []step {
	var steps []step
	for _, id := range []struct {
		name string
		v    func() uint64
	}{{"0", func() uint64 { return 0 }}, {"2^64-1", func() uint64 { return math.MaxUint64 }},
		{"above the table", func() uint64 { return 1 << 40 }}, {"freed", func() uint64 { return n("fg") }}} {
		for _, op := range []struct {
			name string
			req  func(uint64) []byte
		}{{"getattr", reqGetattr}, {"lookup", func(v uint64) []byte { return reqLookup(v, "x") }},
			{"open", func(v uint64) []byte { return reqOpen(v, 0) }}, {"opendir", reqOpendir},
			{"mkdir", func(v uint64) []byte { return reqMkdir(v, "x") }}, {"readlink", reqReadlink},
			{"setattr", func(v uint64) []byte { return reqSetattr(v, fattrMode, 0, 0, 0o644) }},
			{"rename", func(v uint64) []byte { return reqRename(v, "x", 1, "y") }}} {
			steps = append(steps, step{name: "37 " + op.name + " of node " + id.name, want: syscall.ENOENT,
				req: func() []byte { return op.req(id.v()) }})
		}
	}
	for _, fh := range []struct {
		name string
		v    func() uint64
	}{{"0", func() uint64 { return 0 }}, {"2^64-1", func() uint64 { return math.MaxUint64 }},
		{"freed", func() uint64 { return n("fh1") }}} {
		for _, op := range []struct {
			name string
			req  func(uint64) []byte
		}{{"read", func(v uint64) []byte { return reqRead(n("a"), v, 0, 10) }},
			{"write", func(v uint64) []byte { return reqWrite(n("a"), v, 0, []byte("x")) }},
			{"getattr", func(v uint64) []byte { return reqGetattrFh(n("a"), v) }},
			{"setattr", func(v uint64) []byte { return reqSetattr(n("a"), fattrFh|fattrSize, v, 0, 0) }},
			{"release", func(v uint64) []byte { return reqRelease(n("a"), v) }}} {
			steps = append(steps, step{name: "38 " + op.name + " with fh " + fh.name, want: syscall.EBADF,
				req: func() []byte { return op.req(fh.v()) }})
		}
	}
	return steps
}
