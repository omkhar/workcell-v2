// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// fixture is a temporary tree: the export, and beside it a secret that no request may reach.
type fixture struct {
	dir, export, secret string
	secretStat          os.FileInfo
}

const longName = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // 255 bytes

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	fx := &fixture{dir: dir, export: filepath.Join(dir, "export"), secret: filepath.Join(dir, "secret")}
	e := fx.export
	steps := []error{
		os.Mkdir(e, 0o755),
		os.WriteFile(fx.secret, []byte("secret"), 0o600),
		os.WriteFile(filepath.Join(dir, "other"), []byte("other"), 0o644),
		os.WriteFile(filepath.Join(e, "a.txt"), []byte("abc"), 0o644),
		os.WriteFile(filepath.Join(e, longName), []byte("long"), 0o644),
		os.WriteFile(filepath.Join(e, "victim"), []byte("v"), 0o644),
		os.WriteFile(filepath.Join(e, "fg"), nil, 0o644),
		os.WriteFile(filepath.Join(e, "big"), make([]byte, 70000), 0o644),
		os.Symlink("../secret", filepath.Join(e, "ln")),
		os.Symlink("..", filepath.Join(e, "up")),
		os.Symlink("loop2", filepath.Join(e, "loop1")),
		os.Symlink("loop1", filepath.Join(e, "loop2")),
		unix.Mkfifo(filepath.Join(e, "fifo"), 0o644),
		os.Link(filepath.Join(dir, "other"), filepath.Join(e, "hl")),
		os.Link(filepath.Join(e, "a.txt"), filepath.Join(dir, "hl2")),
	}
	for _, d := range []string{"d", "swap", "a/b", "sub", "p/q", "r1/r2", "e1", "e2", "c1", "fgd"} {
		steps = append(steps, os.MkdirAll(filepath.Join(e, d), 0o755))
	}
	for _, f := range []string{"d/f", "e1/x", "e2/y", "c1/inner", "fgd/fgc"} {
		steps = append(steps, os.WriteFile(filepath.Join(e, f), []byte(f), 0o644))
	}
	for _, err := range steps {
		if err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("unix", filepath.Join(e, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if fx.secretStat, err = os.Lstat(fx.secret); err != nil {
		t.Fatal(err)
	}
	return fx
}

// checkSecret fails if the secret beside the export changed in bytes, mode or mtime.
func (fx *fixture) checkSecret(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(fx.secret)
	st, err2 := os.Lstat(fx.secret)
	if err != nil || err2 != nil || string(b) != "secret" || st.Mode() != fx.secretStat.Mode() ||
		!st.ModTime().Equal(fx.secretStat.ModTime()) {
		t.Errorf("the secret beside the export changed: %q %v %v %v", b, err, err2, st)
	}
}

// beside lists what lies beside the export, sorted.
func (fx *fixture) beside(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(fx.dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// kern plays the guest kernel: it writes requests and reads replies over a pipe.
type kern struct {
	t *testing.T
	c *wire.Conn
	n uint64 // the last unique used
}

type reply struct {
	unique uint64
	errno  syscall.Errno
	body   []byte
}

// start serves fx.export to a new kern. stop ends the stream and returns what Serve did.
func start(t *testing.T, export string) (*kern, func() error) {
	t.Helper()
	s, err := Open(export)
	if err != nil {
		t.Fatal(err)
	}
	host, guest := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(host) }()
	k := &kern{t: t, c: wire.New(guest, 5*time.Second)}
	return k, func() error { _ = guest.Close(); return <-done }
}

// send writes one request with a fresh unique, which it returns.
func (k *kern) send(b []byte) uint64 {
	k.t.Helper()
	k.n++
	le.PutUint64(b[8:], k.n)
	k.raw(b)
	return k.n
}

func (k *kern) raw(b []byte) {
	k.t.Helper()
	if err := k.c.WriteFrame(wire.Frame{Type: FrameType, Payload: b}); err != nil {
		k.t.Fatal(err)
	}
}

// recv reads one reply and checks its header against the frame.
func (k *kern) recv() reply {
	k.t.Helper()
	f, err := k.c.ReadFrame()
	if err != nil {
		k.t.Fatal(err)
	}
	p := f.Payload
	if f.Type != FrameType || len(p) < OutHeaderLen || int(le.Uint32(p)) != len(p) {
		k.t.Fatalf("bad reply header % x", p[:min(len(p), 16)])
	}
	r := reply{le.Uint64(p[8:]), syscall.Errno(-int32(le.Uint32(p[4:]))), p[OutHeaderLen:]}
	if r.errno != 0 && len(r.body) != 0 {
		k.t.Fatalf("error reply %v carries %d bytes", r.errno, len(r.body))
	}
	return r
}

// call sends one request and returns its reply.
func (k *kern) call(b []byte) (syscall.Errno, []byte) {
	k.t.Helper()
	u := k.send(b)
	r := k.recv()
	if r.unique != u {
		k.t.Fatalf("reply for %d, want %d", r.unique, u)
	}
	return r.errno, r.body
}

// ok is call for a request that must succeed.
func (k *kern) ok(b []byte) []byte {
	k.t.Helper()
	e, body := k.call(b)
	if e != 0 {
		k.t.Fatalf("%v", e)
	}
	return body
}

// batch sends every request without waiting and returns the replies by unique. The pipe is
// synchronous, so the replies are drained while the requests go out.
func (k *kern) batch(reqs [][]byte) map[uint64]reply {
	k.t.Helper()
	uniques := make([]uint64, len(reqs))
	for i := range reqs {
		k.n++
		uniques[i] = k.n
		le.PutUint64(reqs[i][8:], k.n)
	}
	written := make(chan struct{})
	go func() {
		defer close(written)
		for _, b := range reqs {
			if err := k.c.WriteFrame(wire.Frame{Type: FrameType, Payload: b}); err != nil {
				return
			}
		}
	}()
	out := make(map[uint64]reply, len(reqs))
	for range reqs {
		r := k.recv()
		out[r.unique] = r
	}
	<-written
	return out
}

// Request builders; the unique is filled in by send.

func reqInit(major, minor uint32) []byte {
	return req(opInit, 0, 0, u32(major, minor, 131072, ^uint32(0)), make([]byte, 48))
}
func reqLookup(node uint64, name string) []byte { return req(opLookup, 0, node, cstr(name)) }
func reqGetattr(node uint64) []byte             { return req(opGetattr, 0, node, u32(0, 0), u64(0)) }
func reqGetattrFh(node, fh uint64) []byte       { return req(opGetattr, 0, node, u32(getattrFh, 0), u64(fh)) }
func reqOpen(node uint64, flags uint32) []byte  { return req(opOpen, 0, node, u32(flags, 0)) }
func reqRead(node, fh, off uint64, size uint32) []byte {
	return req(opRead, 0, node, u64(fh, off), u32(size, 0), u64(0), u32(0, 0))
}
func reqWrite(node, fh, off uint64, data []byte) []byte {
	return req(opWrite, 0, node, u64(fh, off), u32(uint32(len(data)), 0), u64(0), u32(0, 0), data)
}
func reqCreate(node uint64, name string, flags, mode uint32) []byte {
	return req(opCreate, 0, node, u32(flags, mode, 0o22, 0), cstr(name))
}
func reqMkdir(node uint64, name string) []byte {
	return req(opMkdir, 0, node, u32(0o755, 0o22), cstr(name))
}
func reqUnlink(node uint64, name string) []byte { return req(opUnlink, 0, node, cstr(name)) }
func reqRmdir(node uint64, name string) []byte  { return req(opRmdir, 0, node, cstr(name)) }
func reqRename(old uint64, name string, newdir uint64, name2 string) []byte {
	return req(opRename, 0, old, u64(newdir), cstr(name, name2))
}
func reqSymlink(node uint64, name, target string) []byte {
	return req(opSymlink, 0, node, cstr(name, target))
}
func reqReadlink(node uint64) []byte { return req(opReadlink, 0, node) }
func reqSetattr(node uint64, valid uint32, fh, size uint64, mode uint32) []byte {
	b := make([]byte, setattrInLen)
	le.PutUint32(b, valid)
	le.PutUint64(b[8:], fh)
	le.PutUint64(b[16:], size)
	le.PutUint32(b[68:], mode)
	return req(opSetattr, 0, node, b)
}
func reqOpendir(node uint64) []byte { return req(opOpendir, 0, node, u32(0, 0)) }
func reqReaddir(node, fh, off uint64, size uint32, plus bool) []byte {
	op := uint32(opReaddir)
	if plus {
		op = opReaddirplus
	}
	return req(op, 0, node, u64(fh, off), u32(size, 0), u64(0), u32(0, 0))
}
func reqRelease(node, fh uint64) []byte { return req(opRelease, 0, node, u64(fh), u32(0, 0), u64(0)) }
func reqReleasedir(node, fh uint64) []byte {
	return req(opReleasedir, 0, node, u64(fh), u32(0, 0), u64(0))
}
func reqFlush(node, fh uint64) []byte { return req(opFlush, 0, node, u64(fh), u32(0, 0), u64(0)) }
func reqFsync(node, fh uint64) []byte { return req(opFsync, 0, node, u64(fh), u32(0, 0)) }
func reqForget(node, n uint64) []byte { return req(opForget, 0, node, u64(n)) }
func reqStatfs() []byte               { return req(opStatfs, 0, 1) }

// Reply readers.

func entryMode(b []byte) uint32  { return le.Uint32(b[40+60:]) & unix.S_IFMT }
func entryPerm(b []byte) uint32  { return le.Uint32(b[40+60:]) & 0o7777 }
func entryNlink(b []byte) uint32 { return le.Uint32(b[40+64:]) }
func attrMode(b []byte) uint32   { return le.Uint32(b[16+60:]) & unix.S_IFMT }
func attrSize(b []byte) uint64   { return le.Uint64(b[16+8:]) }
func attrOwner(b []byte) (uint32, uint32) {
	return le.Uint32(b[16+68:]), le.Uint32(b[16+72:])
}

// dirNames lists the names of a READDIR or READDIRPLUS reply.
func dirNames(b []byte, plus bool) []string {
	var out []string
	skip := 0
	if plus {
		skip = entryOutLen
	}
	for len(b) >= skip+direntLen {
		n := int(le.Uint32(b[skip+16:]))
		name := string(b[skip+direntLen : skip+direntLen+n])
		out = append(out, name)
		b = b[direntSize(name, plus):]
	}
	return out
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func joined(names []string) string { return strings.Join(names, ",") }
