// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fileserve

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// openFDs counts this process's descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// started is start after INIT, with the descriptor count before Open.
func started(t *testing.T, export string) (*kern, func() error, int) {
	t.Helper()
	before := openFDs(t)
	k, stop := start(t, export)
	k.ok(reqInit(7, 37))
	return k, stop, before
}

// TestNodeCap is rows 57 and 61: the table stops at maxNodes with ENOMEM, a negative lookup
// never grows it, and FORGET gives the room back. READDIRPLUS makes a node per entry, as
// LOOKUP would, and hands back node 0 for an entry that got none.
func TestNodeCap(t *testing.T) {
	export := t.TempDir()
	dir, err := unix.Open(export, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxNodes { // a node is a name: hard links fill the table in a second, inodes take a minute
		if i%60000 == 0 {
			err = unix.Mknodat(dir, fmt.Sprint(i), unix.S_IFREG|0o644, 0)
		} else {
			err = unix.Linkat(dir, fmt.Sprint(i/60000*60000), dir, fmt.Sprint(i), 0)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = unix.Close(dir)
	k, stop, before := started(t, export)
	dfh := le.Uint64(k.ok(reqOpendir(1)))
	made, none, off := 0, "", uint64(0)
	for {
		body := k.ok(reqReaddir(1, dfh, off, math.MaxUint32, true))
		if len(body) == 0 {
			break
		}
		for b := body; len(b) > 0; {
			name := string(b[direntPlusLen : direntPlusLen+int(le.Uint32(b[entryOutLen+16:]))])
			if le.Uint64(b) != 0 {
				made++
			} else {
				none = name
			}
			off = le.Uint64(b[entryOutLen+8:])
			b = b[direntSize(name, true):]
		}
	}
	if made != maxNodes-1 || none == "" { // the root is one node
		t.Fatalf("%d nodes made, last without one %q; want %d", made, none, maxNodes-1)
	}
	if e, _ := k.call(reqLookup(1, none)); e != syscall.ENOMEM {
		t.Errorf("lookup at the cap: %v, want ENOMEM", e)
	}
	if e, _ := k.call(reqLookup(1, "missing")); e != syscall.ENOENT {
		t.Errorf("negative lookup at the cap: %v, want ENOENT", e)
	}
	if e, _ := k.call(reqLookup(1, "0")); e != 0 {
		t.Errorf("lookup of a known node at the cap: %v", e)
	}
	for i := range 2 { // two nodes forgotten make room for one more
		_, body := k.call(reqLookup(1, fmt.Sprint(i)))
		k.send(reqForget(le.Uint64(body), 3))
	}
	if e, _ := k.call(reqLookup(1, none)); e != 0 {
		t.Errorf("lookup after FORGET: %v", e)
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("%d descriptors open, %d before", after, before)
	}
}

// TestDescriptorCap is rows 58 and 59: directory nodes and open files each hold one
// descriptor, ENFILE at maxFDs, and FORGET or RELEASE restore service.
func TestDescriptorCap(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil || lim.Cur < maxFDs+64 {
		t.Skipf("RLIMIT_NOFILE %d: no room for the cap", lim.Cur)
	}
	export := t.TempDir()
	const extra = 8
	for i := range maxFDs + extra {
		if err := os.Mkdir(filepath.Join(export, fmt.Sprint(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(export, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	k, stop, before := started(t, export)
	count := func(replies map[uint64]reply, want syscall.Errno) (int, []uint64) {
		n, ids := 0, []uint64{}
		for _, r := range replies {
			if r.errno == want {
				n++
			}
			if r.errno == 0 && len(r.body) >= 8 {
				ids = append(ids, le.Uint64(r.body))
			}
		}
		return n, ids
	}
	reqs := make([][]byte, maxFDs+extra)
	for i := range reqs {
		reqs[i] = reqLookup(1, fmt.Sprint(i))
	}
	enfile, dirs := count(k.batch(reqs), syscall.ENFILE)
	if len(dirs) != maxFDs-1 || enfile != extra+1 { // the export holds one
		t.Fatalf("%d directories, %d ENFILE; want %d and %d", len(dirs), enfile, maxFDs-1, extra+1)
	}
	if peak := openFDs(t); peak < before+maxFDs-1 || peak > before+maxFDs+8 {
		t.Errorf("%d descriptors at the cap, %d before", peak, before)
	}
	if e, _ := k.call(reqOpen(1, 0)); e != syscall.EISDIR { // the root itself is not a file
		t.Errorf("open root: %v", e)
	}
	for _, id := range dirs {
		k.send(reqForget(id, 1))
	}
	k.ok(reqStatfs())
	f := le.Uint64(k.ok(reqLookup(1, "f")))
	for i := range reqs {
		reqs[i] = reqOpen(f, unix.O_RDONLY)
	}
	enfile, fhs := count(k.batch(reqs), syscall.ENFILE)
	if len(fhs) != maxFDs-1 || enfile != extra+1 {
		t.Fatalf("%d opens, %d ENFILE; want %d and %d", len(fhs), enfile, maxFDs-1, extra+1)
	}
	for i, fh := range fhs {
		reqs[i] = reqRelease(f, fh)
	}
	if n, _ := count(k.batch(reqs[:len(fhs)]), 0); n != len(fhs) {
		t.Fatalf("%d releases of %d", n, len(fhs))
	}
	if e, _ := k.call(reqOpen(f, unix.O_RDONLY)); e != 0 {
		t.Errorf("open after RELEASE: %v", e)
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("%d descriptors open, %d before", after, before)
	}
}

// TestInflight is rows 20, 27, 55 and 56: 17 requests at once all finish, FIFO opens
// included; a RENAME racing a LOOKUP in the renamed directory resolves against its
// descriptor; replies with one unique, or unique 0, do not cross.
func TestInflight(t *testing.T) {
	fx := newFixture(t)
	k, stop, _ := started(t, fx.export)
	fifo := le.Uint64(k.ok(reqLookup(1, "fifo")))
	reqs := make([][]byte, 17)
	for i := range reqs {
		reqs[i] = reqOpen(fifo, unix.O_RDONLY)
	}
	reqs = append(reqs, reqStatfs())
	for _, r := range k.batch(reqs) {
		if r.errno != syscall.EPERM && r.errno != 0 {
			t.Errorf("fifo open: %v", r.errno)
		}
	}
	c1 := le.Uint64(k.ok(reqLookup(1, "c1")))
	for i := range 2 {
		rename, lookup := reqRename(1, "c1", 1, "c2"), reqLookup(c1, "inner")
		if i == 1 {
			rename = reqRename(1, "c2", 1, "c1")
		}
		replies := k.batch([][]byte{rename, lookup})
		for _, r := range replies {
			if r.errno != 0 {
				t.Errorf("rename racing lookup: %v", r.errno)
			}
		}
	}
	if e, body := k.call(reqLookup(c1, "inner")); e != 0 || entryMode(body) != unix.S_IFREG {
		t.Errorf("lookup after the renames: %v", e)
	}
	for _, unique := range []uint64{0, 7} {
		two := [][]byte{reqStatfs(), reqGetattr(1)}
		for _, b := range two {
			le.PutUint64(b[8:], unique)
			k.raw(b)
		}
		sizes := map[int]int{}
		for range two {
			r := k.recv()
			if r.unique != unique || r.errno != 0 {
				t.Fatalf("reply %d %v for unique %d", r.unique, r.errno, unique)
			}
			sizes[len(r.body)]++
		}
		if sizes[kstatfsLen] != 1 || sizes[attrOutLen] != 1 {
			t.Errorf("replies for unique %d: %v", unique, sizes)
		}
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
}

// TestDeepChain is row 60: a chain of 300 directories, each a node with its descriptor,
// is served, and a file made at the bottom lands there.
func TestDeepChain(t *testing.T) {
	export := t.TempDir()
	k, stop, before := started(t, export)
	dir, path := uint64(1), export
	for i := range 300 {
		dir = le.Uint64(k.ok(reqMkdir(dir, fmt.Sprint("d", i))))
		path = filepath.Join(path, fmt.Sprint("d", i))
	}
	k.ok(reqCreate(dir, "bottom", unix.O_RDWR, 0o644))
	if !exists(filepath.Join(path, "bottom")) {
		t.Error("bottom is not at the bottom")
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("%d descriptors open, %d before", after, before)
	}
}

// TestReaddirPaging is rows 43 and 66: a listing longer than a frame is clamped to MaxWrite
// and paged by the offsets handed back, each name exactly once.
func TestReaddirPaging(t *testing.T) {
	export := t.TempDir()
	const n = 3000
	for i := range n {
		if err := os.WriteFile(filepath.Join(export, fmt.Sprintf("file%04d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	k, stop, _ := started(t, export)
	for _, plus := range []bool{false, true} {
		dfh := le.Uint64(k.ok(reqOpendir(1)))
		seen, off, pages := map[string]int{}, uint64(0), 0
		for {
			body := k.ok(reqReaddir(1, dfh, off, math.MaxUint32, plus))
			if len(body) > MaxWrite {
				t.Fatalf("plus=%t: reply of %d bytes", plus, len(body))
			}
			if len(body) == 0 {
				break
			}
			pages++
			skip := 0
			if plus {
				skip = entryOutLen
			}
			for b := body; len(b) > 0; {
				name := dirNames(b[:direntSize(string(b[skip+direntLen:skip+direntLen+int(le.Uint32(b[skip+16:]))]), plus)], plus)[0]
				seen[name]++
				off = le.Uint64(b[skip+8:])
				b = b[direntSize(name, plus):]
			}
		}
		if len(seen) != n || pages < 2 {
			t.Errorf("plus=%t: %d names in %d pages", plus, len(seen), pages)
		}
		for name, c := range seen {
			if c != 1 {
				t.Errorf("plus=%t: %s listed %d times", plus, name, c)
			}
		}
		k.ok(reqReleasedir(1, dfh))
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
}

// TestStreamEnd is row 49 and the clean end: a frame over the wire limit ends Serve with the
// wire's error, a closed stream ends it with nil, and either way no descriptor stays open.
func TestStreamEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(k *kern, guest net.Conn)
		want error
	}{
		{"stream closed", func(_ *kern, guest net.Conn) { _ = guest.Close() }, nil},
		{"frame of 64 KiB + 1", func(_ *kern, guest net.Conn) {
			_, _ = guest.Write([]byte{wire.Version, FrameType, 0, 1, 0, 1})
		}, wire.ErrTooLarge},
		{"wire header claiming 4 GiB", func(_ *kern, guest net.Conn) {
			_, _ = guest.Write([]byte{wire.Version, FrameType, 0xff, 0xff, 0xff, 0xff})
		}, wire.ErrTooLarge},
		{"another version", func(_ *kern, guest net.Conn) { _, _ = guest.Write([]byte{wire.Version + 1}) }, wire.ErrVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			before := openFDs(t)
			s, err := Open(fx.export, testLimit)
			if err != nil {
				t.Fatal(err)
			}
			host, guest := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- s.Serve(host) }()
			k := &kern{t: t, c: wire.New(guest, 5*time.Second)}
			k.ok(reqInit(7, 37))
			d := le.Uint64(k.ok(reqLookup(1, "d")))
			k.ok(reqOpendir(d))
			a := le.Uint64(k.ok(reqLookup(1, "a.txt")))
			k.ok(reqOpen(a, unix.O_RDONLY))
			if openFDs(t) != before+4 { // the export, d, d's open handle, a.txt's
				t.Fatalf("%d descriptors, want %d", openFDs(t), before+4)
			}
			tc.end(k, guest)
			select {
			case err := <-done:
				if err = ended(err); !errors.Is(err, tc.want) {
					t.Errorf("Serve: %v, want %v", err, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return")
			}
			_ = guest.Close()
			if after := openFDs(t); after != before {
				t.Errorf("%d descriptors open, %d before", after, before)
			}
			fx.checkSecret(t)
		})
	}
}

// TestOpen refuses what is not a directory reached without following a link.
func TestOpen(t *testing.T) {
	fx := newFixture(t)
	for _, tc := range []struct {
		name, path string
		ok         bool
	}{
		{"directory", fx.export, true},
		{"symlink to a directory", filepath.Join(fx.export, "up"), false},
		{"file", filepath.Join(fx.export, "a.txt"), false},
		{"missing", filepath.Join(fx.export, "missing"), false},
	} {
		s, err := Open(tc.path, testLimit)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if s != nil {
			s.Close()
		}
	}
}

// TestGrowthCap is I10 on the export: files may grow by the cap in all, and the WRITE or
// SETATTR that would take them past it is ENOSPC and does nothing, whether the growth is
// bytes or a hole. Writes in place are free; shrinking gives nothing back.
func TestGrowthCap(t *testing.T) {
	fx := newFixture(t)
	const limit = 100_000
	k, stop := startCapped(t, fx.export, limit)
	defer func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	}()
	k.ok(reqInit(7, 37))
	var fill, two, fhFill, fhTwo uint64
	for _, tc := range []struct {
		name string
		req  func() []byte
		want syscall.Errno
	}{
		{"create fill", func() []byte { return reqCreate(1, "fill", unix.O_RDWR, 0o644) }, 0},
		{"write 60000 under the cap", func() []byte { return reqWrite(fill, fhFill, 0, make([]byte, 60000)) }, 0},
		{"write 40000 to the cap", func() []byte { return reqWrite(fill, fhFill, 60000, make([]byte, 40000)) }, 0},
		{"write 1 past the cap", func() []byte { return reqWrite(fill, fhFill, limit, []byte{1}) }, syscall.ENOSPC},
		{"overwrite in place", func() []byte { return reqWrite(fill, fhFill, 0, make([]byte, 1000)) }, 0},
		{"truncate past the cap", func() []byte { return reqSetattr(fill, fattrFh|fattrSize, fhFill, limit+1, 0) }, syscall.ENOSPC},
		{"truncate shorter", func() []byte { return reqSetattr(fill, fattrFh|fattrSize, fhFill, 50000, 0) }, 0},
		{"regrow after shrinking", func() []byte { return reqWrite(fill, fhFill, 50000, []byte{1}) }, syscall.ENOSPC},
		{"create two", func() []byte { return reqCreate(1, "two", unix.O_RDWR, 0o644) }, 0},
		{"write 1 byte at 1 TiB", func() []byte { return reqWrite(two, fhTwo, 1<<40, []byte{1}) }, syscall.ENOSPC},
		{"truncate two to 2^62 by name", func() []byte { return reqSetattr(two, fattrSize, 0, 1<<62, 0) }, syscall.ENOSPC},
	} {
		e, body := k.call(tc.req())
		if e != tc.want {
			t.Fatalf("%s: %v, want %v", tc.name, e, tc.want)
		}
		switch tc.name {
		case "create fill":
			fill, fhFill = le.Uint64(body), le.Uint64(body[entryOutLen:])
		case "create two":
			two, fhTwo = le.Uint64(body), le.Uint64(body[entryOutLen:])
		}
	}
	for name, want := range map[string]int64{"fill": 50000, "two": 0} {
		st, err := os.Stat(filepath.Join(fx.export, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != want {
			t.Errorf("%s is %d bytes on the host, want %d", name, st.Size(), want)
		}
	}
}
