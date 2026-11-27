// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// stallLimit is how long the host waits for the guest's next frame of a tree (I12).
const stallLimit = time.Minute

// pull is `workcell pull [dir]`: it brings the work tree of the newest session run in the current directory into dir, which is the current directory by default. It exits 0 when the tree is in, 1 with one line on stderr when the tree was refused or could not be read.
func pull(args []string, stderr io.Writer) int {
	if len(args) > 1 || len(args) == 1 && strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: workcell pull [dir]\n  writes the work tree of the newest session run here into dir (default: here);\n  what the guest deleted stays, and workcell diff shows it")
		return 2
	}
	dest := "."
	if len(args) == 1 {
		dest = args[0]
	}
	code, err := fetch(dest, write)
	if err != nil {
		fmt.Fprintln(stderr, "workcell pull:", err)
		return 1
	}
	return code
}

// diff is `workcell diff`: one line per difference between the work tree of the newest session run in the current directory and the directory itself. It exits 0 when nothing differs, 1 when something does and 2 when it could not tell, as diff(1) does.
func diff(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: workcell diff\n  lists what the newest session run here changed: A added, M modified, D deleted")
		return 2
	}
	differs := false
	code, err := fetch(".", func(root int, m *manifest, data source) (err error) {
		differs, err = compare(root, m, data, os.Stdout)
		return err
	})
	if err != nil {
		fmt.Fprintln(stderr, "workcell diff:", err)
		return 2
	}
	if code == 0 && differs {
		return 1
	}
	return code
}

// source hands out the next bytes of the files, at most n and at least one, in manifest order.
type source func(n int) ([]byte, error)

// fetch boots the newest session of the current directory, asks its init for the work tree and gives use the directory dest open as root, the judged manifest and the files' bytes. A dest that holds workcell's own directory is refused first (holds), and so is one whose name names another directory after the judgement than the one opened (named, C61). The whole tree must follow, and the Exit after it, or the result is an error. SIGINT and SIGTERM end the VM, as in run, and give a code of 128 plus the signal.
func fetch(dest string, use func(int, *manifest, source) error) (int, error) {
	root, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(root)
	if err := holds(dest); err != nil {
		return 0, err
	}
	if within(dest, os.TempDir()) { // the VMM's sockets, of a session running now or of one begun during the pull, would lie under it, for the guest's tree to swap for a link to any host socket of the operator's (I1, I4, I7)
		return 0, fmt.Errorf("%q holds the temp directory %s, where the VMM's sockets lie, which no pull may write over: set TMPDIR elsewhere", dest, os.TempDir())
	}
	if err := named(root, dest); err != nil {
		return 0, err
	}
	a, err := loadArtifacts()
	if err != nil {
		return 0, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	session, err := newest(filepath.Join(a.dir, "sessions"), cwd)
	if err != nil {
		return 0, err
	}
	lock, err := lockSession(session, unix.LOCK_EX|unix.LOCK_NB) // held for the pull's whole life, as a run holds its own: ls reads the session as running, rm refuses it and stop ends this process; a run that still holds it is refused here, before any boot (C63)
	if err != nil {
		return 0, err
	}
	defer lock.Close()
	image := filepath.Join(session, "workspace.ext4")
	st, err := os.Stat(image)
	if errors.Is(err, fs.ErrNotExist) { // a mount session has no image, its work being in the directory itself (ADR-005), and neither has a start that failed before its copy was made (C83)
		return 0, fmt.Errorf("the newest session run in %q, %s, has no copy to bring back: it ran with --mount, so the agent wrote to the directory itself, or it failed before its copy was made (workcell rm %s drops it)", cwd, filepath.Base(session), filepath.Base(session))
	}
	rec, rerr := os.ReadFile(filepath.Join(session, "inodes")) // how many inodes the export gave the image, before the guest ran
	inodes, perr := strconv.ParseInt(string(rec), 10, 64)
	if err = cmp.Or(err, rerr, perr); err != nil {
		return 0, err
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	b, code, err := boot(a, defaults(), sigs, session, nil, image, "", nil, nil) // no network: nothing to pull from but the image
	if b == nil {
		return code, err
	}
	defer b.close()
	c := wire.New(b.conn, frameLimit)
	if err := c.WriteFrame(wire.Frame{Type: guest.TypePull}); err != nil {
		return 0, fmt.Errorf("guest channel: %w", err)
	}
	frames := make(chan framed)
	go func() {
		for {
			f, err := c.ReadFrame()
			frames <- framed{f, err}
			if err != nil {
				return
			}
		}
	}()
	p := &pulled{frames: frames, sigs: sigs}
	m, err := p.manifest(st.Size() + inodes*block) // what the image holds: its bytes, and a block for each entry an inode could be
	if err == nil {
		err = use(root, m, p.data)
	}
	if err == nil {
		err = p.end()
	}
	if p.sig != 0 {
		return 128 + int(p.sig), nil
	}
	return 0, err
}

// named is the error for a directory, open as dir (unix.AT_FDCWD for this process's own), that name does not name now. holds and the TMPDIR rule judge the
// name; a guest that renamed the directory away and put a link under its name in between would have had another directory judged than the one taken (C61).
func named(dir int, name string) error {
	var opened, now unix.Stat_t
	err := cmp.Or(unix.Fstatat(dir, ".", &opened, 0), unix.Stat(name, &now))
	if err != nil || opened.Dev != now.Dev || opened.Ino != now.Ino { // a name gone for the instant is refused with the rest
		return fmt.Errorf("%q no longer names the directory it did a moment ago: it was renamed or replaced", name)
	}
	return nil
}

// newest is the directory of the newest session whose repo file names dir: session directories sort by time.
func newest(sessions, dir string) (string, error) {
	l, err := list(sessions)
	if err != nil {
		return "", err
	}
	for i := len(l) - 1; i >= 0; i-- {
		if l[i].repo == dir {
			return filepath.Join(sessions, l[i].id), nil
		}
	}
	return "", fmt.Errorf("no session has run in %q: workcell run one first", dir)
}

type framed struct {
	f   wire.Frame
	err error
}

// pulled is the init's answer as it arrives, on a goroutine so that a signal or a stalled guest ends a wait (I12).
type pulled struct {
	frames <-chan framed
	sigs   <-chan os.Signal
	rest   []byte         // the unread bytes of the last Data frame
	sig    syscall.Signal // the signal that ended the wait for the guest, if one did
}

func (p *pulled) frame() (wire.Frame, error) {
	select {
	case fr := <-p.frames:
		if fr.err != nil {
			return wire.Frame{}, fmt.Errorf("guest channel: %w", fr.err)
		}
		return fr.f, nil
	case s := <-p.sigs:
		p.sig = s.(syscall.Signal)
		return wire.Frame{}, fmt.Errorf("interrupted by %s", s)
	case <-time.After(stallLimit):
		return wire.Frame{}, fmt.Errorf("no frame from the guest in %s", stallLimit)
	}
}

// manifest reads the entries up to the empty one that ends them, judging each as it arrives.
func (p *pulled) manifest(limit int64) (*manifest, error) {
	m := &manifest{limit: limit}
	for {
		f, err := p.frame()
		if err != nil {
			return nil, err
		}
		if f.Type != guest.TypeEntry {
			return nil, p.odd(f)
		}
		if len(f.Payload) == 0 {
			return m, nil
		}
		e, err := guest.DecodeEntry(f.Payload)
		if err == nil {
			err = m.add(e)
		}
		if err != nil {
			return nil, fmt.Errorf("refused the guest's tree: %w", err)
		}
	}
}

// odd is the error for a frame out of place: an Exit there says the init stopped, with its reason if any.
func (p *pulled) odd(f wire.Frame) error {
	if f.Type != guest.TypeExit {
		return fmt.Errorf("frame type %d from the guest", f.Type)
	}
	e, err := guest.DecodeExit(f.Payload)
	if err != nil {
		return err
	}
	if e.Err != "" {
		return fmt.Errorf("the guest could not read its tree: %q", e.Err)
	}
	return errors.New("the guest ended its tree early")
}

// data is a source: the files' bytes, from the Data frames in order.
func (p *pulled) data(n int) ([]byte, error) {
	for len(p.rest) == 0 {
		f, err := p.frame()
		if err != nil {
			return nil, err
		}
		if f.Type != guest.TypeData {
			return nil, p.odd(f)
		}
		if len(f.Payload) == 0 {
			return nil, errors.New("an empty data frame from the guest")
		}
		p.rest = f.Payload
	}
	n = min(n, len(p.rest))
	b := p.rest[:n]
	p.rest = p.rest[n:]
	return b, nil
}

// end takes the Exit that follows the last byte: the tree is whole only then.
func (p *pulled) end() error {
	long := errors.New("the guest sent more bytes than its tree holds")
	if len(p.rest) > 0 {
		return long
	}
	f, err := p.frame()
	if err != nil || f.Type == guest.TypeData {
		return cmp.Or(err, long)
	}
	if e, err := guest.DecodeExit(f.Payload); f.Type == guest.TypeExit && err == nil && e == (guest.Exit{}) {
		return nil
	}
	return p.odd(f)
}

// write puts the tree into the directory open as root, in manifest order, so that each directory is there before what it holds. Every path is the guest's (R6): it is opened beneath root one component at a time, through no symlink (dirBeneath, createBeneath), and no component may be its directory's .git (isGit, I8). What is there already is kept when both are directories, removed first otherwise and never written through. A directory that is not empty is not removed: that is refused, with the error of unlinkat. What is on the host and not in the tree is left alone, and a directory with no .git before the pull has none after.
func write(root int, m *manifest, data source) error {
	for _, e := range m.entries {
		if err := put(root, e, data); err != nil {
			return fmt.Errorf("%s: %w", shown(e.Path), err)
		}
	}
	return nil
}

// isGit reports whether name, in the directory open as dir, is what ".git" names there, however name is spelled: the same device and inode, both read now, never remembered (C44: HFS+ ignores some code points).
func isGit(dir int, name string) bool {
	var git, st unix.Stat_t
	return unix.Fstatat(dir, ".git", &git, unix.AT_SYMLINK_NOFOLLOW) == nil && unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == git.Dev && st.Ino == git.Ino
}

func put(root int, e guest.Entry, data source) error {
	refused := errors.New("a component is the .git of its directory")
	pfd, err := dirBeneath(root, ".")
	name, rest, deeper := strings.Cut(e.Path, "/")
	for ; err == nil && deeper && !isGit(pfd, name); name, rest, deeper = strings.Cut(rest, "/") {
		up := pfd
		pfd, err = dirBeneath(up, name)
		unix.Close(up)
	}
	if err != nil {
		return fmt.Errorf("open its directory: %w", err)
	}
	defer unix.Close(pfd)
	if isGit(pfd, name) { // the last name, or the directory at which the walk stopped
		return refused
	}
	var st unix.Stat_t
	if unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
		isDir := uint32(st.Mode)&unix.S_IFMT == unix.S_IFDIR
		if isDir && e.Kind == guest.KindDir {
			return nil
		}
		flags := 0
		if isDir {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(pfd, name, flags); err != nil {
			return fmt.Errorf("remove what is there: %w", err)
		}
	}
	mode, fd, rm := map[bool]uint32{false: 0o644, true: 0o755}[e.Exec], -1, 0
	switch e.Kind {
	case guest.KindDir:
		err, rm = unix.Mkdirat(pfd, name, 0o755), unix.AT_REMOVEDIR
	case guest.KindLink:
		err = unix.Symlinkat(e.Target, pfd, name)
	default:
		fd, err = createBeneath(pfd, name, mode)
	}
	if err == nil && isGit(pfd, name) { // no .git was here, and this name has just made one: take it away again
		unix.Close(fd) // -1 unless a file was made
		unix.Unlinkat(pfd, name, rm)
		return refused
	}
	if err != nil || fd < 0 {
		return err
	}
	f := os.NewFile(uintptr(fd), shown(e.Path))
	defer f.Close()
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	for left := e.Size; left > 0; {
		b, err := data(int(min(left, wire.MaxPayload)))
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			return err
		}
		left -= int64(len(b))
	}
	return nil
}

// compare writes one line per difference between the tree and the directory open as root: A for what only the guest has, M for what differs in kind, executable bit, link target or bytes, D for what only the host has. The host's directory is walked by the rules the init walked the guest's. The bytes are compared here, file by file as they arrive; nothing the guest says about sameness counts.
func compare(root int, m *manifest, data source, out io.Writer) (differs bool, err error) {
	wfd, err := unix.Dup(root)
	if err != nil {
		return false, err
	}
	host := map[string]guest.Entry{}
	if err := guest.Walk(wfd, func(e guest.Entry) error { host[e.Path] = e; return nil }); err != nil {
		return false, err
	}
	for _, e := range m.entries {
		h, there := host[e.Path]
		delete(host, e.Path)
		same := there && h == e
		if e.Kind == guest.KindFile {
			if same, err = sameBytes(root, e, data, same); err != nil {
				return false, err
			}
		}
		switch {
		case !there:
			fmt.Fprintln(out, "A", shown(e.Path))
		case !same:
			fmt.Fprintln(out, "M", shown(e.Path))
		default:
			continue
		}
		differs = true
	}
	for _, p := range slices.Sorted(maps.Keys(host)) {
		fmt.Fprintln(out, "D", shown(p))
		differs = true
	}
	return differs, nil
}

// sameBytes takes e.Size bytes of the stream and, when check holds, compares them with the host's file at e.Path, which is as long: it reports whether they are the same.
func sameBytes(root int, e guest.Entry, data source, check bool) (bool, error) {
	var f *os.File
	if check {
		fd, err := fileBeneath(root, e.Path)
		if err != nil {
			return false, fmt.Errorf("%s: %w", shown(e.Path), err)
		}
		f = os.NewFile(uintptr(fd), shown(e.Path))
		defer f.Close()
		var st unix.Stat_t // what took the name since the walk and is not a regular file differs, and is never read: a FIFO with a silent writer would park the read (I12, C87)
		check = unix.Fstat(fd, &st) == nil && uint32(st.Mode)&unix.S_IFMT == unix.S_IFREG
	}
	mine := make([]byte, wire.MaxPayload)
	for left := e.Size; left > 0; {
		b, err := data(int(min(left, wire.MaxPayload)))
		if err != nil {
			return false, err
		}
		left -= int64(len(b))
		if check {
			_, err := io.ReadFull(f, mine[:len(b)])
			check = err == nil && bytes.Equal(mine[:len(b)], b)
		}
	}
	return check, nil
}
