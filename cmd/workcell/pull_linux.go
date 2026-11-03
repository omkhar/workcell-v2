// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// stallLimit is how long the host waits for the guest's next frame of a tree (I12).
const stallLimit = time.Minute

// pull is `workcell pull [dir]`: it brings the work tree of the newest session run in the
// current directory into dir, which is the current directory by default. It exits 0 when
// the tree is in, 1 with one line on stderr when the tree was refused or could not be read.
func pull(args []string, stderr io.Writer) int {
	if len(args) > 1 || len(args) == 1 && strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: workcell pull [dir]\n  writes the work tree of the newest session run here into dir (default: here);\n  what the guest deleted stays, and workcell diff shows it")
		return 2
	}
	dest := "."
	if len(args) == 1 {
		dest = args[0]
	}
	root, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(stderr, "workcell pull:", err)
		return 1
	}
	defer unix.Close(root)
	code, err := fetch(func(m *manifest, data source) error { return write(root, m, data) })
	if err != nil {
		fmt.Fprintln(stderr, "workcell pull:", err)
		return 1
	}
	return code
}

// diff is `workcell diff`: one line per difference between the work tree of the newest
// session run in the current directory and the directory itself. It exits 0 when nothing
// differs, 1 when something does and 2 when it could not tell, as diff(1) does.
func diff(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: workcell diff\n  lists what the newest session run here changed: A added, M modified, D deleted")
		return 2
	}
	root, err := unix.Open(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(stderr, "workcell diff:", err)
		return 2
	}
	defer unix.Close(root)
	differs := false
	code, err := fetch(func(m *manifest, data source) (err error) {
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

// fetch boots the newest session of the current directory, asks its init for the work tree
// and gives use the judged manifest and the files' bytes. The whole tree must follow, and
// the Exit after it, or the result is an error. SIGINT and SIGTERM end the VM, as in run,
// and give a code of 128 plus the signal.
func fetch(use func(*manifest, source) error) (int, error) {
	dir, err := dataDir()
	var a artifacts
	if err == nil {
		a, err = findArtifacts(dir)
	}
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
	image := filepath.Join(session, "workspace.ext4")
	st, err := os.Stat(image)
	if errors.Is(err, fs.ErrNotExist) { // a mount session has no image: its work is in the directory itself (ADR-005)
		return 0, fmt.Errorf("the newest session run in %s was a mount session (--mount): the agent wrote to the directory itself, so there is nothing to bring back", cwd)
	}
	if err != nil {
		return 0, err
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	b, code, err := boot(a, defaults(), sigs, image, "")
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
	m, err := p.manifest(bounds{entries: guest.MaxEntries, names: guest.MaxNames, bytes: st.Size()})
	if err == nil {
		err = use(m, p.data)
	}
	if err == nil {
		err = p.end()
	}
	var sig interrupted
	if errors.As(err, &sig) {
		return 128 + int(sig), nil
	}
	return 0, err
}

// newest is the directory of the newest session whose repo file names dir: the session
// directories sort by time.
func newest(sessions, dir string) (string, error) {
	ents, err := os.ReadDir(sessions)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	for i := len(ents) - 1; i >= 0; i-- {
		b, err := os.ReadFile(filepath.Join(sessions, ents[i].Name(), "repo"))
		if err == nil && strings.TrimSuffix(string(b), "\n") == dir {
			return filepath.Join(sessions, ents[i].Name()), nil
		}
	}
	return "", fmt.Errorf("no session has run in %s: workcell run one first", dir)
}

type framed struct {
	f   wire.Frame
	err error
}

// pulled is the init's answer as it arrives. The frames come on a goroutine, so that a
// signal, or a guest that stalls, ends the wait for one (I12).
type pulled struct {
	frames <-chan framed
	sigs   <-chan os.Signal
	rest   []byte // the unread bytes of the last Data frame
}

// interrupted is the error of a signal that ended the wait for the guest.
type interrupted syscall.Signal

func (s interrupted) Error() string { return "interrupted by " + syscall.Signal(s).String() }

func (p *pulled) frame() (wire.Frame, error) {
	select {
	case fr := <-p.frames:
		if fr.err != nil {
			return wire.Frame{}, fmt.Errorf("guest channel: %w", fr.err)
		}
		return fr.f, nil
	case s := <-p.sigs:
		return wire.Frame{}, interrupted(s.(syscall.Signal))
	case <-time.After(stallLimit):
		return wire.Frame{}, fmt.Errorf("no frame from the guest in %s", stallLimit)
	}
}

// manifest reads the entries up to the empty one that ends them, judging each as it arrives.
func (p *pulled) manifest(limit bounds) (*manifest, error) {
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

// odd is the error for a frame that does not belong where it came: an Exit there says the
// init stopped, with its reason when it has one.
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
	if err != nil {
		return err
	}
	switch f.Type {
	case guest.TypeData:
		return long
	case guest.TypeExit:
		e, err := guest.DecodeExit(f.Payload)
		if err != nil {
			return err
		}
		if e.Err == "" && e.Code == 0 && e.Signal == 0 {
			return nil
		}
		return fmt.Errorf("the guest could not read its tree: %q", e.Err)
	}
	return p.odd(f)
}

// write puts the tree into the directory open as root, in manifest order, so that each
// directory is there before what it holds. Every path is the guest's (R6): it is resolved
// beneath root by openat2 without following any symlink, and what is there already is
// kept when both are directories, removed first otherwise, and never written through. A
// directory that is not empty is not removed: that is refused, with the error of unlinkat.
// What is on the host and not in the tree is left alone.
func write(root int, m *manifest, data source) error {
	for _, e := range m.entries {
		if err := put(root, e, data); err != nil {
			return fmt.Errorf("%s: %w", shown(e.Path), err)
		}
	}
	return nil
}

// beneath opens the directory rel beneath root, or root itself for "", never through a symlink.
func beneath(root int, rel string) (int, error) {
	if rel == "" {
		rel = "."
	}
	return unix.Openat2(root, rel, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
}

// split is the directory and the name of a path.
func split(p string) (dir, name string) {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

func put(root int, e guest.Entry, data source) error {
	dir, name := split(e.Path)
	pfd, err := beneath(root, dir)
	if err != nil {
		return fmt.Errorf("open its directory: %w", err)
	}
	defer unix.Close(pfd)
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
	switch e.Kind {
	case guest.KindDir:
		return unix.Mkdirat(pfd, name, 0o755)
	case guest.KindLink:
		return unix.Symlinkat(e.Target, pfd, name)
	}
	mode := uint32(0o644)
	if e.Exec {
		mode = 0o755
	}
	fd, err := unix.Openat2(pfd, name, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC, Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), e.Path)
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

// compare writes one line per difference between the tree and the directory open as root:
// A for what the guest has and the host has not, M for what differs in kind, executable
// bit, link target or bytes, D for what the host has and the guest has not. The host's
// directory is walked by the rules the init walked the guest's. The bytes are compared
// here, file by file as they arrive; nothing the guest says about sameness counts.
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

// sameBytes takes e.Size bytes of the stream and, when check holds, compares them with the
// host's file at e.Path, which is as long: it reports whether they are the same.
func sameBytes(root int, e guest.Entry, data source, check bool) (bool, error) {
	var f *os.File
	if check {
		fd, err := unix.Openat2(root, e.Path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		if err != nil {
			return false, fmt.Errorf("%s: %w", shown(e.Path), err)
		}
		f = os.NewFile(uintptr(fd), e.Path)
		defer f.Close()
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
