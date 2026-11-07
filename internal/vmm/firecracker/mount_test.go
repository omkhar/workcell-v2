// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/fileserve"
	"github.com/omkhar/workcell/v2/internal/guest"
)

// A command's environment in the guest, and a command that works /workspace until it fails.
const (
	guestPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	busyLoop  = "echo looping; while cat seed.txt >/dev/null; do :; done; exit 9"
)

// TestMount boots cmd/workcell-init with the Debian image in mount mode (ADR-005): /workspace is a directory of this host, served by internal/fileserve over
// the guest's FUSE stream. Each operation of the unit's acceptance is done through the guest's shell and checked on the host tree at once, git copied from this
// host runs `git status` in the mounted repository, and the two ways a host goes away each leave no process waiting on the mount.
func TestMount(t *testing.T) {
	needKVM(t)
	binary, kernel := pinned(t)
	dir := t.TempDir()
	in := inputs{binary: binary, kernel: kernel, image: debianImage(t, dir), cmdline: "root=/dev/vda ro workcell.mount=1",
		initrd: initramfs(t, dir, file{"init", build(t, dir, "github.com/omkhar/workcell/v2/cmd/workcell-init")})}

	t.Run("operations", func(t *testing.T) {
		export := repository(t)
		at := func(name string) string { return filepath.Join(export, name) }
		g, _ := connectMount(t, in, export, uncapped)
		steps := []struct {
			name, script string
			before       func() error // on the host, before the command
			out          string       // what the command must print, or "" for anything
			check        func() error // the host tree, right after the command ended
		}{
			{name: "create and write", script: "printf hello > new.txt", check: func() error { return hostFile(at("new.txt"), "hello") }},
			{name: "read", script: "cat seed.txt sub/inner.txt", out: "seed\ninner\n"},
			{name: "truncate", script: "truncate -s 2 new.txt", check: func() error { return hostFile(at("new.txt"), "he") }},
			{name: "rename", script: "mv new.txt moved.txt", check: func() error {
				return errors.Join(hostFile(at("moved.txt"), "he"), hostGone(at("new.txt")))
			}},
			{name: "symlink", script: "ln -s moved.txt link", check: func() error {
				target, err := os.Readlink(at("link"))
				if err != nil || target != "moved.txt" {
					return fmt.Errorf("link -> %q (%v), want moved.txt", target, err)
				}
				return nil
			}},
			{name: "readdir", script: "ls -la", check: nil},
			{name: "chmod", script: "chmod 755 moved.txt", check: func() error {
				st, err := os.Stat(at("moved.txt"))
				if err != nil || st.Mode().Perm() != 0o755 {
					return fmt.Errorf("mode %v (%v), want 0755", st.Mode(), err)
				}
				return nil
			}},
			{name: "unlink", script: "rm moved.txt link", check: func() error { return errors.Join(hostGone(at("moved.txt")), hostGone(at("link"))) }},
			{name: "a host edit", script: "cat edited.txt", out: "from the host\n",
				before: func() error { return os.WriteFile(at("edited.txt"), []byte("from the host\n"), 0o644) }},
			{name: "git status", script: "./git status"},
		}
		for _, s := range steps {
			if s.before != nil {
				if err := s.before(); err != nil {
					t.Fatal(err)
				}
			}
			out, e := g.sh(s.script)
			if e != (guest.Exit{}) {
				t.Fatalf("%s: %q ended %+v; stdout %q, stderr %q", s.name, s.script, e, out, g.errs.String())
			}
			if s.out != "" && out != s.out {
				t.Fatalf("%s: %q printed %q, want %q", s.name, s.script, out, s.out)
			}
			if s.check != nil {
				if err := s.check(); err != nil {
					t.Fatalf("%s: on the host right after: %v", s.name, err)
				}
			}
			switch s.name {
			case "readdir":
				for _, want := range []string{"link -> moved.txt", " moved.txt\n", " seed.txt\n", " sub\n", " .git\n"} {
					if !strings.Contains(out, want) {
						t.Fatalf("ls -la lacks %q:\n%s", want, out)
					}
				}
			case "git status":
				if !strings.Contains(out, "Untracked files") || !strings.Contains(out, "seed.txt") {
					t.Fatalf("git status in the guest printed %q, stderr %q", out, g.errs.String())
				}
				t.Logf("mount git_status_stdout=%q stderr=%q", out, g.errs.String())
			}
		}
	})

	// The caps of I10 in mount mode, as the escape row mount-disk-flood runs them: one vCPU, so the init has one P, 256 MiB, and 64 MiB of growth. The command is
	// started with /workspace as its directory by a vfork whose child waits on the mount for the init's own copier, so the init must keep a second P (mountFUSE).
	// It takes a payload-sized stdin as the escape loader does, floods the export past the cap, and its exit is reported.
	t.Run("capped", func(t *testing.T) {
		capped := in
		capped.cpus, capped.memoryMiB, capped.cmdline = 1, 256, in.cmdline+" workcell.disk=64"
		export := repository(t)
		g, _ := connectMount(t, capped, export, 64<<20)
		const script = `cat >/tmp/p && chmod 755 /tmp/p && echo stdin=$(wc -c </tmp/p)
truncate -s 4G sparse 2>&1 | grep -o 'No space left on device'
dd if=/dev/zero of=fill bs=1M count=128 2>&1 | grep -o 'No space left on device'
sync && rm -f sparse fill && echo done`
		t0 := time.Now()
		g.exec(guest.Exec{Argv: []string{"/bin/sh", "-c", script, "sh"}, Dir: "/workspace", Env: []string{guestPath, "HOME=/root"}})
		const size = 12 << 20 // about the escape payload: 192 frames of guest.MaxStdin
		for sent := 0; sent < size; sent += guest.MaxStdin {
			g.stdin(make([]byte, guest.MaxStdin))
		}
		g.stdin(nil)
		t.Logf("mount capped stdin_ms=%d", time.Since(t0).Milliseconds())
		e := g.exit()
		t.Logf("mount capped exit_ms=%d", time.Since(t0).Milliseconds())
		want := fmt.Sprintf("stdin=%d\nNo space left on device\nNo space left on device\ndone\n", size)
		if e != (guest.Exit{}) || g.out.String() != want {
			t.Fatalf("under the caps the flood ended %+v and printed %q, want exit 0 and %q; stderr %q", e, g.out.String(), want, g.errs.String())
		}
		if err := errors.Join(hostGone(filepath.Join(export, "sparse")), hostGone(filepath.Join(export, "fill"))); err != nil {
			t.Fatal(err)
		}
	})

	// The file service goes away under a command that is using the mount: the command gets an error, not a wait with no end.
	t.Run("stream-end", func(t *testing.T) {
		g, h := connectMount(t, in, repository(t), uncapped)
		g.exec(guest.Exec{Argv: []string{"sh", "-c", busyLoop}, Dir: "/workspace", Env: []string{guestPath}})
		g.until("looping")
		t0 := time.Now()
		_ = h.stream.Close()
		e := g.exit() // within read's 5 s per frame
		took := time.Since(t0)
		if e != (guest.Exit{Code: 9}) {
			t.Fatalf("after the host's stream ended, the command ended %+v, want exit 9; stderr %q", e, g.errs.String())
		}
		t.Logf("mount stream_end_error_ms=%d stderr=%q serve=%v", took.Milliseconds(), strings.TrimSpace(g.errs.String()), h.wait())
	})

	// The channel ends while the host holds a request of a command without answering, so the command waits in the kernel where no signal reaches it: the init must
	// still get the guest powered off promptly, which takes aborting the mount before killing.
	t.Run("channel-end", func(t *testing.T) {
		g, h := connectMount(t, in, repository(t), uncapped)
		g.exec(guest.Exec{Argv: []string{"sh", "-c", busyLoop}, Dir: "/workspace", Env: []string{guestPath}})
		g.until("looping")
		h.stream.hold()
		time.Sleep(300 * time.Millisecond) // the loop's next request is in the host's hands by now
		t.Logf("mount channel_end_poweroff_ms=%d", g.hangUp("with a command stuck on the mount").Milliseconds())
		h.stream.release()
		g.closed()
	})
}

// sh runs script with the image's shell in /workspace and returns what it printed and how it ended.
func (g *client) sh(script string) (string, guest.Exit) {
	g.t.Helper()
	g.exec(guest.Exec{Argv: []string{"sh", "-c", script}, Dir: "/workspace", Env: []string{guestPath, "HOME=/root"}})
	e := g.exit()
	return g.out.String(), e
}

func hostFile(path, want string) error {
	b, err := os.ReadFile(path)
	if err != nil || string(b) != want {
		return fmt.Errorf("%s holds %q (%v), want %q", path, b, err, want)
	}
	return nil
}

func hostGone(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %v, want gone", path, err)
	}
	return nil
}

// repository is a small tree to export: two files, a repository git init made, and this host's git, which the image lacks, to run in the guest.
func repository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git on this host: %v", err)
	}
	git, err := os.ReadFile(gitPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]struct {
		b    []byte
		mode os.FileMode
	}{"seed.txt": {[]byte("seed\n"), 0o644}, "sub/inner.txt": {[]byte("inner\n"), 0o644}, "git": {git, 0o755}} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), content.b, content.mode); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command(gitPath, "init", "-q", "-b", "main", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	return dir
}

// mountHost is the host side of one mount session: the guest's FUSE stream, served from the export until Serve returns, which wait reports.
type mountHost struct {
	stream *held
	done   chan error
	once   sync.Once
	err    error
}

func (h *mountHost) wait() error {
	h.once.Do(func() { h.err = <-h.done })
	return h.err
}

// uncapped is the export's growth cap where the test is not about it: far more than any writes.
const uncapped = 1 << 30

// connectMount boots a mount-mode guest on export, which may grow by limit bytes, and drives its init.
func connectMount(t *testing.T, in inputs, export string, limit int64) (*client, *mountHost) {
	t.Helper()
	dir := shortDir(t)
	m := in.machine(t, dir, consoleFile(t))
	ln, err := m.Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	files, err := m.Listen(fileserve.Port)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fileserve.Open(export, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	t0 := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, l := range []net.Listener{files, ln} {
		if err := l.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(bootLimit)); err != nil {
			t.Fatal(err)
		}
	}
	fc, err := files.Accept() // the init dials the file service first, then the channel
	if err != nil {
		t.Fatalf("no FUSE stream from the guest within %v: %v", bootLimit, err)
	}
	_ = files.Close()
	h := &mountHost{stream: &held{Conn: fc}, done: make(chan error, 1)}
	t.Cleanup(func() { h.stream.release(); _ = h.stream.Close(); _ = h.wait() })
	go func() { h.done <- srv.Serve(h.stream) }()
	raw, err := ln.Accept()
	if err != nil {
		t.Fatalf("no channel from the guest within %v: %v", bootLimit, err)
	}
	t.Logf("mount boot_ms=%d", time.Since(t0).Milliseconds())
	return newClient(t, m, raw, dir), h
}

// held is a net.Conn whose writes can be held back: the host then has the guest's requests and answers none, as a wedged host would, so a guest process waits
// in the kernel on a reply that never comes, where no signal reaches it.
type held struct {
	net.Conn
	mu   sync.Mutex
	gate chan struct{} // nil: writes pass; else they wait for it to close, then fail
}

func (h *held) hold() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gate == nil {
		h.gate = make(chan struct{})
	}
}

func (h *held) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gate != nil {
		select {
		case <-h.gate:
		default:
			close(h.gate)
		}
	}
}

func (h *held) Write(b []byte) (int, error) {
	h.mu.Lock()
	gate := h.gate
	h.mu.Unlock()
	if gate != nil {
		<-gate
		return 0, net.ErrClosed
	}
	return h.Conn.Write(b)
}
