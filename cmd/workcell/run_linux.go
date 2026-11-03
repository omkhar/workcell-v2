// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/relay"
	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/vmm/firecracker"
	"github.com/omkhar/workcell/v2/internal/wire"
	"github.com/omkhar/workcell/v2/internal/workspace"
	"golang.org/x/sys/unix"
)

const (
	bootLimit  = 20 * time.Second // from Start to the guest's connection
	frameLimit = 5 * time.Second  // one frame, once it has begun
	path       = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// run is `workcell run [--cpus N] [--memory SIZE] [--disk SIZE] [--] <cmd> [args...]`: it boots a guest with a copy of
// the current directory in it, runs the command there and exits as the command did. This process is the session's supervisor (A9): it owns the VM
// and the channel, and the VM dies with it.
func run(args []string, stderr io.Writer) int {
	caps, args, ok := parseRun(args, stderr)
	if !ok {
		return 2
	}
	dir, err := dataDir()
	var a artifacts
	if err == nil {
		a, err = findArtifacts(dir)
	}
	code := 0
	if err == nil {
		code, err = session(args, caps, a)
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell:", err)
		if code == 0 {
			code = 125 // the session itself failed, not the command
		}
	}
	return code
}

// session boots a guest and runs argv in it. It returns the command's exit code. A nonzero
// code with an error means the command could not run; an error alone means the session failed.
func session(argv []string, caps limits, a artifacts) (int, error) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
	defer signal.Stop(sigs)
	cwd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	image, err := export(a, caps, cwd)
	if err != nil {
		return 0, err
	}
	b, code, err := boot(a, caps, sigs, image)
	if b == nil {
		return code, err
	}
	defer b.close()
	raw := b.conn

	req := guest.Exec{Argv: argv, Env: []string{path, "HOME=/root", "LANG=C.UTF-8"}, Dir: "/workspace"}
	restore, tty := rawMode(unix.Stdin)
	if tty {
		defer restore()
		req.PTY = true
		req.Rows, req.Cols = windowSize(unix.Stdin)
		if term := os.Getenv("TERM"); term != "" {
			req.Env = append(req.Env, "TERM="+term)
		}
	}
	c := wire.New(raw, frameLimit)
	if err := c.WriteFrame(wire.Frame{Type: guest.TypeExec, Payload: guest.EncodeExec(req)}); err != nil {
		return 0, err
	}
	window := make(chan struct{}, guest.StdinWindow) // one token per Stdin frame the init has not acknowledged
	done := make(chan result, 1)
	go output(c, window, done)
	chunks := make(chan []byte)
	go readStdin(window, chunks, tty)

	signalled := false
	for {
		var err error
		select {
		case b := <-chunks:
			err = c.WriteFrame(wire.Frame{Type: guest.TypeStdin, Payload: b})
		case s := <-sigs:
			switch {
			case s == syscall.SIGWINCH:
				if tty {
					rows, cols := windowSize(unix.Stdin)
					err = c.WriteFrame(wire.Frame{Type: guest.TypeResize, Payload: guest.EncodeResize(guest.Resize{Rows: rows, Cols: cols})})
				}
			case signalled: // the command ignored the first one: stop waiting for it
				return 128 + int(s.(syscall.Signal)), nil
			default:
				signalled = true
				err = c.WriteFrame(wire.Frame{Type: guest.TypeSignal, Payload: guest.EncodeSignal(int(s.(syscall.Signal)))})
			}
		case r := <-done:
			return r.code, r.err
		}
		if err != nil {
			return 0, fmt.Errorf("guest channel: %w", err)
		}
	}
}

// booted is a guest whose init has connected. close ends the VM and removes its files; it
// returns only once the VMM process is gone, so the next boot may reuse the CID.
type booted struct {
	conn  net.Conn
	took  time.Duration // from just before the VMM started to the guest's connection
	close func()
}

// sessionTime names a session directory by when it began, so that the names sort by time;
// a random suffix keeps two that began in the same instant apart.
const sessionTime = "20060102T150405.000000000Z"

// export copies the directory repo into a new session, <data>/sessions/<id>/: the image the
// guest gets as /workspace, and a file repo naming the directory, so that diff and pull find
// the newest session of a directory later. The image lives in the data directory, not under
// TMPDIR, because a reflink only works within one filesystem and the data directory shares
// the home filesystem with most repositories. It is as big as the repository plus the room
// the guest may write, which is --disk or 1 GiB (I10). It stays when the session ends, for
// diff and pull; rm removes it (I7).
func export(a artifacts, caps limits, repo string) (string, error) {
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", err
	}
	dir := filepath.Join(a.dir, "sessions", time.Now().UTC().Format(sessionTime)+"-"+hex.EncodeToString(r[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	free := int64(1 << 30)
	if caps.DiskMiB > 0 {
		free = int64(caps.DiskMiB) << 20
	}
	image := filepath.Join(dir, "workspace.ext4")
	err := os.WriteFile(filepath.Join(dir, "repo"), []byte(repo+"\n"), 0o600)
	if err == nil {
		_, err = workspace.Export(context.Background(), repo, image, free)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("copy %s for the guest: %w", repo, err)
	}
	return image, nil
}

// boot starts a guest and waits for its init to dial in. The ext4 image at image is the
// guest's /workspace, unless image is empty. close ends the VM and removes its files; the
// image stays. A nil result means the session goes no further: code and err say how it
// ended (see accept).
func boot(a artifacts, caps limits, sigs <-chan os.Signal, image string) (*booted, int, error) {
	dir, err := os.MkdirTemp("", "wc") // short: a unix socket path has 108 bytes
	if err != nil {
		return nil, 0, err
	}
	cmdline := caps.cmdline()
	if image != "" {
		cmdline += " workcell.workspace=/dev/vdb"
	}
	console := &tail{}
	// No allowlist yet, so no TCP port is relayed: the guest relays UDP 53 alone (U-303).
	m := firecracker.New(vmm.Config{Binary: a.firecracker, Kernel: a.kernel, Initrd: a.initrd, Image: a.image,
		Workspace: image, Cmdline: cmdline + " " + portsArg(nil), CPUs: caps.CPUs, MemoryMiB: caps.MemoryMiB, CID: 3, Console: console, Dir: dir})
	closeAll := func() { m.Close(); os.RemoveAll(dir) } // kills the VM on every path out
	ln, err := m.Listen(guest.Port)
	if err != nil {
		closeAll()
		return nil, 0, err
	}
	streams, err := m.Listen(relay.Port)
	if err != nil {
		closeAll()
		return nil, 0, err
	}
	go serveRelay(streams) // until Close closes the listener
	start := time.Now()
	if err := m.Start(context.Background()); err != nil {
		closeAll()
		return nil, 0, err
	}
	raw, code, err := accept(once{ln}, m, sigs, console)
	if raw == nil {
		closeAll()
		return nil, code, err
	}
	return &booted{conn: raw, took: time.Since(start), close: func() { raw.Close(); closeAll() }}, 0, nil
}

// once is the channel's listener: it takes exactly one connection, the init's, then closes,
// which unlinks the socket, so Firecracker refuses every later guest connection to the port
// instead of the host kernel queuing each one, and whatever the guest writes on it, for the
// whole session (I12).
type once struct{ net.Listener }

func (l once) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		_ = l.Listener.Close()
	}
	return c, err
}

// accept waits for the guest to dial in. A guest that never does is reported with the end
// of its console. A non-nil conn means the session goes on; otherwise code and err are the result.
func accept(ln net.Listener, m *firecracker.Machine, sigs <-chan os.Signal, console *tail) (net.Conn, int, error) {
	type accepted struct {
		c   net.Conn
		err error
	}
	got, died := make(chan accepted, 1), make(chan error, 1)
	go func() { c, err := ln.Accept(); got <- accepted{c, err} }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { died <- m.Wait(ctx) }()
	why := ""
	select {
	case r := <-got:
		if r.err == nil {
			return r.c, 0, nil
		}
		why = r.err.Error()
	case err := <-died:
		why = fmt.Sprint("the VMM ended: ", err)
	case <-time.After(bootLimit):
		why = "no connection from the guest in " + bootLimit.String()
	case s := <-sigs:
		return nil, 128 + int(s.(syscall.Signal)), nil
	}
	return nil, 0, fmt.Errorf("guest did not boot (%s)\n%s", why, lastLines(console.bytes(), 10))
}

// result is how the session ended: the command's code, or an error.
type result struct {
	code int
	err  error
}

// output passes the guest's output to the host's stdout and stderr and gives back a window
// slot for every Ack, until the command's Exit or an error ends the session. It decodes
// bytes the guest chose, so every payload is checked.
func output(c *wire.Conn, window chan struct{}, done chan<- result) {
	for {
		f, err := c.ReadFrame()
		if err != nil {
			done <- result{err: fmt.Errorf("guest channel: %w", err)}
			return
		}
		switch f.Type {
		case guest.TypeStdout:
			_, _ = os.Stdout.Write(f.Payload)
		case guest.TypeStderr:
			_, _ = os.Stderr.Write(f.Payload)
		case guest.TypeAck:
			if _, err := guest.DecodeAck(f.Payload); err != nil {
				done <- result{err: err}
				return
			}
			select {
			case <-window:
			default: // an Ack nobody was waiting for: harmless
			}
		case guest.TypeExit:
			e, err := guest.DecodeExit(f.Payload)
			switch {
			case err != nil:
				done <- result{err: err}
			case e.Err != "":
				done <- result{code: 126, err: fmt.Errorf("the command could not run: %q", e.Err)}
			case e.Signal != 0:
				done <- result{code: 128 + e.Signal}
			default:
				done <- result{code: e.Code}
			}
			return
		default:
			done <- result{err: fmt.Errorf("frame type %d from the guest", f.Type)}
			return
		}
	}
}

// readStdin feeds host input to chunks, holding a window slot for each frame so that at most
// guest.StdinWindow are unacknowledged. At the end of input a pipe gets one empty frame,
// which closes the command's stdin; a terminal sends its end-of-file as a byte.
func readStdin(window chan struct{}, chunks chan<- []byte, tty bool) {
	buf := make([]byte, guest.MaxStdin)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			window <- struct{}{}
			chunks <- slices.Clone(buf[:n])
		}
		if err != nil {
			if !tty {
				window <- struct{}{}
				chunks <- nil
			}
			return
		}
	}
}

// tail keeps the end of the guest's console: enough to say why a boot failed, and bounded
// however much the guest writes (I10).
type tail struct {
	mu sync.Mutex
	b  []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tail) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.b)
}

// lastLines is the last n lines of console output, safe to print on a terminal: the guest
// chose these bytes, so anything but printable ASCII becomes '?', and carriage returns go.
func lastLines(b []byte, n int) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r == '\r':
			return -1
		case r == '\n' || r >= ' ' && r < 0x7f:
			return r
		}
		return '?'
	}, string(b))
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
