// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
)

const probe = "/probe" // testdata/probe, next to /init in the initramfs

// TestInit boots cmd/workcell-init as PID 1 of a real guest and drives it over the channel
// with testdata/probe as the command: a PTY with its window size and a resize, pipes with
// stdin and stderr apart, an exit code and a signal reported as such, orphans reaped, and
// the guest gone once the host hangs up while a command still runs.
func TestInit(t *testing.T) {
	needKVM(t)
	binary, kernel := pinned(t)
	dir := t.TempDir()
	in := inputs{binary: binary, kernel: kernel, initrd: initramfs(t, dir,
		file{"init", build(t, dir, "github.com/omkhar/workcell/v2/cmd/workcell-init")},
		file{"probe", build(t, dir, "./testdata/probe")})}

	t.Run("commands", func(t *testing.T) {
		g := connect(t, in)
		g.exec(guest.Exec{Argv: []string{probe, "pty", "7"}, PTY: true, Rows: 24, Cols: 80})
		first := g.until("rows=24 cols=80")
		if !strings.Contains(first, "ppid=1 tty=true") {
			t.Fatalf("with a PTY the probe said %q, want ppid=1 tty=true", first)
		}
		g.send(guest.TypeResize, guest.EncodeResize(guest.Resize{Rows: 30, Cols: 100}))
		g.until("rows=30 cols=100")
		if e := g.exit(); e != (guest.Exit{Code: 7}) {
			t.Fatalf("exit 7 reported as %+v", e)
		}

		g.exec(guest.Exec{Argv: []string{probe, "sleep"}})
		g.until("sleeping")
		g.send(guest.TypeSignal, guest.EncodeSignal(15))
		if e := g.exit(); e != (guest.Exit{Signal: 15}) {
			t.Fatalf("death by SIGTERM reported as %+v", e)
		}

		g.exec(guest.Exec{Argv: []string{"probe", "pipes"}, Env: []string{"PATH=/"}})
		g.send(guest.TypeStdin, []byte("ping\n"))
		g.send(guest.TypeStdin, nil)
		if e := g.exit(); e != (guest.Exit{}) || g.out.String() != "ping\n" || g.errs.String() != "err\n" {
			t.Fatalf("pipes: exit %+v stdout %q stderr %q", e, g.out.String(), g.errs.String())
		}

		g.exec(guest.Exec{Argv: []string{probe, "orphans", "40"}})
		if e := g.exit(); e != (guest.Exit{}) {
			t.Fatalf("orphans: exit %+v", e)
		}
		g.exec(guest.Exec{Argv: []string{probe, "zombies"}})
		if e, out := g.exit(), g.out.String(); e != (guest.Exit{}) || !strings.HasPrefix(out, "zombies=0 ") {
			t.Fatalf("after 40 orphans: exit %+v, %q", e, out)
		}
		t.Logf("init %s", strings.TrimSpace(g.out.String()))

		g.exec(guest.Exec{Argv: []string{"/nope"}})
		if e := g.exit(); e.Err == "" || e.Code != 0 || e.Signal != 0 {
			t.Fatalf("a command that cannot start was reported as %+v", e)
		}
	})

	// A command that never reads its stdin must not stall the init: a signal still ends it.
	t.Run("stdin-flood", func(t *testing.T) {
		g := connect(t, in)
		g.exec(guest.Exec{Argv: []string{probe, "sleep"}})
		g.until("sleeping")
		flood := make([]byte, wire.MaxPayload)
		g.send(guest.TypeStdin, flood)
		g.send(guest.TypeStdin, flood)
		g.send(guest.TypeSignal, guest.EncodeSignal(15))
		if e := g.exit(); e != (guest.Exit{Signal: 15}) {
			t.Fatalf("after two 64 KiB stdin frames, SIGTERM reported as %+v", e)
		}
	})

	// More frames than the init queues, to a command that reads slowly: the window holds the
	// host back, nothing is dropped, and every frame is acknowledged.
	t.Run("stdin-window", func(t *testing.T) {
		g := connect(t, in)
		g.exec(guest.Exec{Argv: []string{probe, "count"}})
		const frames, size = 100, 32 << 10
		for range frames {
			g.stdin(make([]byte, size))
		}
		g.stdin(nil)
		if e := g.exit(); e != (guest.Exit{}) || g.out.String() != fmt.Sprintf("bytes=%d\n", frames*size) || g.acks != g.sent {
			t.Fatalf("%d frames of %d bytes: exit %+v, stdout %q, %d of %d acknowledged", frames, size, e, g.out.String(), g.acks, g.sent)
		}
	})

	t.Run("disconnect", func(t *testing.T) {
		g := connect(t, in)
		g.exec(guest.Exec{Argv: []string{probe, "sleep"}})
		g.until("sleeping")
		pid := g.m.cmd.Process.Pid
		t0 := time.Now()
		_ = g.raw.Close()
		ctx, cancel := context.WithTimeout(context.Background(), bootLimit)
		defer cancel()
		if err := g.m.Wait(ctx); err != nil {
			t.Fatalf("Wait after the host hung up on a running command: %v", err)
		}
		if !gone(pid) {
			t.Fatalf("firecracker pid %d is still there", pid)
		}
		t.Logf("init disconnect_poweroff_ms=%d", time.Since(t0).Milliseconds())
		if err := g.m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if left := list(t, g.dir); len(left) != 0 {
			t.Fatalf("after Close, Dir holds %q", left)
		}
	})
}

// client is the host's end of the channel to one guest, with every frame seen kept
// for the log of a failure.
type client struct {
	t          *testing.T
	m          *Machine
	raw        net.Conn
	dir        string
	c          *wire.Conn
	frames     chan wire.Frame
	readErr    chan error
	seen       []string
	out, errs  strings.Builder // of the current command
	sent, acks int             // Stdin frames sent and acknowledged for the current command
}

func connect(t *testing.T, in inputs) *client {
	t.Helper()
	m, raw, dir, bootMS := launch(t, in)
	g := &client{t: t, m: m, raw: raw, dir: dir, c: wire.New(raw, 5*time.Second),
		frames: make(chan wire.Frame), readErr: make(chan error, 1)}
	t.Logf("init boot_ms=%d", bootMS)
	t.Cleanup(func() {
		_ = raw.Close()
		if t.Failed() {
			t.Logf("frames:\n%s", strings.Join(g.seen, "\n"))
		}
	})
	go func() {
		for {
			f, err := g.c.ReadFrame()
			if err != nil {
				g.readErr <- err
				return
			}
			g.frames <- f
		}
	}()
	return g
}

func (g *client) send(typ uint8, payload []byte) {
	g.t.Helper()
	g.seen = append(g.seen, fmt.Sprintf("> type %d %q", typ, payload))
	if err := g.c.WriteFrame(wire.Frame{Type: typ, Payload: payload}); err != nil {
		g.t.Fatalf("send type %d: %v", typ, err)
	}
}

// stdin sends one Stdin frame as a host must: never with guest.StdinWindow unacknowledged.
func (g *client) stdin(b []byte) {
	g.t.Helper()
	for g.sent-g.acks >= guest.StdinWindow {
		g.read()
	}
	g.sent++
	g.send(guest.TypeStdin, b)
}

func (g *client) exec(e guest.Exec) {
	g.t.Helper()
	g.out.Reset()
	g.errs.Reset()
	g.sent, g.acks = 0, 0
	g.send(guest.TypeExec, guest.EncodeExec(e))
}

// read returns the next frame from the guest within 5 s, adding output to out and errs.
func (g *client) read() wire.Frame {
	g.t.Helper()
	select {
	case f := <-g.frames:
		g.seen = append(g.seen, fmt.Sprintf("< type %d %q", f.Type, f.Payload))
		switch f.Type {
		case guest.TypeStdout:
			g.out.Write(f.Payload)
		case guest.TypeStderr:
			g.errs.Write(f.Payload)
		case guest.TypeAck:
			g.acks++
		}
		return f
	case err := <-g.readErr:
		g.t.Fatalf("the guest's channel ended: %v", err)
	case <-time.After(5 * time.Second):
		g.t.Fatal("no frame from the guest in 5 s")
	}
	panic("unreachable")
}

// until reads output until it holds want, and returns it with carriage returns dropped.
func (g *client) until(want string) string {
	g.t.Helper()
	for {
		if s := strings.ReplaceAll(g.out.String(), "\r", ""); strings.Contains(s, want) {
			return s
		}
		if f := g.read(); f.Type == guest.TypeExit {
			g.t.Fatalf("the command ended (%q) before it printed %q; output %q", f.Payload, want, g.out.String())
		}
	}
}

// exit reads until the command's Exit.
func (g *client) exit() guest.Exit {
	g.t.Helper()
	for {
		if f := g.read(); f.Type == guest.TypeExit {
			e, err := guest.DecodeExit(f.Payload)
			if err != nil {
				g.t.Fatal(err)
			}
			return e
		}
	}
}
