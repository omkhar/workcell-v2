// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
)

func TestLastLines(t *testing.T) {
	tests := []struct {
		name, in string
		n        int
		want     string
	}{
		{"empty", "", 3, ""},
		{"fewer lines than asked", "a\nb\n", 3, "a\nb"},
		{"the last two", "a\nb\nc\nd\n", 2, "c\nd"},
		{"no final newline", "a\nb", 1, "b"},
		{"carriage returns go", "a\r\nb\r\n", 2, "a\nb"},
		{"escape sequences are defused", "\x1b]0;x\x07ok\x00", 1, "?]0;x?ok?"},
		{"non-ASCII is defused", "caf\xc3\xa9", 1, "caf?"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastLines([]byte(tc.in), tc.n); got != tc.want {
				t.Errorf("lastLines(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestTailIsBounded(t *testing.T) {
	var c tail
	for range 100 {
		_, _ = c.Write([]byte(strings.Repeat("x", 1000)))
	}
	_, _ = c.Write([]byte("end"))
	if b := c.bytes(); len(b) != 4096 || !strings.HasSuffix(string(b), "xend") {
		t.Errorf("tail holds %d bytes ending %q, want 4096 ending xend", len(b), b[len(b)-4:])
	}
}

// TestOnceTakesOneConnection is the regression test for the channel connect flood (I12): once the init's connection is in, a later connection to the port is
// refused rather than queued on the host with whatever the guest writes on it, and the first one goes on working.
func TestOnceTakesOneConnection(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "vsock_5000")
	raw := must(net.Listen("unix", addr))
	ln := once{raw}
	defer ln.Close()
	first := must(net.Dial("unix", addr))
	defer first.Close()
	queued := must(net.Dial("unix", addr)) // in the backlog before the host accepts
	defer queued.Close()
	conn := must(ln.Accept())
	defer conn.Close()

	if c, err := net.Dial("unix", addr); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("a connection after the first Accept: %v, want ENOENT", err)
		if err == nil {
			_ = c.Close()
		}
	}
	if _, err := os.Stat(addr); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket %s after the first Accept: %v, want gone", addr, err)
	}
	must(0, queued.SetReadDeadline(time.Now().Add(2*time.Second)))
	if _, err := queued.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection queued before the first Accept still stands: %v", err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("a second Accept returned a connection")
	}
	go func() { _, _ = first.Write([]byte("hi")) }()
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hi" {
		t.Errorf("the first connection after the listener closed: %q, %v", got, err)
	}
}

// TestOutput drives output with the guest's frames: how the command ended comes from its Exit, and an Exit with Err qualifies for fail (first) only as the
// guest's first frame, since the init's exec failure comes before anything else and a forged one needs a running process, which spoke before it (I12, A1).
func TestOutput(t *testing.T) {
	noexec := guest.Exit{Err: "no such file"}
	tests := []struct {
		name   string
		before []wire.Frame // what the guest sends before its Exit
		exit   guest.Exit
		want   result
	}{
		{"success", nil, guest.Exit{}, result{}},
		{"status 7", nil, guest.Exit{Code: 7}, result{code: 7}},
		{"killed by SIGTERM", nil, guest.Exit{Signal: 15}, result{code: 143}},
		{"could not run, the first frame", nil, noexec, result{code: 126, err: errNoExec, first: true}},
		{"could not run after output", []wire.Frame{{Type: guest.TypeStdout, Payload: []byte("hi")}}, noexec, result{code: 126, err: errNoExec}},
		{"could not run after an ack", []wire.Frame{{Type: guest.TypeAck, Payload: guest.EncodeAck(1)}}, noexec, result{code: 126, err: errNoExec}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, g := net.Pipe()
			defer host.Close()
			done := make(chan result, 1)
			go output(wire.New(host, time.Second), &seat{window: make(chan struct{}, 1)}, done)
			gc := wire.New(g, time.Second)
			for _, f := range append(tc.before, wire.Frame{Type: guest.TypeExit, Payload: guest.EncodeExit(tc.exit)}) {
				if err := gc.WriteFrame(f); err != nil {
					t.Fatal(err)
				}
			}
			if got := <-done; got.code != tc.want.code || !errors.Is(got.err, tc.want.err) || got.first != tc.want.first {
				t.Errorf("output = %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := exitResult([]byte{9, 9, 9}, false); got.err == nil {
		t.Error("exitResult of a payload that is no Exit has no error")
	}
}

// TestSeat: output with nobody attached is dropped; a client sees the output and its Stdin and Resize frames reach the guest side, anything else it sends does
// not; the next client turns the first out and gets the output instead; a client that has gone costs the seat, not the session.
func TestSeat(t *testing.T) {
	s := &seat{window: make(chan struct{}, 4), in: make(chan wire.Frame, 4)}
	out := func(text string) wire.Frame { return wire.Frame{Type: guest.TypeStdout, Payload: []byte(text)} }
	client := func() (*wire.Conn, net.Conn) {
		a, b := net.Pipe()
		s.sit(a)
		stop := time.AfterFunc(10*time.Second, func() { b.Close() }) // a hang becomes a failure
		t.Cleanup(func() { stop.Stop(); b.Close() })
		return wire.New(b, time.Second), b
	}
	shown := func(c *wire.Conn, text string) {
		t.Helper()
		go s.send(out(text))
		if f, err := c.ReadFrame(); err != nil || f.Type != guest.TypeStdout || string(f.Payload) != text {
			t.Fatalf("client shows %+v, %v; want %q", f, err, text)
		}
	}
	s.send(out("nobody")) // must return
	first, _ := client()
	shown(first, "one")
	for _, f := range []wire.Frame{{Type: guest.TypeExec}, {Type: guest.TypeStdin, Payload: []byte("x")}, {Type: guest.TypeResize, Payload: guest.EncodeResize(guest.Resize{Rows: 3, Cols: 4})}} {
		if err := first.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []uint8{guest.TypeStdin, guest.TypeResize} {
		if f := <-s.in; f.Type != want {
			t.Errorf("the guest side got type %d, want %d", f.Type, want)
		}
	}
	if len(s.window) != 1 {
		t.Errorf("%d window slots taken, want 1 for one Stdin frame", len(s.window))
	}
	second, gone := client()
	if _, err := first.ReadFrame(); err == nil {
		t.Error("the first client still reads after the second sat down")
	}
	shown(second, "two")
	gone.Close()
	for range 2 { // the first send that fails empties the seat; the next finds nobody
		s.send(out("lost"))
	}
}

// TestClientEndsWithItsConnection is the regression test for a session that ends in error (a malformed frame from the guest, I12): no Exit frame reaches the
// client, so only the closing of its connection ends it, and the supervisor, which waits for it, must not hang.
func TestClientEndsWithItsConnection(t *testing.T) {
	ours, theirs := net.Pipe()
	ended := make(chan int, 1)
	go func() { code, _ := client(theirs, func() {}, false); ended <- code }()
	ours.Close()
	select {
	case code := <-ended:
		if code != 0 {
			t.Errorf("client ended with %d, want 0", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client still running 10 s after its connection closed")
	}
}
