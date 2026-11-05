// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/relay"
)

func TestPortsArg(t *testing.T) {
	tests := []struct {
		name string
		in   []uint16
		want string
	}{
		{"none", nil, "workcell.ports="},
		{"one", []uint16{443}, "workcell.ports=443"},
		{"many, in the order given", []uint16{443, 80, 8443}, "workcell.ports=443,80,8443"},
		{"the largest", []uint16{65535}, "workcell.ports=65535"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := portsArg(tc.in); got != tc.want {
				t.Errorf("portsArg(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// pipeListener stands in for the backend's relay listener: each stream is a net.Pipe, the
// guest's end returned by dial, the host's end given to Accept.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "relay", Net: "unix"} }

// dial opens a stream and returns the guest's end once the relay has accepted the host's.
func (l *pipeListener) dial(t *testing.T) net.Conn {
	t.Helper()
	g, h := net.Pipe()
	select {
	case l.conns <- h:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not accept a stream")
	}
	return g
}

// header is a relay header with the version and proto given, for the destination dst.
func header(version, proto byte, dst string) []byte {
	b := relay.Header{Proto: relay.TCP, Dst: netip.MustParseAddrPort(dst)}.Encode()
	b[0], b[1] = version, proto
	return b
}

// readEOF holds c to being closed by the host within wait.
func readEOF(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("%s: read = %d, %v; want EOF", what, n, err)
	}
}

// held holds c to being open and silent for 200 ms.
func held(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%s: read = %d, %v; want the stream held open", what, n, err)
	}
}

// acceptOne is the next connection of l, which must come within 5 s.
func acceptOne(t *testing.T, l *adapter) (net.Conn, error) {
	t.Helper()
	type got struct {
		c   net.Conn
		err error
	}
	ch := make(chan got, 1)
	go func() { c, err := l.Accept(); ch <- got{c, err} }()
	select {
	case g := <-ch:
		return g.c, g.err
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
		return nil, nil
	}
}

func TestStreamDemultiplexes(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		local  string // the LocalAddr the adapter's conn reports; "" when the stream must close
	}{
		{"a served port", header(1, 6, "203.0.113.5:8443"), "203.0.113.5:8443"},
		{"a served port over IPv6", header(1, 6, "[2001:db8::1]:8443"), "[2001:db8::1]:8443"},
		{"an unserved port", header(1, 6, "203.0.113.5:80"), ""},
		{"port 443, not served by this policy", header(1, 6, "203.0.113.5:443"), ""},
		{"UDP on a served port", header(1, 17, "203.0.113.5:8443"), ""},
		{"version 2", header(2, 6, "203.0.113.5:8443"), ""},
		{"version 0", header(0, 6, "203.0.113.5:8443"), ""},
		{"proto 0", header(1, 0, "203.0.113.5:8443"), ""},
		{"proto 1", header(1, 1, "203.0.113.5:8443"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ln := newPipeListener()
			served := newAdapters([]uint16{8443})
			go serveRelay(ln, served, time.Second)
			defer ln.Close()
			guest := ln.dial(t)
			defer guest.Close()
			go func() { _, _ = guest.Write(append(tc.header, "payload"...)) }()
			if tc.local == "" {
				// The host closed the stream without delivering it: a delivered stream is held
				// open by the proxy, not closed, so the EOF alone proves it went nowhere.
				readEOF(t, guest, "the guest's end")
				return
			}
			c, err := acceptOne(t, served[8443])
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			got := make([]byte, 7)
			if _, err := io.ReadFull(c, got); err != nil || string(got) != "payload" {
				t.Errorf("the proxy read %q, %v; want the payload with the header consumed", got, err)
			}
			if c.LocalAddr().String() != tc.local {
				t.Errorf("LocalAddr = %s, want %s", c.LocalAddr(), tc.local)
			}
			if c.RemoteAddr().Network() != "pipe" {
				t.Errorf("RemoteAddr = %s, want the stream's own", c.RemoteAddr())
			}
		})
	}
}

// TestRelayHoldsAtMostMaxStreams: the 1024th stream is held, the 1025th is closed at once, and
// a slot is released when the guest ends a stream, or when the proxy closes a delivered one.
func TestRelayHoldsAtMostMaxStreams(t *testing.T) {
	ln := newPipeListener()
	served := newAdapters([]uint16{8443})
	go serveRelay(ln, served, 30*time.Second)
	defer ln.Close()
	var guests []net.Conn
	defer func() {
		for _, g := range guests {
			_ = g.Close()
		}
	}()
	for range maxStreams {
		guests = append(guests, ln.dial(t))
	}
	held(t, guests[maxStreams-1], "the 1024th stream")
	readEOF(t, ln.dial(t), "the 1025th stream")

	// dialHeld dials until a stream is held: the release of a slot is asynchronous.
	dialHeld := func(what string) net.Conn {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			g := ln.dial(t)
			_ = g.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := g.Read(make([]byte, 1)); errors.Is(err, os.ErrDeadlineExceeded) {
				return g
			}
		}
		t.Fatalf("%s: no stream was held", what)
		return nil
	}
	_ = guests[0].Close() // the guest ends a stream: its slot comes back
	guests = append(guests, dialHeld("after the guest closed a stream"))

	go func() { _, _ = guests[1].Write(header(1, 6, "203.0.113.5:8443")) }()
	c, err := acceptOne(t, served[8443]) // delivered: the proxy holds the stream and its slot
	if err != nil {
		t.Fatal(err)
	}
	readEOF(t, ln.dial(t), "a stream while the proxy holds the 1024th")
	_ = c.Close() // the proxy is done with it
	guests = append(guests, dialHeld("after the proxy closed a stream"))
}

func TestRelayDropsAnIncompleteHeader(t *testing.T) {
	ln := newPipeListener()
	go serveRelay(ln, newAdapters(nil), 100*time.Millisecond)
	defer ln.Close()
	guest := ln.dial(t)
	defer guest.Close()
	start := time.Now()
	if _, err := guest.Write(header(1, 6, "203.0.113.5:8443")[:10]); err != nil {
		t.Fatal(err)
	}
	readEOF(t, guest, "a stream with half a header")
	if took := time.Since(start); took < 100*time.Millisecond {
		t.Errorf("the stream was dropped after %s, before the header's deadline", took)
	}
}

// TestRelayCloseEndsAdapters: closing the relay listener ends every adapter's Accept with
// net.ErrClosed, which is what the proxy's Serve returns on, and leaves no goroutine behind.
func TestRelayCloseEndsAdapters(t *testing.T) {
	before := runtime.NumGoroutine()
	ln := newPipeListener()
	served := newAdapters([]uint16{443, 8443})
	go serveRelay(ln, served, 200*time.Millisecond)
	delivered := ln.dial(t)
	go func() { _, _ = delivered.Write(header(1, 6, "203.0.113.5:8443")) }()
	c, err := acceptOne(t, served[8443])
	if err != nil {
		t.Fatal(err)
	}
	headless := ln.dial(t) // held for its header when the session ends
	_ = ln.Close()
	for port, l := range served {
		if _, err := acceptOne(t, l); !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept on port %d after the relay closed = %v, want net.ErrClosed", port, err)
		}
	}
	got := make(chan error, 1)
	go func() { _, err := io.ReadFull(delivered, make([]byte, 10)); got <- err }()
	if _, err := c.Write([]byte("still mine")); err != nil || <-got != nil { // the proxy decides when a delivered stream ends
		t.Errorf("a delivered stream after the relay closed: %v", err)
	}
	_ = c.Close()
	_ = delivered.Close()
	readEOF(t, headless, "the headless stream")
	_ = headless.Close()
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines after the relay closed, %d before", runtime.NumGoroutine(), before)
		}
	}
}
