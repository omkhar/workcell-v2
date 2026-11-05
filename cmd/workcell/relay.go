// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/internal/relay"
	"github.com/omkhar/workcell/v2/internal/resolver"
)

// The host end of the network path (ADR-003). The guest's init opens one vsock stream to
// relay.Port for each connection it accepted and names the destination in a 20-byte header.
// The bytes are the guest's (A1): the host reads exactly the header, under a deadline, before
// it allocates anything else, and holds a bounded number of streams (I10, I12). A TCP header
// for a port the policy serves hands the rest of the stream to that port's adapter, a
// net.Listener the proxy's Serve(adapter, port) takes connections from as it would from any
// listener: it routes by SNI or by the port's one host, resolves the name on the host and dials
// the vetted address. The address in the header is never dialled (I4). A UDP header for port 53,
// whatever its address, carries one framed query, which the host resolver answers from the
// policy alone with one framed reply (I3): no query leaves the host. Any other header closes the
// stream with nothing dialled.
const (
	maxStreams = 1024            // streams held at once; the next one is closed at once
	headerWait = 5 * time.Second // from accept to the last header byte, or to the end of a DNS exchange
	dnsPort    = 53
)

// portsArg is the workcell.ports= argument of the guest's kernel command line: the TCP ports
// the init relays. The guest listens on them (ADR-003); the host admits only them regardless (A1).
func portsArg(ports []uint16) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(int(p))
	}
	return "workcell.ports=" + strings.Join(s, ",")
}

// adapters are the served ports' listeners, one per port the allowlist names.
type adapters map[uint16]*adapter

func newAdapters(ports []uint16) adapters {
	served := adapters{}
	for _, p := range ports {
		served[p] = &adapter{port: p, conns: make(chan net.Conn), done: make(chan struct{})}
	}
	return served
}

func (a adapters) closeAll() {
	for _, l := range a {
		_ = l.Close()
	}
}

// adapter is the net.Listener of one served port: Accept takes the streams the demultiplexer
// delivers, and returns net.ErrClosed once the adapter is closed, which ends the proxy's Serve.
type adapter struct {
	port  uint16
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *adapter) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *adapter) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *adapter) Addr() net.Addr { return &net.TCPAddr{Port: int(l.port)} }

// deliver hands c to Accept, or closes it when the adapter is closed: the session has ended.
func (l *adapter) deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		_ = c.Close()
	}
}

// relayConn is one relayed stream as the proxy sees it: the bytes after the header. Its local
// address is the destination the guest's program dialled, which is where the guest's kernel
// accepted the connection: a hint for the deny line (U-308), never dialled (I4). Its remote
// address is the stream's own, the backend's end of the vsock. Closing it releases the
// stream's slot, so a conn the proxy holds is counted until the proxy lets go of it.
type relayConn struct {
	net.Conn
	dst     *net.TCPAddr
	release func()
	once    sync.Once
}

func (c *relayConn) LocalAddr() net.Addr { return c.dst }

func (c *relayConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// maxDenyLogBytes bounds what one session's deny.log may put on the host disk (I10): the guest
// can attempt connections for as long as the session lives, and each refusal is one line.
const maxDenyLogBytes = 8 << 20

// denyLogFull is the one line written when the cap is reached. It is no deny line: it has no
// host, port, count or seq, so a reader of the log can tell it apart, and the seq of the deny
// lines says how many were written before it.
const denyLogFull = "{\"reason\":\"deny_log_full\"}\n"

// boundedLog writes whole lines to w while the total stays within limit bytes, then writes
// denyLogFull once and drops everything after it. Every write reports success, so that the
// proxy never stalls on its log. The file may exceed limit by the marker alone.
type boundedLog struct {
	w     io.Writer
	limit int
	mu    sync.Mutex
	n     int
	full  bool
}

func (l *boundedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.full:
	case l.n+len(p) <= l.limit:
		_, _ = l.w.Write(p)
		l.n += len(p)
	default:
		l.full = true
		_, _ = l.w.Write([]byte(denyLogFull))
	}
	return len(p), nil
}

// serveRelay takes the guest's relayed streams until the listener closes with the session, then
// closes every adapter, so that the proxy's Serve loops end with it (A9). Each stream has wait
// to complete its header; dns answers the UDP 53 streams.
func serveRelay(ln net.Listener, served adapters, dns *resolver.Resolver, wait time.Duration) {
	defer served.closeAll()
	slots := make(chan struct{}, maxStreams)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go stream(&relayConn{Conn: c, release: func() { <-slots }}, served, dns, wait)
	}
}

// stream reads one header: 20 bytes within wait, or the stream is dropped. Version 1, TCP and a
// served port hand the rest of the stream to that port's adapter, the header consumed and the
// deadline lifted. Version 1, UDP and port 53 is one DNS exchange under the same deadline, and
// the stream closes after it. Any other header closes the stream with nothing dialled.
func stream(c *relayConn, served adapters, dns *resolver.Resolver, wait time.Duration) {
	_ = c.SetDeadline(time.Now().Add(wait))
	var b [relay.HeaderLen]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		_ = c.Close()
		return
	}
	h, err := relay.Decode(b[:])
	if err == nil && h.Proto == relay.UDP {
		if h.Dst.Port() == dnsPort {
			exchange(c, dns)
		}
		_ = c.Close()
		return
	}
	l, ok := served[h.Dst.Port()]
	if err != nil || h.Proto != relay.TCP || !ok || c.SetDeadline(time.Time{}) != nil {
		_ = c.Close()
		return
	}
	c.dst = net.TCPAddrFromAddrPort(h.Dst)
	l.deliver(c)
}

// exchange reads the one framed query of a DNS stream and writes the one framed reply, if the
// resolver has one. The frame reader bounds the query; the resolver bounds the reply (I12).
func exchange(c net.Conn, dns *resolver.Resolver) {
	q, err := relay.ReadFrame(c)
	if err != nil {
		return
	}
	if a := dns.Answer(q); a != nil {
		_, _ = c.Write(relay.Frame(a))
	}
}
