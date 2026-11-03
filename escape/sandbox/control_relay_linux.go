// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
)

// naiveRelay is the host end of the control sandbox's relay, the deliberately
// weak counterpart of the product's (SPEC T2, I2, I4, I12): it accepts every
// stream, waits for the 20-byte header with no clock, checks neither version
// nor proto, dials whatever address and port the header names, as UDP when
// the proto says so and as TCP otherwise, and splices. It is what a relay
// that trusted the guest would be. Only the suite's own probes name an
// address, and they name canaries on the test host (SPEC T8, S12).
type naiveRelay struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

func (r *naiveRelay) serve() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		r.conns = append(r.conns, c)
		r.mu.Unlock()
		r.wg.Go(func() { r.one(c) })
	}
}

// one relays a stream: the header, then for UDP one framed datagram sent as
// it came, else both directions of a TCP connection until either end closes.
func (r *naiveRelay) one(c net.Conn) {
	defer c.Close()
	var h [20]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	addr := net.JoinHostPort(net.IP(h[4:]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(h[2:]))))
	if h[1] == 17 {
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		u, err := net.Dial("udp", addr)
		if err != nil {
			return
		}
		defer u.Close()
		u.Write(b)
		return
	}
	up, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer up.Close()
	go func() {
		io.Copy(up, c)
		up.(*net.TCPConn).CloseWrite()
	}()
	io.Copy(c, up)
}

func (r *naiveRelay) stop() {
	r.ln.Close()
	r.mu.Lock()
	for _, c := range r.conns {
		c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}
