// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/internal/relay"
)

// The host end of the network path (ADR-003). The guest's init opens one vsock stream to
// relay.Port for each connection it accepted and names the destination in a 20-byte header.
// The bytes are the guest's (A1): the host reads exactly the header, under a deadline, before
// it allocates anything else, and holds a bounded number of streams (I10, I12). The address in
// the header is never dialled (I4): the proxy resolves names on the host. No port is served yet
// (U-303 brings the proxy's adapters), so every stream ends once its header is in, whatever it says.
const (
	maxStreams = 1024            // streams held at once; the next one is closed at once
	headerWait = 5 * time.Second // from accept to the last header byte
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

// serveRelay takes the guest's relayed streams until the listener closes with the session.
func serveRelay(ln net.Listener) {
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
		go func() {
			defer func() { _ = c.Close(); <-slots }()
			stream(c)
		}()
	}
}

// stream reads one header: 20 bytes within headerWait, or the stream is dropped. A valid header
// names a port the host does not serve yet, so the stream ends here either way.
func stream(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(headerWait))
	var b [relay.HeaderLen]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return
	}
	_, _ = relay.Decode(b[:])
}
