// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// C14 of S-1006 (I9, low). This file waits here, where Go does not compile it, until its fix lands or the finding is refuted; the fix unit moves it into
// cmd/workcell/. stream records a version-1 TCP header for a port the policy does not serve as port_not_allowed, but a version-1 UDP header for any port
// but 53 closes the stream with no record at all: a guest's UDP attempt on, say, 5353 is a connection attempt the host never recorded.
package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/resolver"
)

// TestStreamRecordsARefusedUDPHeader: a UDP header for a port the relay does not answer leaves a record, as a TCP header for a port the policy does not
// serve does. No record → FAIL (I9).
func TestStreamRecordsARefusedUDPHeader(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		ln, denied := newAdapters([]uint16{0})[0], make(chan string, 1)
		go serveRelay(ln, newAdapters([]uint16{8443}), resolver.New(nil, nil), func(host string, port uint16, reason string) {
			denied <- fmt.Sprintf("%s:%d %s", host, port, reason)
		}, time.Second)
		guest := dial(t, ln)
		go func() { _, _ = guest.Write(header(1, proto, "203.0.113.5:5353")) }()
		readEOF(t, guest, "the guest's end")
		select {
		case got := <-denied:
			t.Logf("proto %d to port 5353 recorded %q", proto, got)
		case <-time.After(time.Second):
			t.Errorf("proto %d to port 5353: the closed stream recorded nothing", proto)
		}
		_, _ = guest.Close(), ln.Close()
	}
}
