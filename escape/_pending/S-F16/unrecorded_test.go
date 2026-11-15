// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// S-F16 (C23 full log, C24 failed write; I9): package proxy, for internal/proxy/proxy_test.go. Overlay: cp escape/_pending/S-F16/unrecorded_test.go internal/proxy/ && go test ./internal/proxy -run TestUnrecordedConnectionIsNotServed
package proxy

import (
	"github.com/omkhar/workcell/v2/internal/audit"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type failingRecorder struct{ err error }

func (r failingRecorder) Note(audit.Record) error { return r.err }
func TestUnrecordedConnectionIsNotServed(t *testing.T) {
	for _, err := range []error{audit.ErrFull, io.ErrUnexpectedEOF} { // C23: the log is full; C24: a write to it failed
		p, _, dialed := testProxy(t, "db.example:5432", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, must(net.Listen("tcp", "127.0.0.1:0")).Addr().String()) // an upstream that lives for the test
		p.rec = failingRecorder{err}
		c := must(net.Dial("tcp", listen(t, p, 5432)))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := c.Read(make([]byte, 1)); rerr != io.EOF || len(*dialed) != 0 {
			t.Fatalf("recorder failing with %q: the guest read %v and the upstream was dialled %d times; want EOF and no dial", err, rerr, len(*dialed))
		}
	}
}
