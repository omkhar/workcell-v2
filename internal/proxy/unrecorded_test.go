// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// S-F16 fix of C23 (full log) and C24 (failed write) of S-1010, I9: a connection whose record cannot be taken is not served.
package proxy

import (
	"crypto/tls"
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
	for i, err := range []error{audit.ErrFull, io.ErrUnexpectedEOF, audit.ErrFull, io.ErrUnexpectedEOF} { // C23: the log is full; C24: a write to it failed; twice: on the spliced forward port, then on the terminated one
		port := []uint16{5432, 5432, 443, 443}[i]
		p, log, dialed := testProxy(t, "api.example.com:5432 api.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, "") // no upstream: a dial, which must not happen, fails at once
		p.rec = failingRecorder{err}
		must(0, p.Terminate(must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour))), nil, nil))
		if _, herr := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", listen(t, p, port), &tls.Config{ServerName: "api.example.com", InsecureSkipVerify: true}); herr != io.EOF || func() int { log.mu.Lock(); defer log.mu.Unlock(); return len(*dialed) }() != 0 {
			t.Errorf("recorder failing with %q, port %d: the guest's handshake ended with %v; want EOF before any upstream dial (EOF here means the upstream was dialled)", err, port, herr)
		}
	}
}
