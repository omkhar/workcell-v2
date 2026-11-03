// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package relay is the wire vocabulary of the network path (ADR-003), shared by cmd/workcell-init
// and the host: the 20-byte header that opens every relayed stream and the two-byte length frame
// that carries one datagram on such a stream. The bytes of a header and of a frame come from the
// guest (A1), so the host decodes them with bounds and nothing else (I12).
package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
)

const (
	Port      = 5001 // the vsock port the init dials on the host, once per relayed stream
	HeaderLen = 20   // version, proto, port (big-endian), 16-byte address
	Version   = 1
	TCP       = 6  // one TCP connection: the rest of the stream is its bytes
	UDP       = 17 // one datagram: a Frame, and one Frame in reply
)

// Header is the destination of one relayed stream, as the guest's program dialled it.
type Header struct {
	Proto byte
	Dst   netip.AddrPort
}

// Encode is the header on the wire; an IPv4 address goes as IPv4-mapped IPv6.
func (h Header) Encode() []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = Version, h.Proto
	binary.BigEndian.PutUint16(b[2:], h.Dst.Port())
	a := h.Dst.Addr().As16()
	copy(b[4:], a[:])
	return b
}

// Decode reads a header. It accepts exactly HeaderLen bytes, Version, and TCP or UDP.
func Decode(b []byte) (Header, error) {
	switch {
	case len(b) != HeaderLen:
		return Header{}, fmt.Errorf("relay header: %d bytes, want %d", len(b), HeaderLen)
	case b[0] != Version:
		return Header{}, fmt.Errorf("relay header: version %d, want %d", b[0], Version)
	case b[1] != TCP && b[1] != UDP:
		return Header{}, fmt.Errorf("relay header: proto %d, want %d or %d", b[1], TCP, UDP)
	}
	addr := netip.AddrFrom16([16]byte(b[4:])).Unmap()
	return Header{Proto: b[1], Dst: netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[2:]))}, nil
}

// Frame prefixes a datagram with its length, as DNS over TCP does. A datagram is at most 65535 bytes.
func Frame(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// ReadFrame reads one framed datagram: at most 65535 bytes, so a frame is never a large allocation.
func ReadFrame(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
