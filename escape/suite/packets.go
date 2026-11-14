// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import "bytes"

// Pure encoders and parsers for the probes' packets. The bytes a judge parses come from the guest and are hostile, so quicDCID is total and fuzzed.

const (
	maxCID      = 20   // RFC 9000: a connection ID is at most 20 bytes
	quicInitMin = 1200 // RFC 9000: a client Initial is padded to at least this
)

// quicInitial builds a QUIC version 1 Initial packet with the destination connection ID dcid, padded as a client's first flight must be. Its payload
// is not a valid handshake; a canary only needs the invariant header.
func quicInitial(dcid []byte) []byte {
	b := []byte{0xC3, 0, 0, 0, 1, byte(len(dcid))} // long header, fixed bit, Initial, 4-byte packet number; version 1
	b = append(b, dcid...)
	b = append(b, 0, 0)                         // no source connection ID, no token
	rem := quicInitMin - len(b) - 2             // what follows the 2-byte length
	b = append(b, byte(0x40|rem>>8), byte(rem)) // length, as a 2-byte varint
	return append(b, make([]byte, rem)...)      // packet number and payload
}

// quicDCID parses a datagram as a QUIC version 1 Initial packet and returns its destination connection ID.
func quicDCID(b []byte) ([]byte, bool) {
	if len(b) < quicInitMin || b[0]&0xF0 != 0xC0 || !bytes.Equal(b[1:5], []byte{0, 0, 0, 1}) {
		return nil, false
	}
	n := int(b[5])
	if n > maxCID || 6+n > len(b) {
		return nil, false
	}
	return b[6 : 6+n], true
}

// icmpEcho builds an ICMPv4 echo request carrying payload.
func icmpEcho(id, seq uint16, payload []byte) []byte {
	b := append([]byte{8, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq)}, payload...)
	sum := icmpChecksum(b)
	b[2], b[3] = byte(sum>>8), byte(sum)
	return b
}

// icmpReply parses what a socket returned, with the IPv4 header still on it when raw is set, and returns the payload if it is an echo reply.
func icmpReply(b []byte, raw bool) ([]byte, bool) {
	if raw {
		if len(b) < 20 {
			return nil, false
		}
		ihl := int(b[0]&0x0F) * 4
		if ihl < 20 || ihl > len(b) {
			return nil, false
		}
		b = b[ihl:]
	}
	if len(b) < 8 || b[0] != 0 || b[1] != 0 {
		return nil, false
	}
	return b[8:], true
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}
