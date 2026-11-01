// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"encoding/binary"
	"strings"
)

// A minimal DNS wire codec (RFC 1035 section 4.1) for the I3 probes and their
// canaries. The bytes a canary parses come from the guest and are hostile, so
// parseDNSQuery is total and fuzzed. A name is "label.label.", always with the
// trailing dot, every label 1 to 63 bytes of printable ASCII without a dot.

const (
	dnsTypeA   = 1
	dnsTypeTXT = 16
	dnsClassIN = 1
	maxLabel   = 63
	maxName    = 255
)

// dnsQuestion is the one question of a query.
type dnsQuestion struct {
	ID   uint16
	Name string
	Type uint16
}

// dnsQuery encodes a standard recursive query with one question. A name the
// rules above forbid still encodes, so that a probe can send what it likes.
func dnsQuery(q dnsQuestion) []byte {
	b := make([]byte, 12, 12+len(q.Name)+5)
	binary.BigEndian.PutUint16(b[0:], q.ID)
	b[2] = 0x01 // QR 0, opcode 0, RD
	b[5] = 1    // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(q.Name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, q.Type), dnsClassIN)
}

// parseDNSQuery decodes a message as a query (QR 0) whose first question has
// an uncompressed, well-formed name of class IN. Anything else is not a query
// the canary counts.
func parseDNSQuery(b []byte) (dnsQuestion, bool) {
	if len(b) < 12 || b[2]&0x80 != 0 || binary.BigEndian.Uint16(b[4:]) == 0 {
		return dnsQuestion{}, false
	}
	var name strings.Builder
	i := 12
	for {
		if i >= len(b) {
			return dnsQuestion{}, false
		}
		n := int(b[i])
		i++
		if n == 0 {
			break
		}
		if n > maxLabel || i+n > len(b) || name.Len()+n+1 > maxName {
			return dnsQuestion{}, false
		}
		for _, c := range b[i : i+n] {
			if c <= ' ' || c > '~' || c == '.' {
				return dnsQuestion{}, false
			}
		}
		name.Write(b[i : i+n])
		name.WriteByte('.')
		i += n
	}
	if name.Len() == 0 || i+4 > len(b) || binary.BigEndian.Uint16(b[i+2:]) != dnsClassIN {
		return dnsQuestion{}, false
	}
	return dnsQuestion{ID: binary.BigEndian.Uint16(b), Name: name.String(), Type: binary.BigEndian.Uint16(b[i:])}, true
}

// dnsFrame adds the two-byte length prefix of DNS over TCP and TLS (RFC 1035
// section 4.2.2, RFC 7858).
func dnsFrame(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(msg)), uint16(len(msg))), msg...)
}
