// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

// A minimal DNS wire codec (RFC 1035 section 4.1) for the I3 probes and their
// canaries. The bytes a canary parses come from the guest and are hostile, so
// parseDNSQuery is total and fuzzed. A name is "label.label.", always with the
// trailing dot, every label 1 to 63 bytes of printable ASCII without a dot.

const (
	dnsTypeA    = 1
	dnsTypePTR  = 12
	dnsTypeTXT  = 16
	dnsTypeAAAA = 28
	dnsTypeOPT  = 41
	dnsTypeANY  = 255
	dnsClassIN  = 1
	maxLabel    = 63
	maxName     = 255
)

// Response codes (RFC 1035 section 4.1.1), as the resolver probes name them.
var rcodeNames = map[uint16]string{0: "noerror", 1: "formerr", 2: "servfail", 3: "nxdomain", 4: "notimp", 5: "refused"}

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

// withEDNS0 adds an OPT pseudo-record (RFC 6891) to a query: ARCOUNT 1, root
// name, type OPT, a 4096-byte UDP size in the class field, no options.
func withEDNS0(msg []byte) []byte {
	msg = bytes.Clone(msg)
	binary.BigEndian.PutUint16(msg[10:], 1)
	return append(msg, 0, 0, dnsTypeOPT, 0x10, 0, 0, 0, 0, 0, 0, 0)
}

// dnsReply is what a resolver's response says, as far as a probe judges it:
// the id it answers, its rcode, and the type and data of each answer record.
type dnsReply struct {
	ID      uint16
	Rcode   uint16
	Answers []dnsRR
}

type dnsRR struct {
	Type uint16
	Data []byte
}

// parseDNSReply decodes a message as a response (QR 1) whose answer section
// it can walk: names are skipped, compressed or not, and nothing is followed.
// The bytes come from whatever answered the guest and are hostile, so the
// parser is total: anything it cannot walk is not a reply.
func parseDNSReply(b []byte) (dnsReply, bool) {
	if len(b) < 12 || b[2]&0x80 == 0 {
		return dnsReply{}, false
	}
	r := dnsReply{ID: binary.BigEndian.Uint16(b), Rcode: uint16(b[3] & 0x0F)}
	qd, an := int(binary.BigEndian.Uint16(b[4:])), int(binary.BigEndian.Uint16(b[6:]))
	i := 12
	for range qd {
		if i = skipName(b, i); i < 0 || i+4 > len(b) {
			return dnsReply{}, false
		}
		i += 4
	}
	for range an {
		if i = skipName(b, i); i < 0 || i+10 > len(b) {
			return dnsReply{}, false
		}
		typ, n := binary.BigEndian.Uint16(b[i:]), int(binary.BigEndian.Uint16(b[i+8:]))
		i += 10
		if i+n > len(b) {
			return dnsReply{}, false
		}
		r.Answers = append(r.Answers, dnsRR{Type: typ, Data: bytes.Clone(b[i : i+n])})
		i += n
	}
	return r, true
}

// skipName returns the offset after the name at i, or -1 if it runs off the
// message. A compression pointer ends the name where it stands.
func skipName(b []byte, i int) int {
	for {
		if i >= len(b) {
			return -1
		}
		n := int(b[i])
		switch {
		case n == 0:
			return i + 1
		case n&0xC0 == 0xC0:
			return i + 2
		case n&0xC0 != 0:
			return -1
		}
		i += 1 + n
	}
}

// addresses lists the A and AAAA records of a reply, as text.
func (r dnsReply) addresses() []string {
	var out []string
	for _, rr := range r.Answers {
		if (rr.Type == dnsTypeA && len(rr.Data) == 4) || (rr.Type == dnsTypeAAAA && len(rr.Data) == 16) {
			out = append(out, net.IP(rr.Data).String())
		}
	}
	return out
}
