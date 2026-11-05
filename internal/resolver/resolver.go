// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package resolver is the host resolver of the network path (ADR-003, I3). It answers the guest's
// DNS from the policy alone: an A question for a name the policy allows gets one fixed address,
// any other question for such a name gets an empty answer, and every other name is refused. No
// query is forwarded anywhere, so nothing the guest asks leaves the host, and there is no cache,
// no upstream and no timeout. The address is a hint: in the guest every address routes to the
// init, and the proxy resolves the name on the host and dials the vetted address (I4). The bytes
// of a query are the guest's (A1): the parser reads one question, plain labels only, within the
// message, and a reply is at most maxReply bytes (I12).
package resolver

import "encoding/binary"

const (
	headerLen = 12
	maxName   = 253 // the text of a name, as the proxy bounds it
	maxLabel  = 63
	maxReply  = headerLen + maxName + 2 + 4 + 16 // header, question (name, type, class), one A record
	typeA     = 1
	classIN   = 1
	formErr   = 1
	refused   = 5
)

// addressA is the one answer: the question's name (a pointer to it), type A, class IN, TTL 60,
// 127.0.0.1. In the guest 127.0.0.1 is where the init listens, so the program's connection lands
// in the relay whatever route the guest has (ADR-003). 16 bytes, as maxReply counts.
var addressA = []byte{0xC0, headerLen, 0, typeA, 0, classIN, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1}

// Resolver holds the allowed names: lower-case, no trailing dot, as the proxy holds them.
type Resolver struct{ names map[string]bool }

// New makes a resolver that answers names and refuses every other name.
func New(names []string) *Resolver {
	r := &Resolver{names: make(map[string]bool, len(names))}
	for _, n := range names {
		r.names[n] = true
	}
	return r
}

// Answer is the reply to one query: an address for an A question on an allowed name, no record
// for any other question on it, REFUSED for every other name, FORMERR for a message that is no
// query, and nil for one too short to answer or one that is itself a response.
func (r *Resolver) Answer(q []byte) []byte {
	if len(q) < headerLen || q[2]&0x80 != 0 {
		return nil
	}
	name, typ, class, end, ok := question(q)
	if !ok {
		return reply(q[:headerLen], formErr, nil)
	}
	if q[2]&0x78 != 0 || class != classIN || !r.names[name] {
		return reply(q[:end], refused, nil)
	}
	if typ != typeA {
		return reply(q[:end], 0, nil)
	}
	return reply(q[:end], 0, addressA)
}

// question reads the one question of q: its name, lower-cased, without the trailing dot and
// empty when any label holds a byte no host name has, so that it matches one spelling or none;
// its type and class; and where it ends. It wants one question of plain labels within bounds.
func question(q []byte) (name string, typ, class uint16, end int, ok bool) {
	if binary.BigEndian.Uint16(q[4:]) != 1 {
		return "", 0, 0, 0, false
	}
	text := make([]byte, 0, maxName)
	plain := true
	i := headerLen
	for {
		if i >= len(q) {
			return "", 0, 0, 0, false
		}
		n := int(q[i])
		i++
		if n == 0 {
			break
		}
		if len(text) > 0 {
			text = append(text, '.')
		}
		if n > maxLabel || i+n > len(q) || len(text)+n > maxName {
			return "", 0, 0, 0, false
		}
		for _, c := range q[i : i+n] {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				plain = false
			}
			text = append(text, c)
		}
		i += n
	}
	if i+4 > len(q) {
		return "", 0, 0, 0, false
	}
	if plain {
		name = string(text)
	}
	return name, binary.BigEndian.Uint16(q[i:]), binary.BigEndian.Uint16(q[i+2:]), i + 4, true
}

// reply is a response to q, which is the header and the question when there is one: the same
// id and opcode, QR set, RD as asked, no recursion available, rcode, and answer if any.
func reply(q []byte, rcode byte, answer []byte) []byte {
	b := make([]byte, 0, maxReply)
	b = append(b, q...)
	b[2] = 0x80 | q[2]&0x79
	b[3] = rcode
	var questions, answers uint16
	if len(q) > headerLen {
		questions = 1
	}
	if len(answer) > 0 {
		answers = 1
	}
	binary.BigEndian.PutUint16(b[4:], questions)
	binary.BigEndian.PutUint16(b[6:], answers)
	clear(b[8:headerLen])
	return append(b, answer...)
}
