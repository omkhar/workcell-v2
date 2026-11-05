// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package resolver

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// query builds one query: id 0x1234, RD set, opcode, qdcount, one question for name (labels
// split on dots, a trailing dot allowed) of the type and class given.
func query(opcode byte, qdcount uint16, name string, typ, class uint16) []byte {
	b := []byte{0x12, 0x34, 0x01 | opcode<<3, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[4:], qdcount)
	if name != "" {
		for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			b = append(append(b, byte(len(label))), label...)
		}
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, typ)
	return binary.BigEndian.AppendUint16(b, class)
}

// rawName is an A query whose name section is the bytes given, terminator included, for what
// no name builder writes.
func rawName(wire ...byte) []byte {
	return append(append(query(0, 1, "", 0, 0)[:12], wire...), 0, 1, 0, 1)
}

// withOPT adds an EDNS0 OPT record as the query's one additional record.
func withOPT(q []byte) []byte {
	q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(q[10:], 1)
	return q
}

// reading is what a test reads from a reply: its rcode, question count, and the address of its
// one A record, "" for none.
type reading struct {
	rcode     byte
	questions int
	addr      string
}

// read parses a reply to a query of id 0x1234 and holds it to the shape every reply has: a
// response, at most one question echoed unchanged from the query, no record but the one A record.
func read(t *testing.T, q, b []byte) reading {
	t.Helper()
	if len(b) < headerLen || len(b) > maxReply || b[2]&0x80 == 0 || b[0] != 0x12 || b[1] != 0x34 {
		t.Fatalf("reply %x is no response to the query", b)
	}
	if b[2]&0x01 == 0 || b[3]&0x80 != 0 || binary.BigEndian.Uint16(b[8:]) != 0 || binary.BigEndian.Uint16(b[10:]) != 0 {
		t.Fatalf("reply %x: RD must be echoed, RA clear, and no authority or additional record", b)
	}
	got := reading{rcode: b[3] & 0x0F, questions: int(binary.BigEndian.Uint16(b[4:]))}
	body := b[headerLen:]
	if answers := binary.BigEndian.Uint16(b[6:]); answers == 1 {
		if len(body) < len(addressA) || !bytes.Equal(body[len(body)-len(addressA):len(body)-4], addressA[:12]) {
			t.Fatalf("reply %x has an answer that is not the one A record", b)
		}
		got.addr = net.IP(body[len(body)-4:]).String()
		body = body[:len(body)-len(addressA)]
	} else if answers != 0 {
		t.Fatalf("reply %x claims %d answers", b, answers)
	}
	if (got.questions == 0) != (len(body) == 0) || len(q) < headerLen+len(body) || !bytes.Equal(body, q[headerLen:headerLen+len(body)]) {
		t.Fatalf("reply %x does not echo the question of %x", b, q)
	}
	return got
}

func TestAnswer(t *testing.T) {
	t.Parallel()
	r := New([]string{"allowed.example", "db.example"})
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	address, nodata := reading{0, 1, "127.0.0.1"}, reading{0, 1, ""}
	refuse, formerr := reading{refused, 1, ""}, reading{formErr, 0, ""}
	tests := []struct {
		name string
		in   []byte
		want reading
	}{
		{"an allowed name", query(0, 1, "allowed.example", typeA, classIN), address},
		{"the other allowed name, rooted", query(0, 1, "db.example.", typeA, classIN), address},
		{"upper case", query(0, 1, "ALLOWED.EXAMPLE", typeA, classIN), address},
		{"mixed case", query(0, 1, "aLlOwEd.ExAmPlE.", typeA, classIN), address},
		{"with EDNS0", withOPT(query(0, 1, "allowed.example", typeA, classIN)), address},
		{"AAAA for an allowed name", query(0, 1, "allowed.example", 28, classIN), nodata},
		{"TXT for an allowed name", query(0, 1, "allowed.example", 16, classIN), nodata},
		{"ANY for an allowed name", query(0, 1, "allowed.example", 255, classIN), nodata},
		{"a name no policy allows", query(0, 1, "denied.example", typeA, classIN), refuse},
		{"a subdomain", query(0, 1, "sub.allowed.example", typeA, classIN), refuse},
		{"a name that ends in the allowed one", query(0, 1, "evilallowed.example", typeA, classIN), refuse},
		{"a name that starts with the allowed one", query(0, 1, "allowed.example.evil", typeA, classIN), refuse},
		{"one label holding the allowed name and a dot", rawName(append(append([]byte{15}, "allowed.example"...), 0)...), refuse},
		{"a label holding a byte above ASCII", query(0, 1, "allowed.exampl\xc9", typeA, classIN), refuse},
		{"a label holding a space", query(0, 1, "allowed.ex ample", typeA, classIN), refuse},
		{"the root", query(0, 1, "", typeA, classIN), refuse},
		{"PTR for loopback", query(0, 1, "1.0.0.127.in-addr.arpa", 12, classIN), refuse},
		{"class CH", query(0, 1, "allowed.example", typeA, 3), refuse},
		{"class ANY", query(0, 1, "allowed.example", typeA, 255), refuse},
		{"opcode IQUERY", query(1, 1, "allowed.example", typeA, classIN), refuse},
		{"opcode UPDATE", query(5, 1, "allowed.example", typeA, classIN), refuse},
		{"the longest name", query(0, 1, long, typeA, classIN), refuse},
		{"one byte past the longest name", query(0, 1, long+"e", typeA, classIN), formerr},
		{"a header that promises a question and brings none", query(0, 1, "", typeA, classIN)[:headerLen], formerr},
		{"no question promised", query(0, 0, "allowed.example", typeA, classIN), formerr},
		{"QDCOUNT 65535", query(0, 65535, "allowed.example", typeA, classIN), formerr},
		{"QDCOUNT 2", query(0, 2, "allowed.example", typeA, classIN), formerr},
		{"a compression pointer to itself", rawName(0xC0, 12), formerr},
		{"a 70-byte label", rawName(append(append([]byte{70}, strings.Repeat("x", 70)...), 0)...), formerr},
		{"a 64-byte label", rawName(append(append([]byte{64}, strings.Repeat("x", 64)...), 0)...), formerr},
		{"a label that runs off the message", query(0, 1, "allowed.example", typeA, classIN)[:20], formerr},
		{"a question cut before its class", query(0, 1, "allowed.example", typeA, classIN)[:31], formerr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := read(t, tc.in, r.Answer(tc.in)); got != tc.want {
				t.Errorf("Answer(%x) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// TestAnswerSaysNothing: a message shorter than a header, or one that is itself a response,
// gets no reply, so no answer is reflected; and an empty policy refuses the allowed name too.
func TestAnswerSaysNothing(t *testing.T) {
	t.Parallel()
	response := query(0, 1, "allowed.example", typeA, classIN)
	response[2] |= 0x80
	allowed := query(0, 1, "allowed.example", typeA, classIN)
	tests := []struct {
		name string
		r    *Resolver
		in   []byte
		want []byte
	}{
		{"one byte", New([]string{"allowed.example"}), []byte{0x55}, nil},
		{"eleven bytes", New([]string{"allowed.example"}), make([]byte, 11), nil},
		{"nothing", New([]string{"allowed.example"}), nil, nil},
		{"a response", New([]string{"allowed.example"}), response, nil},
		{"an empty policy", New(nil), allowed, reply(allowed, refused, nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.r.Answer(tc.in); !bytes.Equal(got, tc.want) {
				t.Errorf("Answer(%x) = %x, want %x", tc.in, got, tc.want)
			}
		})
	}
}

// FuzzAnswer holds the resolver to its bounds on any bytes (T5): it never panics, every query
// of a header or more gets a reply unless it is a response, a reply is at most maxReply bytes
// and is a response to the query's id with at most one question and one answer, and an answer
// comes only for a plain A question on the allowed name.
func FuzzAnswer(f *testing.F) {
	r := New([]string{"allowed.example"})
	f.Add(query(0, 1, "allowed.example", typeA, classIN))
	f.Add(withOPT(query(0, 1, "ALLOWED.example.", typeA, classIN)))
	f.Add(query(0, 1, "denied.example", 28, classIN))
	f.Add(rawName(0xC0, 12))
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, in []byte) {
		got := r.Answer(in)
		if got == nil {
			if len(in) >= headerLen && in[2]&0x80 == 0 {
				t.Fatalf("no reply to the %d-byte query %x", len(in), in)
			}
			return
		}
		if len(got) > maxReply || len(got) < headerLen || got[0] != in[0] || got[1] != in[1] || got[2]&0x80 == 0 {
			t.Fatalf("%x answered %x", in, got)
		}
		questions, answers := binary.BigEndian.Uint16(got[4:]), binary.BigEndian.Uint16(got[6:])
		if questions > 1 || answers > 1 || binary.BigEndian.Uint16(got[8:]) != 0 || binary.BigEndian.Uint16(got[10:]) != 0 {
			t.Fatalf("%x answered %x with %d questions and %d answers", in, got, questions, answers)
		}
		if answers == 1 {
			name, typ, class, _, ok := question(in)
			if !ok || name != "allowed.example" || typ != typeA || class != classIN || in[2]&0x78 != 0 {
				t.Fatalf("%x got an address: %x", in, got)
			}
		}
	})
}
