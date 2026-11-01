// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"testing"
)

func TestQUICDCID(t *testing.T) {
	cid := bytes.Repeat([]byte{0xAB}, 16)
	good := quicInitial(cid)
	short := quicInitial(cid)[:quicInitMin-1]
	v2 := quicInitial(cid)
	v2[4] = 2
	shortHeader := quicInitial(cid)
	shortHeader[0] = 0x43
	long := quicInitial(cid)
	long[5] = maxCID + 1
	cases := []struct {
		name string
		in   []byte
		want []byte
		ok   bool
	}{
		{"initial", good, cid, true},
		{"empty cid", quicInitial(nil), []byte{}, true},
		{"max cid", quicInitial(make([]byte, maxCID)), make([]byte, maxCID), true},
		{"unpadded", short, nil, false},
		{"version 2", v2, nil, false},
		{"short header", shortHeader, nil, false},
		{"cid too long", long, nil, false},
		{"nothing", nil, nil, false},
		{"hello", []byte("hello\n"), nil, false},
	}
	for _, c := range cases {
		got, ok := quicDCID(c.in)
		if ok != c.ok || !bytes.Equal(got, c.want) {
			t.Errorf("%s: quicDCID = %x, %v; want %x, %v", c.name, got, ok, c.want, c.ok)
		}
	}
	if len(good) != quicInitMin {
		t.Errorf("quicInitial is %d bytes, want %d", len(good), quicInitMin)
	}
}

func FuzzQUICDCID(f *testing.F) {
	f.Add(quicInitial([]byte("0123456789abcdef")))
	f.Add([]byte{0xC3, 0, 0, 0, 1, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		dcid, ok := quicDCID(b)
		if !ok {
			return
		}
		again, _ := quicDCID(quicInitial(dcid))
		if len(dcid) > maxCID || !bytes.Equal(again, dcid) {
			t.Fatalf("quicDCID(%x) = %x: not a connection ID, or not what quicInitial encodes", b, dcid)
		}
	})
}

func TestICMP(t *testing.T) {
	payload := []byte("0123456789abcdef0123456789abcdef")
	req := icmpEcho(0x1234, 1, payload)
	if icmpChecksum(req) != 0 {
		t.Errorf("echo request checksum does not verify: % x", req)
	}
	if req[0] != 8 || req[4] != 0x12 || req[5] != 0x34 || !bytes.Equal(req[8:], payload) {
		t.Errorf("bad echo request: % x", req)
	}
	if icmpChecksum([]byte{0, 1, 0xF2, 3, 0xF4, 0xF5, 0xF6, 0xF7, 0}) != 0x220D { // RFC 1071 example, odd length
		t.Errorf("checksum is %#x", icmpChecksum([]byte{0, 1, 0xF2, 3, 0xF4, 0xF5, 0xF6, 0xF7, 0}))
	}
}
