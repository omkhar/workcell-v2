// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package relay

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

func TestHeader(t *testing.T) {
	v4 := append([]byte{1, 6, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 198, 51, 100, 7)
	v6 := append([]byte{1, 6, 1, 187, 0x20, 0x01, 0x0d, 0xb8}, make([]byte, 12)...)
	v6[19] = 7
	dns := append([]byte{1, 17, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 127, 0, 0, 1)
	tests := []struct {
		name string
		in   []byte
		want Header
		ok   bool
	}{
		{"tcp to an IPv4 address", v4, Header{Proto: TCP, Dst: netip.MustParseAddrPort("198.51.100.7:443")}, true},
		{"tcp to an IPv6 address", v6, Header{Proto: TCP, Dst: netip.MustParseAddrPort("[2001:db8::7]:443")}, true},
		{"udp to the resolver", dns, Header{Proto: UDP, Dst: netip.MustParseAddrPort("127.0.0.1:53")}, true},
		{"empty", nil, Header{}, false},
		{"short", v4[:19], Header{}, false},
		{"long", append(bytes.Clone(v4), 0), Header{}, false},
		{"version 0", append([]byte{0}, v4[1:]...), Header{}, false},
		{"version 2", append([]byte{2}, v4[1:]...), Header{}, false},
		{"proto 0", append([]byte{1, 0}, v4[2:]...), Header{}, false},
		{"proto 1", append([]byte{1, 1}, v4[2:]...), Header{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("Decode(%x) = %+v, %v; want %+v, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
			if tc.ok && !bytes.Equal(got.Encode(), tc.in) {
				t.Errorf("%+v encodes to %x, want %x", got, got.Encode(), tc.in)
			}
		})
	}
}

func TestFrame(t *testing.T) {
	big := bytes.Repeat([]byte{7}, 65535)
	tests := []struct {
		name string
		in   []byte
		want []byte // nil for an error
	}{
		{"a datagram", append(Frame([]byte("abc")), "tail"...), []byte("abc")},
		{"empty datagram", []byte{0, 0}, []byte{}},
		{"the largest", Frame(big), big},
		{"no length", nil, nil},
		{"one length byte", []byte{0}, nil},
		{"shorter than its length", []byte{0, 3, 'a', 'b'}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadFrame(bytes.NewReader(tc.in))
			if (err == nil) != (tc.want != nil) || !bytes.Equal(got, tc.want) {
				t.Errorf("ReadFrame(%d bytes) = %d bytes, %v; want %d bytes", len(tc.in), len(got), err, len(tc.want))
			}
		})
	}
	if _, err := ReadFrame(bytes.NewReader(Frame([]byte("abc"))[:3])); err != io.ErrUnexpectedEOF {
		t.Errorf("a cut frame: %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

// FuzzDecode holds the header decoder to its bounds on any bytes: what decodes has a proto the
// host knows and encodes back to the same bytes, so the guest has exactly one way to name a destination.
func FuzzDecode(f *testing.F) {
	f.Add(Header{Proto: TCP, Dst: netip.MustParseAddrPort("198.51.100.7:443")}.Encode())
	f.Add(Header{Proto: UDP, Dst: netip.MustParseAddrPort("[::1]:53")}.Encode())
	f.Add([]byte{1, 6})
	f.Add(make([]byte, HeaderLen))
	f.Fuzz(func(t *testing.T, in []byte) {
		h, err := Decode(in)
		if err != nil {
			return
		}
		if h.Proto != TCP && h.Proto != UDP || !h.Dst.IsValid() || h.Dst.Addr().Is4In6() {
			t.Fatalf("%x decodes to %+v", in, h)
		}
		if again := h.Encode(); !bytes.Equal(again, in) {
			t.Fatalf("%x re-encodes to %x", in, again)
		}
	})
}

// FuzzReadFrame holds the frame reader to its bounds on any bytes: a frame is never longer
// than its two-byte length says, and what it reads frames back to the bytes it consumed.
func FuzzReadFrame(f *testing.F) {
	f.Add(Frame([]byte("abc")))
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0, 0, 1, 2})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		b, err := ReadFrame(r)
		if err != nil {
			return
		}
		used := len(in) - r.Len()
		if len(b) > 65535 || used != 2+len(b) || !bytes.Equal(Frame(b), in[:used]) {
			t.Fatalf("%d bytes read as a %d-byte frame using %d", len(in), len(b), used)
		}
	})
}
