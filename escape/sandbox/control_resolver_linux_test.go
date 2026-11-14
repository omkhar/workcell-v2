// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestNaiveResolver asks the naive resolver, on an ephemeral port, for a name of each kind and checks that each gets one record, and that what is
// not a query gets nothing.
func TestNaiveResolver(t *testing.T) {
	r, err := listenNaiveResolver("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.stop()
	c, err := net.Dial("udp", r.pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	query := func(typ byte) []byte {
		return []byte{0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 4, 't', 'e', 's', 't', 0, 0, typ, 0, 1}
	}
	for _, c2 := range []struct {
		typ  byte
		want byte // the type answered
		n    int  // rdata length
	}{{1, 1, 4}, {255, 1, 4}, {28, 28, 16}, {16, 16, 6}, {12, 16, 6}} {
		q := query(c2.typ)
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(q); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("type %d: %v", c2.typ, err)
		}
		a := buf[:n]
		if n != len(q)+12+c2.n || !bytes.Equal(a[:2], q[:2]) || a[2] != 0x81 || a[3] != 0x80 || a[7] != 1 || !bytes.Equal(a[12:len(q)], q[12:]) ||
			a[len(q)] != 0xC0 || a[len(q)+1] != 12 || a[len(q)+3] != c2.want || int(a[len(q)+11]) != c2.n {
			t.Errorf("type %d: answer % x", c2.typ, a)
		}
	}
	for _, bad := range [][]byte{{1}, query(1)[:12], append(query(1)[:12:12], 0xC0, 12, 0, 1, 0, 1), func() []byte { q := query(1); q[2] |= 0x80; return q }()} {
		if r.answer(bad) != nil {
			t.Errorf("answered % x", bad)
		}
	}
	if ip := hostIPv4(); ip == nil || ip.To4() == nil {
		t.Errorf("hostIPv4 = %v", ip)
	}
}
