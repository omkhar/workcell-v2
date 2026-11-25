// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package proxy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"testing"
)

// TestRoutes feeds routes the parts of a route dump as the kernel sends them (C66, C69): kept are the local rows, among them an AnyIP prefix no interface holds, and the on-link unicast rows of either family and any table, as the /25 on-link beside a /32 on lo in the row rebind-on-link-neighbour-forward; not a gateway, default, broadcast, multicast or unreachable row, nor one of another family. A malformed message or row, or the kernel's error, refuses the dump.
func TestRoutes(t *testing.T) {
	t.Parallel()
	le, u16 := binary.NativeEndian, binary.NativeEndian.AppendUint16
	msg := func(typ uint16, body []byte) []byte { // one netlink message: the header, then body
		return append(u16(u16(le.AppendUint32(nil, uint32(16+len(body))), typ), 0), append(make([]byte, 8), body...)...)
	}
	attr := func(typ uint16, v []byte) []byte { return append(u16(u16(nil, uint16(4+len(v))), typ), v...) }
	row := func(table, typ byte, dst, gw string) []byte { // an RTM_NEWROUTE of the table and type, to dst, through gw when it names one
		p, fam := netip.MustParsePrefix(dst), map[bool]byte{false: syscall.AF_INET, true: syscall.AF_INET6}
		body := append([]byte{fam[p.Addr().Is6()], byte(p.Bits()), 0, 0, table, syscall.RTPROT_BOOT, 0, typ, 0, 0, 0, 0}, attr(syscall.RTA_DST, p.Addr().AsSlice())...)
		if gw != "" {
			body = append(body, attr(syscall.RTA_GATEWAY, netip.MustParseAddr(gw).AsSlice())...)
		}
		return msg(syscall.RTM_NEWROUTE, body)
	}
	local, main, unicast := byte(syscall.RT_TABLE_LOCAL), byte(syscall.RT_TABLE_MAIN), byte(syscall.RTN_UNICAST)
	onLink, anyIP, done := row(main, unicast, "192.175.48.0/25", ""), row(local, syscall.RTN_LOCAL, "192.175.48.0/25", ""), msg(syscall.NLMSG_DONE, le.AppendUint32(nil, 0))
	cases := []struct {
		name string
		part []byte
		want string // the kept prefixes and whether the dump ended, or "error"
	}{
		{"local v4, the AnyIP prefix", anyIP, "[192.175.48.0/25] false"},
		{"local v6", row(local, syscall.RTN_LOCAL, "2001:db8:1::/64", ""), "[2001:db8:1::/64] false"},
		{"on-link beside a /32 on lo", onLink, "[192.175.48.0/25] false"},
		{"via gateway", row(main, unicast, "192.175.48.129/32", "192.175.48.2"), "[] false"},
		{"another table", row(100, unicast, "2620:4f:8000::/64", ""), "[2620:4f:8000::/64] false"},
		{"no destination: the zero prefix of its family", msg(syscall.RTM_NEWROUTE, []byte{syscall.AF_INET, 0, 0, 0, local, 0, 0, syscall.RTN_LOCAL, 0, 0, 0, 0}), "[0.0.0.0/0] false"},
		{"default via gateway, on-link default, broadcast, multicast, unreachable, another family", slices.Concat(row(main, unicast, "0.0.0.0/0", "10.0.2.2"), row(main, unicast, "::/0", ""), row(local, syscall.RTN_BROADCAST, "192.175.48.127/32", ""), row(local, syscall.RTN_MULTICAST, "ff00::/8", ""), row(main, syscall.RTN_UNREACHABLE, "192.175.48.0/25", ""), msg(syscall.RTM_NEWROUTE, append([]byte{28, 20, 0, 0, main, 0, 0, unicast, 0, 0, 0, 0}, attr(syscall.RTA_DST, []byte{0, 1, 0, 0})...))), "[] false"}, // the last of another family, with a label for a destination
		{"prefix too long", slices.Concat(onLink[:17], []byte{33}, onLink[18:]), "error"},
		{"short message", msg(syscall.RTM_NEWROUTE, []byte{syscall.AF_INET, 0, 0, 0}), "error"},
		{"cut message", onLink[:len(onLink)-4], "error"},
		{"cut attribute", slices.Concat(onLink[:28], []byte{32}, onLink[29:]), "error"},
		{"done", done, "[] true"},
		{"done with the dump's error", msg(syscall.NLMSG_DONE, le.AppendUint32(nil, ^uint32(syscall.EINVAL)+1)), "error"},
		{"error message", msg(syscall.NLMSG_ERROR, make([]byte, 20)), "error"},
		{"a whole part", slices.Concat(anyIP, row(main, unicast, "192.175.48.129/32", "192.175.48.2"), row(main, unicast, "2620:4f:8000::/64", ""), done), "[192.175.48.0/25 2620:4f:8000::/64] true"},
	}
	for _, tc := range cases {
		nets, done, err := routes(tc.part, nil)
		if (err != nil) != (tc.want == "error") || err == nil && fmt.Sprint(nets, done) != tc.want {
			t.Errorf("%s: routes = %v, %v, %v; want %s", tc.name, nets, done, err, tc.want)
		}
	}
}
