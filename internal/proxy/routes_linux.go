// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package proxy

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

// hostRoutes returns the prefixes of the host's route tables that are the host's own (routes), from one RTM_GETROUTE dump of every table of both families, which needs no privilege (I4). A dump that fails or is cut short refuses.
func hostRoutes() (nets []netip.Prefix, err error) {
	le := binary.NativeEndian // the request: a header, then an all-zero rtmsg, which asks for every family and every table
	req := append(le.AppendUint16(le.AppendUint16(le.AppendUint32(nil, syscall.SizeofNlMsghdr+syscall.SizeofRtMsg), syscall.RTM_GETROUTE), syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP), make([]byte, 8+syscall.SizeofRtMsg)...)
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err == nil {
		defer syscall.Close(fd)
		err = syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	}
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10) // the kernel sends a dump in parts of at most 32 KiB
	for done := false; !done; {
		n, _, err := syscall.Recvfrom(fd, buf, syscall.MSG_TRUNC) // n is the part's whole length, even past the buffer
		if err != nil || n > len(buf) {
			return nil, errors.Join(err, errors.New("route dump: no whole part came back"))
		}
		if nets, done, err = routes(buf[:n], nets); err != nil {
			return nil, err
		}
	}
	return nets, nil
}

// routes parses one part of a route dump, appends to nets the prefixes of its rows that are the host's own, and reports whether the part ends the dump. The host's own are its local rows (RTN_LOCAL, the kernel's local table: its addresses, among them an AnyIP prefix no interface holds) and its on-link unicast rows (no gateway, so a neighbour in the prefix is reached directly; not the default route), of either family and of every table. A malformed message or row, or the kernel's error, refuses the whole dump.
func routes(b []byte, nets []netip.Prefix) ([]netip.Prefix, bool, error) {
	msgs, err := syscall.ParseNetlinkMessage(b)
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg { // the end of the dump, which carries the dump's own error when it had one; an error message; a row too short for its rtmsg
			if m.Header.Type == syscall.NLMSG_DONE && (len(m.Data) < 4 || binary.NativeEndian.Uint32(m.Data) == 0) {
				return nets, true, nil
			}
			return nil, false, errors.New("route dump: refused or malformed")
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		dst, gw := netip.IPv6Unspecified(), false // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags; a row with no destination is the zero prefix of its family
		if m.Data[0] == syscall.AF_INET {
			dst = netip.IPv4Unspecified()
		} else if m.Data[0] != syscall.AF_INET6 {
			continue
		}
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_DST:
				dst, _ = netip.AddrFromSlice(a.Value)
			case syscall.RTA_GATEWAY:
				gw = true
			}
		}
		p := netip.PrefixFrom(dst, int(m.Data[1]))
		if err != nil || !p.IsValid() || dst.Is4() != (m.Data[0] == syscall.AF_INET) {
			return nil, false, errors.New("route dump: malformed row")
		}
		if m.Data[7] == syscall.RTN_LOCAL || m.Data[7] == syscall.RTN_UNICAST && !gw && p.Bits() > 0 {
			nets = append(nets, p)
		}
	}
	return nets, false, err
}
