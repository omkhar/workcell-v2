// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/internal/relay"
	"golang.org/x/sys/unix"
)

// network is the guest side of the network path (ADR-003). The guest has no network device:
// lo comes up, an AnyIP route makes every address local to the guest for each family, so its
// own kernel completes any TCP handshake to a port the init listens on and refuses the rest;
// ICMP echo is ignored; and the resolver is 127.0.0.1, where UDP 53 is relayed. Each failure is
// reported and the rest goes on: whatever is missing, the guest has that much less network,
// which is the safe side. Nothing here enforces anything (A1): the guest shapes traffic, and
// the host admits a stream or not.
func network(cmdline string) error {
	var errs []error
	try := func(what string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
		}
	}
	try("lo up", loUp())
	try("route local 0.0.0.0/0", anyIP(unix.AF_INET))
	try("route local ::/0", anyIP(unix.AF_INET6))
	try("icmp_echo_ignore_all", os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1"), 0))
	try("icmp.echo_ignore_all", os.WriteFile("/proc/sys/net/ipv6/icmp/echo_ignore_all", []byte("1"), 0))
	ports, err := ports(cmdline)
	try("ports", err)
	for _, p := range ports {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(p))) // [::]:p, so IPv4 and IPv6 alike
		try("listen on tcp "+strconv.Itoa(int(p)), err)
		if err == nil {
			go accept(ln)
		}
	}
	pc, err := net.ListenPacket("udp", ":53")
	try("listen on udp 53", err)
	if err == nil {
		go dnsRelay(pc)
	}
	_ = os.MkdirAll("/etc", 0o755)
	try("resolv.conf", os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.1\n"), 0o644))
	return errors.Join(errs...)
}

// loUp sets IFF_UP on lo.
func loUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err == nil {
		err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr)
	}
	if err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// anyIP is "ip route add local <any>/0 dev lo table local" for the family, over route netlink:
// one RTM_NEWROUTE with a zero-length destination and lo as the output interface.
func anyIP(family byte) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	msg := make([]byte, unix.SizeofNlMsghdr+unix.SizeofRtMsg+unix.SizeofRtAttr+4)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:], uint32(len(msg)))
	ne.PutUint16(msg[4:], unix.RTM_NEWROUTE)
	ne.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	ne.PutUint32(msg[8:], 1)        // sequence
	rt := msg[unix.SizeofNlMsghdr:] // family, dst_len 0, src_len, tos, table, protocol, scope, type
	rt[0], rt[4], rt[5], rt[6], rt[7] = family, unix.RT_TABLE_LOCAL, unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL
	a := rt[unix.SizeofRtMsg:]
	ne.PutUint16(a[0:], unix.SizeofRtAttr+4)
	ne.PutUint16(a[2:], unix.RTA_OIF)
	ne.PutUint32(a[4:], uint32(lo.Index))
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr+4 || ne.Uint16(buf[4:]) != unix.NLMSG_ERROR {
		return errors.New("no netlink acknowledgement")
	}
	if code := int32(ne.Uint32(buf[unix.SizeofNlMsghdr:])); code != 0 {
		return unix.Errno(-code)
	}
	return nil
}

// accept relays every connection a listener takes, each on its own vsock stream.
func accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go stream(c)
	}
}

// stream relays one accepted connection. Every address is local, so getsockname of the accepted
// socket is the destination the program dialled; it goes into the header. When the host end is
// gone the vsock connect fails and the program's connection is closed: no byte leaves (I11).
func stream(c net.Conn) {
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	dst := netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	v, err := dial(relay.Port, 0)
	if err != nil {
		return
	}
	if _, err := v.Write(relay.Header{Proto: relay.TCP, Dst: dst}.Encode()); err != nil {
		_ = v.Close()
		return
	}
	// Only Read, Write and Close: io.Copy then never tries splice(2) or sendfile(2) on the vsock.
	splice(c, struct{ io.ReadWriteCloser }{v})
}

// splice copies both ways and ends the stream when either read ends, once what it read is
// written. An end of one direction is carried by closing the whole stream: a vsock SHUT_WR does
// not cross Firecracker (ADR-003), and a host close reaches the guest as a full shutdown.
func splice(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	for _, p := range [][2]io.ReadWriteCloser{{a, b}, {b, a}} {
		wg.Go(func() {
			_, _ = io.Copy(p[0], p[1])
			_ = a.Close()
			_ = b.Close()
		})
	}
	wg.Wait()
}

// dnsRelay carries each datagram on its own vsock stream, a header then one frame, and writes
// the one framed reply back to the sender. A query the host does not answer in time gets nothing.
func dnsRelay(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append(relay.Header{Proto: relay.UDP, Dst: netip.MustParseAddrPort("127.0.0.1:53")}.Encode(), relay.Frame(buf[:n])...)
		go func() {
			v, err := dial(relay.Port, 0)
			if err != nil {
				return
			}
			defer v.Close()
			_ = v.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := v.Write(q); err != nil {
				return
			}
			if a, err := relay.ReadFrame(v); err == nil && len(a) > 0 {
				_, _ = pc.WriteTo(a, from)
			}
		}()
	}
}
