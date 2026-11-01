// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// loopbackAddr adds ip/32 to the loopback interface, so that a canary can
// listen on an address the host does not otherwise own, such as the cloud
// metadata address, and no packet to it can leave the host. It returns the
// function that removes the address again. It needs CAP_NET_ADMIN and refuses
// an address the host already has, so that it only ever removes its own.
func loopbackAddr(ip net.IP) (func(), error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("loopback address %v: want IPv4", ip)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	if err := addrRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, lo.Index, ip4); err != nil {
		return nil, fmt.Errorf("add %v to lo: %w (needs CAP_NET_ADMIN; 'file exists' means the host already owns it)", ip4, err)
	}
	return func() { addrRequest(syscall.RTM_DELADDR, 0, lo.Index, ip4) }, nil
}

// addrRequest sends one RTM_NEWADDR or RTM_DELADDR for ip4/32 on the interface
// over a route netlink socket and returns the kernel's answer.
func addrRequest(typ uint16, flags uint16, index int, ip4 net.IP) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2})
	const attr = syscall.SizeofRtAttr + 4
	msg := make([]byte, syscall.SizeofNlMsghdr+syscall.SizeofIfAddrmsg+2*attr)
	le := binary.NativeEndian
	le.PutUint32(msg[0:], uint32(len(msg)))
	le.PutUint16(msg[4:], typ)
	le.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags)
	le.PutUint32(msg[8:], 1) // sequence
	ifa := msg[syscall.SizeofNlMsghdr:]
	ifa[0], ifa[1], ifa[3] = syscall.AF_INET, 32, syscall.RT_SCOPE_HOST // family, prefix length, scope
	le.PutUint32(ifa[4:], uint32(index))
	a := ifa[syscall.SizeofIfAddrmsg:]
	for i, t := range []uint16{syscall.IFA_LOCAL, syscall.IFA_ADDRESS} {
		le.PutUint16(a[i*attr:], attr)
		le.PutUint16(a[i*attr+2:], t)
		copy(a[i*attr+syscall.SizeofRtAttr:], ip4)
	}
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			if code := int32(le.Uint32(m.Data)); code != 0 {
				return syscall.Errno(-code)
			}
			return nil
		}
	}
	return errors.New("no acknowledgement from netlink")
}
