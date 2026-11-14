// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

// loopbackAddr adds ip/32 to the loopback interface, so that a canary can listen on an address the host does not otherwise own, such as the cloud metadata
// address, and no packet to it can leave the host. It returns the function that removes the address again. It needs CAP_NET_ADMIN, and without it asks sudo
// to run ip(8), which a hosted runner grants without a password. It refuses an address the host already has, so that it only ever removes its own.
func loopbackAddr(ip net.IP) (func(), error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("loopback address %v: want IPv4", ip)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	err = addrRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, lo.Index, ip4, 32)
	if errors.Is(err, syscall.EPERM) {
		if err = ipAddr("add", ip4); err == nil {
			return func() { ipAddr("del", ip4) }, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("add %v to lo: %w ('file exists' means the host already owns it)", ip4, err)
	}
	return func() { addrRequest(syscall.RTM_DELADDR, 0, lo.Index, ip4, 32) }, nil
}

// ipAddr runs "ip addr <verb> ip4/32 dev lo" through sudo, without a prompt.
func ipAddr(verb string, ip4 net.IP) error {
	out, err := exec.Command("sudo", "-n", "ip", "addr", verb, ip4.String()+"/32", "dev", "lo").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo ip addr %s: %v: %s", verb, err, bytes.TrimSpace(out))
	}
	return nil
}

// addrRequest sends one RTM_NEWADDR or RTM_DELADDR for ip4/bits on the interface, scope host.
func addrRequest(typ uint16, flags uint16, index int, ip4 net.IP, bits int) error {
	body := binary.NativeEndian.AppendUint32([]byte{syscall.AF_INET, byte(bits), 0, syscall.RT_SCOPE_HOST}, uint32(index))
	return netlink(typ, flags, attr(attr(body, syscall.IFA_LOCAL, ip4), syscall.IFA_ADDRESS, ip4))
}

// localRoute adds ip4/32 to the local table as a local route out of the interface, as `ip route add local <ip4> dev lo` does: every packet to it is the host's
// own, as to one of its addresses, while no interface holds a prefix it lies in.
func localRoute(index int, ip4 net.IP) error {
	rtm := []byte{syscall.AF_INET, 32, 0, 0, syscall.RT_TABLE_LOCAL, syscall.RTPROT_BOOT, syscall.RT_SCOPE_HOST, syscall.RTN_LOCAL}
	body := binary.NativeEndian.AppendUint32(rtm, 0) // then the flags
	body = attr(attr(body, syscall.RTA_DST, ip4), syscall.RTA_OIF, binary.NativeEndian.AppendUint32(nil, uint32(index)))
	return netlink(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
}

// attr appends one route attribute of type t holding data to b, padded to four bytes.
func attr(b []byte, t uint16, data []byte) []byte {
	n := syscall.SizeofRtAttr + len(data)
	b = binary.NativeEndian.AppendUint16(b, uint16(n))
	b = binary.NativeEndian.AppendUint16(b, t)
	return append(append(b, data...), make([]byte, (4-n%4)%4)...)
}

// netlink sends one request of type typ with flags, holding body, over a route netlink socket and returns the kernel's answer.
func netlink(typ, flags uint16, body []byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2})
	le := binary.NativeEndian
	msg := make([]byte, syscall.SizeofNlMsghdr, syscall.SizeofNlMsghdr+len(body))
	le.PutUint32(msg[0:], uint32(cap(msg)))
	le.PutUint16(msg[4:], typ)
	le.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags)
	le.PutUint32(msg[8:], 1) // sequence
	if err := syscall.Sendto(fd, append(msg, body...), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
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
