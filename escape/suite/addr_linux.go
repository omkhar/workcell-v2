// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os/exec"
	"syscall"
)

// loopbackAddr adds ip/32 to the loopback interface, so that a canary can listen on an address the host does not otherwise own, such as the cloud metadata address, and no packet to it can leave the host. It returns the function that removes the address again. It needs CAP_NET_ADMIN, and without it asks sudo to run ip(8), which a hosted runner grants without a password. It refuses an address the host already has, so that it only ever removes its own.
func loopbackAddr(ip net.IP) (func(), error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("loopback address %v: want IPv4", ip)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	err = addrRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, lo.Index, ip4, 32, syscall.RT_SCOPE_HOST)
	if errors.Is(err, syscall.EPERM) {
		if err = ipAddr("add", ip4); err == nil {
			return func() { ipAddr("del", ip4) }, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("add %v to lo: %w ('file exists' means the host already owns it)", ip4, err)
	}
	return func() { addrRequest(syscall.RTM_DELADDR, 0, lo.Index, ip4, 32, syscall.RT_SCOPE_HOST) }, nil
}

// ipAddr runs "ip addr <verb> ip4/32 dev lo" through sudo, without a prompt.
func ipAddr(verb string, ip4 net.IP) error {
	out, err := exec.Command("sudo", "-n", "ip", "addr", verb, ip4.String()+"/32", "dev", "lo").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo ip addr %s: %v: %s", verb, err, bytes.TrimSpace(out))
	}
	return nil
}

// addrRequest sends one RTM_NEWADDR or RTM_DELADDR for ip4/bits on the interface, of that scope.
func addrRequest(typ, flags uint16, index int, ip4 net.IP, bits int, scope byte) error {
	body := binary.NativeEndian.AppendUint32([]byte{syscall.AF_INET, byte(bits), 0, scope}, uint32(index))
	_, err := netlink(typ, flags, attr(attr(body, syscall.IFA_LOCAL, ip4), syscall.IFA_ADDRESS, ip4))
	return err
}

// route adds dst/bits to the table as a route of that scope and type out of the interface, through the gateway gw when one is given, as `ip route add <dst>/<bits> dev <if> [scope link] [via <gw>]` does.
func route(index int, dst net.IP, bits int, table, scope, typ byte, gw net.IP) error {
	rtm := []byte{syscall.AF_INET, byte(bits), 0, 0, table, syscall.RTPROT_BOOT, scope, typ}
	body := binary.NativeEndian.AppendUint32(rtm, 0) // then the flags
	body = attr(attr(body, syscall.RTA_DST, dst), syscall.RTA_OIF, binary.NativeEndian.AppendUint32(nil, uint32(index)))
	if gw != nil {
		body = attr(body, syscall.RTA_GATEWAY, gw)
	}
	_, err := netlink(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
	return err
}

// routed asks the kernel how a packet to ip4 leaves this namespace, as `ip route get` does: the table and type of the route it would take, and its gateway, nil when it has none.
func routed(ip4 net.IP) (table, typ byte, gw net.IP, err error) {
	rtm := append([]byte{syscall.AF_INET}, make([]byte, syscall.SizeofRtMsg-1)...)
	data, err := netlink(syscall.RTM_GETROUTE, 0, attr(rtm, syscall.RTA_DST, ip4))
	if err == nil && len(data) < syscall.SizeofRtMsg {
		err = errors.New("no route came back from netlink")
	}
	if err != nil {
		return 0, 0, nil, err
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE}, Data: data})
	for _, a := range attrs {
		if a.Attr.Type == syscall.RTA_GATEWAY {
			gw = net.IP(a.Value)
		}
	}
	return data[4], data[7], gw, err
}

// veth makes a veth pair, as `ip link add <name> type veth peer name <peer> netns <pid>` does: name here, peer in the network namespace of the process pid.
func veth(name, peer string, pid int) error {
	info := make([]byte, syscall.SizeofIfInfomsg)
	far := attr(attr(append([]byte(nil), info...), syscall.IFLA_IFNAME, []byte(peer+"\x00")), syscall.IFLA_NET_NS_PID, binary.NativeEndian.AppendUint32(nil, uint32(pid)))
	link := attr(attr(nil, unix.IFLA_INFO_KIND, []byte("veth")), unix.IFLA_INFO_DATA, attr(nil, 1, far)) // 1: VETH_INFO_PEER
	_, err := netlink(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, attr(attr(info, syscall.IFLA_IFNAME, []byte(name+"\x00")), syscall.IFLA_LINKINFO, link))
	return err
}

// attr appends one route attribute of type t holding data to b, padded to four bytes.
func attr(b []byte, t uint16, data []byte) []byte {
	n := syscall.SizeofRtAttr + len(data)
	b = binary.NativeEndian.AppendUint16(b, uint16(n))
	b = binary.NativeEndian.AppendUint16(b, t)
	return append(append(b, data...), make([]byte, (4-n%4)%4)...)
}

// netlink sends one request of type typ with flags, holding body, over a route netlink socket and returns the kernel's answer: the body of the message it sent back, or none for a bare acknowledgement.
func netlink(typ, flags uint16, body []byte) ([]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2})
	le, msg := binary.NativeEndian, make([]byte, syscall.SizeofNlMsghdr, syscall.SizeofNlMsghdr+len(body))
	le.PutUint32(msg[0:], uint32(cap(msg)))
	le.PutUint16(msg[4:], typ)
	le.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags)
	le.PutUint32(msg[8:], 1) // sequence
	if err := syscall.Sendto(fd, append(msg, body...), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.NLMSG_ERROR {
			return m.Data, nil
		}
		if len(m.Data) >= 4 {
			if code := int32(le.Uint32(m.Data)); code != 0 {
				return nil, syscall.Errno(-code)
			}
			return nil, nil
		}
	}
	return nil, errors.New("no acknowledgement from netlink")
}
