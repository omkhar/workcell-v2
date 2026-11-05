// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"encoding/binary"
	"net"
	"sync"
)

// naiveResolver is the resolver the control sandbox gives its guest, the
// deliberately weak counterpart of the product's host resolver (SPEC T2,
// I3): it answers every query, whatever the name, type or class, with one
// record, as an open resolver that knew every name would. An A question
// gets the test host's own address, an AAAA its loopback, anything else a
// TXT. It stands in for the resolver a plain container would hand on, the
// host's, so that no query of the suite's ever reaches that one (SPEC T8,
// S12). The guest finds it where any program looks, in /etc/resolv.conf,
// which Exec binds over the host's for the run.
type naiveResolver struct {
	pc   net.PacketConn
	host net.IP
	wg   sync.WaitGroup
}

// naiveResolverAddr is where the naive resolver listens: a loopback address
// of its own, since resolv.conf names no port, and port 53 needs root.
const naiveResolverAddr = "127.1.0.53:53"

func listenNaiveResolver(addr string) (*naiveResolver, error) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, err
	}
	r := &naiveResolver{pc: pc, host: hostIPv4()}
	r.wg.Go(r.serve)
	return r, nil
}

func (r *naiveResolver) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if a := r.answer(buf[:n]); a != nil {
			r.pc.WriteTo(a, from)
		}
	}
}

// answer builds the reply to a query: its header with QR, RD and RA set,
// its question as it came, and one record for the question's own name
// (a pointer to offset 12). A message it cannot read gets nothing.
func (r *naiveResolver) answer(q []byte) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:]) == 0 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		if q[i]&0xC0 != 0 {
			return nil
		}
		i += 1 + int(q[i])
	}
	if i+5 > len(q) {
		return nil
	}
	typ := binary.BigEndian.Uint16(q[i+1:])
	var data []byte
	switch typ {
	case 1, 255: // A, ANY
		typ, data = 1, r.host.To4()
	case 28: // AAAA
		data = net.IPv6loopback
	default:
		typ, data = 16, []byte("\x05naive")
	}
	a := make([]byte, 0, i+5+12+len(data))
	a = append(a, q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
	a = append(a, q[12:i+5]...)
	a = append(a, 0xC0, 12)
	a = binary.BigEndian.AppendUint16(a, typ)
	a = append(a, 0, 1, 0, 0, 0, 60)
	a = binary.BigEndian.AppendUint16(a, uint16(len(data)))
	return append(a, data...)
}

func (r *naiveResolver) stop() {
	r.pc.Close()
	r.wg.Wait()
}

// hostIPv4 is the host's first non-loopback IPv4 address, where the
// judges' canaries listen, or loopback when it has none.
func hostIPv4() net.IP {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				return ipn.IP.To4()
			}
		}
	}
	return net.IPv4(127, 0, 0, 1).To4()
}
