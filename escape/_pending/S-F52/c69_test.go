// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Reproduces C69 of S-1006 sweep 3 (I4): an address the host owns through the kernel's local table alone (an AnyIP route, `local 192.175.48.0/25 dev lo`, no interface address, no main-table route) is // not among hostNets, so connect dials it and the kernel delivers the guest's bytes to a listener on the host. It fails until fix unit S-F52 lands; S-F52 moves it to internal/proxy/c69_test.go.
package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// TestC69AnyIPLocalRoute runs itself again in a network namespace of its own (through a user namespace where one may be made, else as root through sudo), lays the host out there and asserts I4.
func TestC69AnyIPLocalRoute(t *testing.T) {
	if os.Args[len(os.Args)-1] != "c69-inside" {
		args := []string{os.Args[0], "-test.run=^" + t.Name() + "$", "-test.v", "c69-inside"}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET, UidMappings: []syscall.SysProcIDMap{{HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{HostID: os.Getgid(), Size: 1}}}
		out, err := cmd.CombinedOutput()
		if err != nil && cmd.ProcessState == nil { // no user namespace here: as root instead
			out, err = exec.Command("sudo", append([]string{"-n", "unshare", "-n"}, args...)...).CombinedOutput()
		}
		if err != nil {
			t.Fatalf("%s%v", out, err)
		}
		return
	}
	le, lo := binary.NativeEndian, need(net.InterfaceByName("lo"))
	idx := le.AppendUint32(nil, uint32(lo.Index))
	a4 := func(typ uint16, v []byte) []byte { return append(le.AppendUint16(le.AppendUint16(nil, 8), typ), v...) }
	nl(t, syscall.RTM_SETLINK, le.AppendUint32(le.AppendUint32(append([]byte{0, 0, 0, 0}, idx...), 1), 1)) // lo up
	nl(t, syscall.RTM_NEWROUTE, append(append([]byte{syscall.AF_INET, 25, 0, 0, syscall.RT_TABLE_LOCAL, syscall.RTPROT_BOOT, syscall.RT_SCOPE_HOST, syscall.RTN_LOCAL, 0, 0, 0, 0}, a4(syscall.RTA_DST, []byte{192, 175, 48, 0})...), a4(syscall.RTA_OIF, idx)...))
	ip := []byte{192, 175, 48, 129} // the control arm: 192.175.48.128/25 as an interface address
	nl(t, syscall.RTM_NEWADDR, append(append(append([]byte{syscall.AF_INET, 25, 0, 0}, idx...), a4(syscall.IFA_LOCAL, ip)...), a4(syscall.IFA_ADDRESS, ip)...))
	ln := need(net.Listen("tcp", "192.175.48.6:8443")) // the canary, at an address the host owns through the local table alone
	answer := netip.MustParseAddr("192.175.48.6")
	p := New(nil, nil)
	p.lookup = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{answer}, nil }
	switch conn, reason := p.connect("api.example.com", 8443); reason {
	case "dial_failed":
		t.Fatalf("layout: the canary at %s cannot be dialled", answer)
	case "":
		conn.Write([]byte("GET /secret HTTP/1.0\r\n\r\n"))
		b := make([]byte, 64)
		n, _ := need(ln.Accept()).Read(b)
		t.Errorf("I4: connect admitted %s, the host's own through the local table alone, and the host's listener read %q", answer, b[:n])
	}
	answer = netip.MustParseAddr("192.175.48.130")
	if _, reason := p.connect("api.example.com", 8443); reason != "blocked_address" {
		t.Errorf("control: %s, inside an interface address's prefix, got %q, want blocked_address", answer, reason)
	}
}
func need[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// nl sends one route netlink request holding body and fails the test on the kernel's refusal.
func nl(t *testing.T, typ uint16, body []byte) {
	le, fd := binary.NativeEndian, need(syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE))
	msg := le.AppendUint16(le.AppendUint16(le.AppendUint32(nil, uint32(16+len(body))), typ), syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE)
	need(0, syscall.Sendto(fd, append(append(msg, make([]byte, 8)...), body...), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}))
	buf := make([]byte, 64)
	if _, _, err := syscall.Recvfrom(fd, buf, 0); err != nil || le.Uint32(buf[16:]) != 0 {
		t.Fatalf("netlink %d: %v %v", typ, err, syscall.Errno(-int32(le.Uint32(buf[16:]))))
	}
}
