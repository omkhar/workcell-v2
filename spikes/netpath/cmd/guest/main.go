// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command guest is PID 1 of the netpath spike's microVM. It dials the host on
// vsock port 5000 and answers one key=value line per command line the host
// sends. After "setup" every address is local to the guest (an AnyIP route on
// lo), so the guest's own kernel terminates every TCP connection; each one
// accepted on a port of workcell.ports= is relayed to the host on its own
// vsock connection to port 5001 behind a header naming the original
// destination, and each DNS datagram to 127.0.0.1:53 likewise. It never
// returns: a PID 1 that exits is a kernel panic.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/escape/suite"
	"github.com/omkhar/workcell/v2/spikes/netpath/relay"
	"golang.org/x/sys/unix"
)

const icmpIgnore = "/proc/sys/net/ipv4/icmp_echo_ignore_all"

var symbols = []string{"NETFILTER", "NF_TABLES", "IP_NF_IPTABLES", "NETFILTER_XT_TARGET_REDIRECT",
	"NETFILTER_XT_TARGET_TPROXY", "TUN", "DUMMY", "IP_MULTIPLE_TABLES", "VETH", "VSOCKETS",
	"VIRTIO_VSOCKETS", "IKCONFIG_PROC"}

var (
	mu      sync.Mutex
	vsockUS []int64 // per relayed stream since the last "connect": vsock connect plus header write
	lastDst string  // getsockname of the last accepted stream
	floods  []*os.File
)

func main() {
	for _, d := range []string{"/dev", "/proc", "/sys", "/etc"} {
		_ = os.MkdirAll(d, 0o755)
	}
	mount("devtmpfs", "/dev", "devtmpfs")
	if fd, err := unix.Open("/dev/console", unix.O_RDWR|unix.O_NOCTTY, 0); err == nil {
		_ = unix.Dup3(fd, 1, 0)
		_ = unix.Dup3(fd, 2, 0)
	}
	mount("proc", "/proc", "proc")
	mount("sysfs", "/sys", "sysfs")
	fmt.Fprintln(os.Stderr, "guest:", serve())
	for {
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART) // reboot=k: Firecracker exits
		time.Sleep(time.Second)
	}
}

func mount(src, dir, fs string) {
	if err := unix.Mount(src, dir, fs, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
		fmt.Fprintln(os.Stderr, "guest: mount", dir, err)
	}
}

// dial connects to the host (CID 2) on port, retrying for retry while the
// device probes (as cmd/workcell-init's connect). The socket is non-blocking
// so that deadlines work on it.
func dial(port uint32, retry time.Duration) (*os.File, error) {
	var err error
	for end := time.Now().Add(retry); ; time.Sleep(20 * time.Millisecond) {
		var fd int
		if fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err == nil {
			if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err == nil {
				if err = unix.SetNonblock(fd, true); err == nil {
					return os.NewFile(uintptr(fd), "vsock"), nil
				}
			}
			_ = unix.Close(fd)
		}
		if !time.Now().Before(end) {
			return nil, err
		}
	}
}

func serve() error {
	c, err := dial(relay.Control, 5*time.Second)
	if err != nil {
		return err
	}
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if _, err := io.WriteString(c, relay.Join(run(f[0], f[1:]))); err != nil || f[0] == "quit" {
			return err
		}
	}
}

func run(cmd string, args []string) (out []string) {
	defer func() {
		if r := recover(); r != nil {
			out = []string{relay.Pair("error", fmt.Sprint("panic: ", r))}
		}
	}()
	n := 1
	if len(args) > 1 {
		n, _ = strconv.Atoi(args[1])
	}
	switch {
	case cmd == "features":
		return features()
	case cmd == "lo-only" && len(args) == 1:
		c, err := net.DialTimeout("tcp", args[0], time.Second)
		if err == nil {
			c.Close()
		}
		return []string{relay.Pair("lo_only_connect", errno(err))}
	case cmd == "setup":
		return setup()
	case cmd == "connect" && len(args) == 2 && n > 0:
		return connect(args[0], n)
	case cmd == "connect-refused" && len(args) == 1:
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", args[0], 2*time.Second)
		d := time.Since(t0)
		if err == nil {
			c.Close()
		}
		return []string{relay.Pair("refused_errno", errno(err)), relay.Pair("refused_us", d.Microseconds())}
	case cmd == "send" && len(args) == 2 && n > 0:
		return send(args[0], n)
	case cmd == "half-close" && len(args) == 1:
		return halfClose(args[0])
	case cmd == "dns" && len(args) == 1:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t0 := time.Now()
		addrs, err := net.DefaultResolver.LookupHost(ctx, args[0])
		d := time.Since(t0)
		if err != nil {
			return []string{relay.Err("dns_answer", err), relay.Pair("dns_rtt_ms", ms(d))}
		}
		return []string{relay.Pair("dns_answer", strings.Join(addrs, ",")), relay.Pair("dns_rtt_ms", ms(d))}
	case cmd == "probe" && len(args) >= 1:
		t, ok := suite.Lookup(args[0])
		if !ok {
			break
		}
		r := t.Probe(args[1:])
		return []string{relay.Pair("status", r.Status), relay.Pair("detail", r.Detail)}
	case cmd == "icmp" && len(args) == 1:
		return []string{result("icmp_echo_ignore_all", os.WriteFile(icmpIgnore, []byte(args[0]), 0))}
	case cmd == "flood" && len(args) == 1:
		n, _ = strconv.Atoi(args[0])
		return flood(n)
	case cmd == "release":
		mu.Lock()
		defer mu.Unlock()
		for _, f := range floods {
			f.Close()
		}
		out = []string{relay.Pair("released", len(floods))}
		floods = nil
		return out
	case cmd == "quit":
		return []string{relay.Pair("bye", 1)}
	}
	return []string{relay.Pair("error", "bad command "+cmd+" "+strings.Join(args, " "))}
}

func features() []string {
	var out []string
	text, err := kernelConfig()
	for _, s := range symbols {
		if err != nil {
			out = append(out, relay.Err("cfg_"+s, err))
		} else {
			out = append(out, relay.Pair("cfg_"+s, relay.Config(text, s)))
		}
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err == nil {
		f.Close()
	}
	out = append(out, relay.Pair("tun_dev", errno(err)))
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err == nil {
		unix.Close(fd)
	}
	var u unix.Utsname
	_ = unix.Uname(&u)
	return append(out, result("netlink_route", err), relay.Pair("kernel", unix.ByteSliceToString(u.Release[:])))
}

func kernelConfig() (string, error) {
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return "", err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(z)
	return string(b), err
}

// setup brings lo up, makes every address local, listens on the relayed ports
// and on UDP 53, and points the resolver at 127.0.0.1.
func setup() []string {
	t0 := time.Now()
	out := []string{result("lo_up", loUp()), result("anyip4_route", anyIP(unix.AF_INET)),
		result("anyip6_route", anyIP(unix.AF_INET6)), result("icmp_ignore_all", os.WriteFile(icmpIgnore, []byte("1"), 0))}
	cmdline, err := os.ReadFile("/proc/cmdline")
	var ports []uint16
	if err == nil {
		ports, err = relay.Ports(string(cmdline))
	}
	if err != nil {
		out = append(out, relay.Err("ports", err))
	}
	for _, p := range ports {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(p))) // [::], dual-stack
		out = append(out, result("listen_"+strconv.Itoa(int(p)), err))
		if err == nil {
			go accept(ln)
		}
	}
	pc, err := net.ListenPacket("udp", ":53")
	out = append(out, result("listen_udp53", err))
	if err == nil {
		go dnsRelay(pc)
	}
	out = append(out, result("resolv_conf", os.WriteFile("/etc/resolv.conf", []byte("nameserver 127.0.0.1\n"), 0o644)))
	return append([]string{relay.Pair("setup_ms", ms(time.Since(t0)))}, out...)
}

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

// anyIP is "ip route add local <any>/0 dev lo table local" for the family, over
// route netlink (the layout of escape/suite's addrRequest).
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

func accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go stream(c)
	}
}

// stream relays one accepted connection; its local address is the destination
// the guest's program dialled.
func stream(c net.Conn) {
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	dst := netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	t0 := time.Now()
	v, err := dial(relay.Port, 0)
	if err == nil {
		if _, err = v.Write(relay.Header{Proto: relay.TCP, Dst: dst}.Encode()); err != nil {
			v.Close()
		}
	}
	d := time.Since(t0)
	mu.Lock()
	lastDst = dst.String()
	if err == nil {
		vsockUS = append(vsockUS, d.Microseconds())
	}
	mu.Unlock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guest: relay", dst, err)
		return
	}
	// Only Read, Write and Close: io.Copy then never tries splice(2) into the vsock.
	relay.Splice(c, struct{ io.ReadWriteCloser }{v})
}

// dnsRelay sends each datagram on its own vsock connection and returns the one reply.
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

// connect makes n sequential connections to addr; each reads the byte the host's
// canary sends first. connect_us is dial start to that byte.
func connect(addr string, n int) []string {
	mu.Lock()
	vsockUS = nil
	mu.Unlock()
	var us []int64
	for i := range n {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = io.ReadFull(c, make([]byte, 1))
			us = append(us, time.Since(t0).Microseconds())
			c.Close()
		}
		if err != nil {
			return []string{relay.Pair("connect_us", fmt.Sprintf("err:%s@%d", errno(err), i))}
		}
	}
	p50, lo, hi := relay.Stats(us)
	mu.Lock()
	defer mu.Unlock()
	v50, _, _ := relay.Stats(vsockUS)
	return []string{relay.Pair("connect_p50_us", p50), relay.Pair("connect_min_us", lo), relay.Pair("connect_max_us", hi),
		relay.Pair("vsock_connect_p50_us", v50), relay.Pair("vsock_samples", len(vsockUS)), relay.Pair("getsockname_dst", lastDst)}
}

// send writes mib MiB on one connection and closes it. The host's sink times
// the bytes as they arrive.
func send(addr string, mib int) []string {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return []string{relay.Err("guest_send_mib_s", err)}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	buf := make([]byte, 1<<20)
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return []string{relay.Err("guest_send_mib_s", err)}
	}
	t0 := time.Now()
	for range mib {
		if _, err := c.Write(buf); err != nil {
			return []string{relay.Err("guest_send_mib_s", err)}
		}
	}
	return []string{relay.Pair("guest_send_mib_s", fmt.Sprintf("%.1f", float64(mib)/time.Since(t0).Seconds()))}
}

// halfClose asks whether Firecracker passes a guest's SHUT_WR on to the host's
// stream: after the sink's byte, the guest shuts its sending side down and
// waits for the host's EOF, which comes only if the sink saw EOF first.
func halfClose(addr string) []string {
	v, err := dial(relay.Port, 0)
	if err != nil {
		return []string{relay.Err("vsock_shut_wr", err)}
	}
	defer v.Close()
	_ = v.SetDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 1)
	if _, err = v.Write(relay.Header{Proto: relay.TCP, Dst: netip.MustParseAddrPort(addr)}.Encode()); err == nil {
		_, err = io.ReadFull(v, b)
	}
	if err == nil {
		rc, _ := v.SyscallConn()
		_ = rc.Control(func(fd uintptr) { err = unix.Shutdown(int(fd), unix.SHUT_WR) })
	}
	if err != nil {
		return []string{relay.Err("vsock_shut_wr", err)}
	}
	t0 := time.Now()
	_, err = v.Read(b)
	state := "propagated"
	if errors.Is(err, os.ErrDeadlineExceeded) {
		state = "not-propagated"
	}
	return []string{relay.Pair("vsock_shut_wr", state), relay.Pair("vsock_shut_wr_read", errno(err)),
		relay.Pair("vsock_shut_wr_ms", ms(time.Since(t0)))}
}

// flood opens n vsock connections to the relay port, each with a valid header
// and 64 KiB of data, and holds them until "release".
func flood(n int) []string {
	data := append(relay.Header{Proto: relay.TCP, Dst: netip.MustParseAddrPort("198.51.100.9:443")}.Encode(), make([]byte, 64<<10)...)
	first := "none"
	ok := 0
	t0 := time.Now()
	for i := range n {
		v, err := dial(relay.Port, 0)
		if err == nil {
			mu.Lock()
			floods = append(floods, v)
			mu.Unlock()
			_ = v.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, err = v.Write(data)
		}
		if err != nil {
			first = fmt.Sprintf("%s@%d", errno(err), i)
			break
		}
		ok++
	}
	return []string{relay.Pair("flood_ok", ok), relay.Pair("flood_first_err", first), relay.Pair("flood_ms", time.Since(t0).Milliseconds())}
}

func result(key string, err error) string {
	if err != nil {
		return relay.Pair(key, "err:"+errno(err))
	}
	return relay.Pair(key, "ok")
}

// errno names the error number in err, or says "ok" for no error.
func errno(err error) string {
	var e syscall.Errno
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &e) && unix.ErrnoName(e) != "":
		return unix.ErrnoName(e)
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	return err.Error()
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
