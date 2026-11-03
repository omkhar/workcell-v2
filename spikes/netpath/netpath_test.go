// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Package netpath is the U-300 spike: how a guest's connections reach the host
// proxy (ADR-003). The guest terminates TCP itself on an AnyIP route and relays
// each stream over its own vsock connection. Findings are in notes.md.
package netpath

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/vmm"
	"github.com/omkhar/workcell/v2/internal/vmm/firecracker"
	"github.com/omkhar/workcell/v2/spikes/netpath/relay"
)

const (
	hardLimit  = 140 * time.Second // from boot; the VM is killed and the test fails
	dst        = "198.51.100.7"    // TEST-NET-2, routed nowhere; the guest's AnyIP route makes it local
	sendMiB    = 32
	floodN     = 1100 // above Firecracker's 1023 connections per vsock device
	maxStreams = 1024 // the host relay's bound on concurrent streams
)

func TestNetpath(t *testing.T) {
	needKVM(t)
	start := time.Now()
	logf := func(format string, a ...any) { t.Logf("netpath "+format, a...) }

	// Inputs: the pinned Firecracker and kernel A, and the guest, at once.
	dl := t.TempDir()
	var fc, kernel, initrd string
	var errs [3]error
	var wg sync.WaitGroup
	wg.Go(func() {
		var tgz string
		if tgz, errs[0] = download(dl, fcURL, "firecracker.tgz", fcSHA256); errs[0] == nil {
			fc = filepath.Join(dl, "firecracker")
			errs[0] = untar(tgz, fcMember, fc)
		}
	})
	wg.Go(func() { kernel, errs[1] = download(dl, kernelURL, "vmlinux", kernelSHA) })
	wg.Go(func() { initrd, errs[2] = guestInitramfs(t.TempDir()) })
	wg.Wait()
	if err := errors.Join(errs[:]...); err != nil {
		t.Fatal(err)
	}
	prepS := time.Since(start).Seconds()

	// "go test ./spikes/..." runs fcch.test and libkrun.test beside this one; their
	// boots and builds would perturb the timings and MemAvailable.
	phase := time.Now()
	others := func() []string {
		return procs("comm", func(s string) bool { return s == "fcch.test" || s == "libkrun.test" })
	}
	for len(others()) > 0 && time.Since(phase) < 200*time.Second {
		time.Sleep(time.Second)
	}
	waitedS := time.Since(phase).Seconds()

	sink := newSink(t)
	dir := shortDir(t)
	// The relay port bypasses Machine.Listen on purpose: Listen takes one connection
	// and this port takes one per stream. Firecracker dials <uds_path>_<port>.
	ln, err := net.Listen("unix", filepath.Join(dir, "vsock_"+fmt.Sprint(relay.Port)))
	if err != nil {
		t.Fatal(err)
	}
	rl := &relayHost{ln: ln, canary: sink.addr()}
	go rl.serve()
	t.Cleanup(func() { _ = ln.Close() })

	console, err := os.Create(filepath.Join(t.TempDir(), "console.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = console.Close()
		if b, _ := os.ReadFile(console.Name()); t.Failed() {
			t.Logf("console:\n%s", b[max(0, len(b)-4096):])
		}
	})
	m := firecracker.New(vmm.Config{Binary: fc, Kernel: kernel, Initrd: initrd, Cmdline: "workcell.ports=443,80",
		CPUs: 2, MemoryMiB: 512, CID: 3, Console: console, Dir: dir})
	defer m.Close()
	ctl, err := m.Listen(relay.Control)
	if err != nil {
		t.Fatal(err)
	}
	guard := time.AfterFunc(hardLimit, func() {
		t.Errorf("netpath hard limit %v reached: the VM is killed", hardLimit)
		_ = m.Kill()
	})
	defer guard.Stop()
	t0 := time.Now()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = ctl.(interface{ SetDeadline(time.Time) error }).SetDeadline(t0.Add(10 * time.Second))
	conn, err := ctl.Accept()
	if err != nil {
		t.Fatalf("no control connection from the guest: %v", err)
	}
	bootMS := time.Since(t0).Milliseconds()
	defer conn.Close()
	g := &guest{c: conn, r: bufio.NewReader(conn)}

	// Each step logs its own line; a failed step logs key=err:... and the next one runs.
	step := func(prefix, key string, limit time.Duration, cmd ...string) map[string]string {
		kv, line, err := g.ask(limit, cmd...)
		if err != nil {
			t.Log("netpath " + relay.Err(prefix+key, err))
			return nil
		}
		t.Log("netpath " + prefix + strings.ReplaceAll(line, " ", " "+prefix))
		return kv
	}
	step("", "cfg", 10*time.Second, "features")
	step("", "lo_only_connect", 5*time.Second, "lo-only", "203.0.113.7:443")
	step("", "setup_ms", 10*time.Second, "setup")
	before := rl.streams.Load()
	if kv := step("", "connect_p50_us", 30*time.Second, "connect", dst+":443", "20"); kv != nil {
		logf("getsockname_match=%t hdr_dst=%s relay_streams=%d", kv["getsockname_dst"] == dst+":443", rl.lastDst(),
			rl.streams.Load()-before)
	}
	if kv := step("v6_", "connect_p50_us", 10*time.Second, "connect", "[2001:db8::7]:443", "1"); kv != nil {
		logf("v6_hdr_dst=%s", rl.lastDst())
	}
	step("", "refused_errno", 10*time.Second, "connect-refused", dst+":8443")
	if kv := step("", "guest_send_mib_s", 90*time.Second, "send", dst+":443", fmt.Sprint(sendMiB)); kv != nil {
		n, d := sink.last()
		for end := time.Now().Add(10 * time.Second); n < sendMiB<<20 && time.Now().Before(end); n, d = sink.last() {
			time.Sleep(10 * time.Millisecond)
		}
		logf("throughput_mib_s=%.1f sink_bytes=%d", float64(n)/(1<<20)/d.Seconds(), n)
	}
	step("", "vsock_shut_wr", 10*time.Second, "half-close", dst+":443")
	if kv := step("", "dns_answer", 10*time.Second, "dns", "canary.test"); kv != nil {
		logf("host_dns_queries=%s", rl.dnsQueries())
	}
	i2(t, g, rl)
	floodStep(t, g, rl, dir)
	step("after_flood_", "connect_p50_us", 10*time.Second, "connect", dst+":443", "1")

	step("", "bye", 5*time.Second, "quit")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t1 := time.Now()
	vmmErr := m.Wait(ctx)
	logf("vmm_exit=%s teardown_ms=%d relay_bad_headers=%d relay_rejected=%d", relay.Clean(fmt.Sprint(vmmErr)),
		time.Since(t1).Milliseconds(), rl.bad.Load(), rl.rejected.Load())
	logf("boot_ms=%d prep_s=%.1f waited_s=%.1f others_left=%d test_s=%.1f", bootMS, prepS, waitedS, len(others()),
		time.Since(start).Seconds())
}

// i2 runs escape/suite's five I2 probes in the guest against canaries on the
// host's own address, then the ICMP probe again with icmp_echo_ignore_all 0.
func i2(t *testing.T, g *guest, rl *relayHost) {
	host, err := hostIPv4()
	if err != nil {
		t.Log("netpath " + relay.Err("i2", err))
		return
	}
	for _, c := range []struct{ name, net string }{
		{"raw-ip-odd-port-tcp4", "tcp4"}, {"ipv4-mapped-ipv6-tcp", "tcp4"},
		{"udp4-datagram", "udp4"}, {"quic-initial", "udp4"}, {"icmp-echo", ""},
	} {
		target, saw, stop := host, "na", func() int64 { return 0 }
		if c.net != "" {
			cn, err := listenCanary(c.net, host)
			if err != nil {
				t.Log("netpath " + relay.Err("i2_"+c.name, err))
				continue
			}
			target, stop = cn.addr, cn.stop
		}
		if c.name == "ipv4-mapped-ipv6-tcp" {
			_, port, _ := net.SplitHostPort(target)
			target = net.JoinHostPort("::ffff:"+host, port)
		}
		before := rl.streams.Load()
		kv, _, err := g.ask(15*time.Second, "probe", c.name, target, token())
		time.Sleep(200 * time.Millisecond) // a datagram in flight
		if n := stop(); c.net != "" {
			saw = fmt.Sprint(n)
		}
		if err != nil {
			t.Log("netpath " + relay.Err("i2_"+c.name, err))
			continue
		}
		t.Logf("netpath i2_%s=%s|host_saw=%s relay_saw=%d detail=%s", c.name, kv["status"], saw,
			rl.streams.Load()-before, kv["detail"])
	}
	for _, v := range []string{"1", "0"} {
		_, _, err := g.ask(5*time.Second, "icmp", v)
		var kv map[string]string
		if err == nil {
			kv, _, err = g.ask(15*time.Second, "probe", "icmp-echo", host, token())
		}
		if err != nil {
			t.Log("netpath " + relay.Err("icmp_ignore"+v, err))
			continue
		}
		t.Logf("netpath icmp_ignore%s=%s", v, kv["status"])
	}
	if _, _, err := g.ask(5*time.Second, "icmp", "1"); err != nil {
		t.Log("netpath " + relay.Err("icmp_restore", err))
	}
}

// floodStep has the guest hold as many relayed streams as it can open and
// measures what they cost the host.
func floodStep(t *testing.T, g *guest, rl *relayHost, dir string) {
	fcPID := "none" // the Firecracker process is the one whose command line names dir
	if p := procs("cmdline", func(s string) bool { return strings.Contains(s, dir+"/") }); len(p) == 1 {
		fcPID = p[0]
	}
	snap := func() (host, fc, avail int64) { // KiB; -1 where a file could not be read
		host, fc, avail = -1, -1, -1
		if v, err := kib("/proc/self/status", "VmRSS"); err == nil {
			host = v
		}
		if v, err := kib("/proc/"+fcPID+"/status", "VmRSS"); err == nil {
			fc = v
		}
		if v, err := kib("/proc/meminfo", "MemAvailable"); err == nil {
			avail = v
		}
		return host, fc, avail
	}
	h0, f0, a0 := snap()
	_, line, err := g.ask(60*time.Second, "flood", fmt.Sprint(floodN))
	if err != nil {
		t.Log("netpath " + relay.Err("flood_ok", err))
		return
	}
	time.Sleep(time.Second) // the relay accepts and dials what is queued
	h1, f1, a1 := snap()
	mib := func(a, b int64) string {
		if a < 0 || b < 0 {
			return "err:unreadable"
		}
		return fmt.Sprintf("%.1f", float64(b-a)/1024)
	}
	t.Logf("netpath %s flood_host_rss_delta_mib=%s flood_fc_rss_delta_mib=%s flood_memavail_delta_mib=%s relay_active=%d fc_pid=%s",
		line, mib(h0, h1), mib(f0, f1), mib(a1, a0), rl.active.Load(), fcPID)
	if _, line, err := g.ask(10*time.Second, "release"); err != nil {
		t.Log("netpath " + relay.Err("released", err))
	} else {
		time.Sleep(time.Second)
		t.Logf("netpath %s relay_active_after_release=%d", line, rl.active.Load())
	}
}

// guest is the host end of the control connection.
type guest struct {
	c net.Conn
	r *bufio.Reader
}

// ask sends one command and reads the guest's one reply line.
func (g *guest) ask(limit time.Duration, cmd ...string) (map[string]string, string, error) {
	_ = g.c.SetDeadline(time.Now().Add(limit))
	if _, err := io.WriteString(g.c, strings.Join(cmd, " ")+"\n"); err != nil {
		return nil, "", err
	}
	line, err := g.r.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	line = strings.TrimSpace(line)
	kv := relay.Parse(line)
	if e, ok := kv["error"]; ok {
		return nil, line, errors.New(e)
	}
	return kv, line, nil
}

// relayHost is the proxy's stand-in on the relay port: it reads each stream's
// header under a deadline, answers DNS itself and splices TCP to the sink.
type relayHost struct {
	ln                             net.Listener
	canary                         string
	streams, active, rejected, bad atomic.Int64
	mu                             sync.Mutex
	last                           string
	queries                        []string
}

func (r *relayHost) lastDst() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

func (r *relayHost) dnsQueries() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return relay.Clean(strings.Join(r.queries, ","))
}

func (r *relayHost) serve() {
	sem := make(chan struct{}, maxStreams)
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				r.handle(c)
			}()
		default:
			r.rejected.Add(1)
			_ = c.Close()
		}
	}
}

func (r *relayHost) handle(c net.Conn) {
	defer c.Close()
	r.active.Add(1)
	defer r.active.Add(-1)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, relay.HeaderLen)
	_, err := io.ReadFull(c, b)
	h, err2 := relay.Decode(b)
	if err != nil || err2 != nil {
		r.bad.Add(1)
		return
	}
	r.streams.Add(1)
	r.mu.Lock()
	r.last = h.Dst.String()
	r.mu.Unlock()
	if h.Proto == relay.UDP {
		q, err := relay.ReadFrame(c)
		if err != nil {
			return
		}
		if qq, ok := parseDNSQuery(q); ok {
			r.mu.Lock()
			r.queries = append(r.queries, fmt.Sprintf("%s/%d", qq.Name, qq.Type))
			r.mu.Unlock()
		}
		_, _ = c.Write(relay.Frame(dnsAnswer(q)))
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	up, err := net.Dial("tcp", r.canary)
	if err != nil {
		return
	}
	relay.Splice(c, up)
}

// sink is the upstream canary on the test host's loopback (T8): it sends one
// byte on accept, then reads everything. For the latest connection past 1 MiB
// it keeps the bytes so far and the time from the first of them to now.
type sink struct {
	ln    net.Listener
	mu    sync.Mutex
	bytes int64
	dur   time.Duration
}

func newSink(t *testing.T) *sink {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sink{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *sink) addr() string { return s.ln.Addr().String() }

func (s *sink) handle(c net.Conn) {
	defer c.Close()
	if _, err := c.Write([]byte{'!'}); err != nil {
		return
	}
	buf := make([]byte, 32<<10)
	var n int64
	var first time.Time
	for {
		k, err := c.Read(buf)
		if k > 0 {
			if n == 0 {
				first = time.Now()
			}
			if n += int64(k); n >= 1<<20 {
				s.mu.Lock()
				s.bytes, s.dur = n, time.Since(first)
				s.mu.Unlock()
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *sink) last() (int64, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes, s.dur
}

// canary counts what reaches an address of the host's own (escape/suite's canary
// pattern); for I2 the count must stay 0.
type canary struct {
	addr string
	stop func() int64
}

func listenCanary(network, host string) (canary, error) {
	var n atomic.Int64
	var closer io.Closer
	var addr string
	done := make(chan struct{})
	if network == "udp4" {
		pc, err := net.ListenPacket(network, host+":0")
		if err != nil {
			return canary{}, err
		}
		closer, addr = pc, pc.LocalAddr().String()
		go func() {
			defer close(done)
			buf := make([]byte, 2048)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
				n.Add(1)
			}
		}()
	} else {
		ln, err := net.Listen(network, host+":0")
		if err != nil {
			return canary{}, err
		}
		closer, addr = ln, ln.Addr().String()
		go func() {
			defer close(done)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				n.Add(1)
				_ = c.Close()
			}
		}()
	}
	return canary{addr: addr, stop: func() int64 { _ = closer.Close(); <-done; return n.Load() }}, nil
}

func token() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
