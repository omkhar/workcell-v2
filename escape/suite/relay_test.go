// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

func TestRelayHeader(t *testing.T) {
	cases := []struct {
		ip   string
		want []byte // the 16 address bytes
	}{
		{"192.0.2.2", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 2}},
		{"::ffff:192.0.2.2", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 2}},
		{"2001:db8::7", []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}},
		{"", make([]byte, 16)},
	}
	for _, c := range cases {
		h := relayHeader(relayVersion, protoTCP, net.ParseIP(c.ip), 443)
		if len(h) != headerLen || h[0] != 1 || h[1] != 6 || h[2] != 1 || h[3] != 0xbb || !bytes.Equal(h[4:], c.want) {
			t.Errorf("relayHeader(%q) = % x", c.ip, h)
		}
	}
	if h := relayHeader(2, protoUDP, net.ParseIP("127.0.0.1"), 53); h[0] != 2 || h[1] != 17 || h[2] != 0 || h[3] != 53 {
		t.Errorf("version 2 proto 17 port 53 = % x", h[:4])
	}
	if f := framed([]byte("abc")); !bytes.Equal(f, []byte{0, 3, 'a', 'b', 'c'}) {
		t.Errorf("framed = % x", f)
	}
	if f := framed(make([]byte, 300)); f[0] != 1 || f[1] != 44 || len(f) != 302 {
		t.Errorf("framed(300 bytes) = % x...", f[:2])
	}
}

func TestVerdict(t *testing.T) {
	const want = "tok"
	cases := []struct {
		name   string
		got    [][]byte
		stream bool
		pass   bool
	}{
		{"nothing on a stream canary", nil, true, true},
		{"nothing on a datagram canary", nil, false, true},
		{"the token on a stream canary", [][]byte{[]byte("tok\n")}, true, false},
		{"the token on a datagram canary", [][]byte{[]byte("x"), []byte("tok\n")}, false, false},
		{"a connection without the token", [][]byte{[]byte("")}, true, false},
		{"a stray datagram", [][]byte{[]byte("x\n")}, false, true},
	}
	for _, c := range cases {
		pass, detail := verdict(c.got, lineToken, want, "127.0.0.1:1", c.stream, "guest says x")
		if pass != c.pass || detail == "" {
			t.Errorf("%s: verdict = %v, %q; want %v", c.name, pass, detail, c.pass)
		}
	}
}

// relayAt is a host whose relay the guest reaches at one address.
type relayAt struct{ idle }

func (relayAt) Relay(context.Context) (sandbox.Channel, error) {
	return sandbox.Channel{Addr: "unix:/nowhere/relay"}, nil
}

// Bind is in the host's one network, at the literal address a test gives.
func (relayAt) Bind(_ context.Context, network, addr string) (net.Listener, net.PacketConn, error) {
	if strings.HasPrefix(network, "udp") {
		pc, err := net.ListenPacket(network, addr)
		return nil, pc, err
	}
	ln, err := net.Listen(network, addr)
	return ln, nil, err
}

// guest is a fake Session whose probe runs are the function: it gets the probe's arguments as the judge passes them and gives the line the payload would print.
func guest(run func(args ...string) Result) Session {
	exec := func(_ context.Context, args ...string) (sandbox.Output, error) {
		return sandbox.Output{Stdout: Format(run(args...))}, nil
	}
	return Session{
		Run:     func(args ...string) (Result, error) { return run(args...), nil },
		Exec:    exec,
		Observe: relayAt{},
	}
}

// deliver is a guest that really connects to args[0] and sends args[1].
func deliver(args ...string) Result {
	c, err := net.Dial("tcp", args[0])
	if err != nil {
		return Result{Status: "unreachable", Detail: err.Error()}
	}
	defer c.Close()
	fmt.Fprintln(c, args[1])
	return Result{Status: "connected-closed", Detail: "delivered"}
}

// Under ADR-003 every address is local to the guest, so a connect that the relay then drops must pass, as a refusal must; anything at the canary fails.
func TestTCPCanaryJudge(t *testing.T) {
	ctx := context.Background()
	judge := tcpCanary("tcp4", "127.0.0.1:0", "")
	cases := []struct {
		name string
		run  func(args ...string) Result
		pass bool
	}{
		{"refused", func(...string) Result { return Result{Status: "refused", Detail: "connection refused"} }, true},
		{"accepted then closed, nothing at the canary", func(...string) Result { return Result{Status: "connected-closed", Detail: "EOF"} }, true},
		{"the token at the canary", deliver, false},
		{"a connection at the canary", func(args ...string) Result {
			c, err := net.Dial("tcp", args[0])
			if err == nil {
				c.Close()
			}
			return Result{Status: "connected-closed", Detail: "no token"}
		}, false},
	}
	for _, c := range cases {
		pass, detail, err := judge(ctx, guest(c.run))
		if err != nil || pass != c.pass {
			t.Errorf("%s: tcpCanary = %v, %q, %v; want %v", c.name, pass, detail, err, c.pass)
		}
	}
}

func TestRelayJudges(t *testing.T) {
	ctx := context.Background()
	say := func(status string) func(...string) Result {
		return func(...string) Result { return Result{Status: status, Detail: "x"} }
	}
	// relayCanary: only the canary's catch fails it.
	canary := relayCanary("tcp4", "127.0.0.1:0", "tcp", "version-2")
	if pass, detail, err := canary(ctx, guest(say("closed"))); err != nil || !pass {
		t.Errorf("relayCanary with nothing arriving = %v, %q, %v; want pass", pass, detail, err)
	}
	if pass, detail, err := canary(ctx, guest(func(args ...string) Result { return deliver(args[2], args[3]) })); err != nil || pass {
		t.Errorf("relayCanary with the token arriving = %v, %q, %v; want fail", pass, detail, err)
	}
	// relayHeld: a dropped stream or no relay passes; a held or answered one fails.
	for status, want := range map[string]bool{"closed": true, "no-relay": true, "held": false, "answered": false, "cut": false} {
		pass, detail, err := relayHeld("short")(ctx, guest(say(status)))
		if err != nil || pass != want {
			t.Errorf("relayHeld with the guest saying %s = %v, %q, %v; want %v", status, pass, detail, err, want)
		}
	}
	// A crashed host end fails whatever the guest says; a run that did not complete is an error.
	crashed := guest(say("closed"))
	crashed.Exec = func(context.Context, ...string) (sandbox.Output, error) {
		return sandbox.Output{Exit: 2, Stderr: []byte("panic: runtime error\n")}, nil
	}
	if pass, detail, err := relayHeld("slow")(ctx, crashed); err != nil || pass || !strings.Contains(detail, "crashed") {
		t.Errorf("relayHeld on a crash = %v, %q, %v; want fail", pass, detail, err)
	}
	failed := guest(say("closed"))
	failed.Exec = func(context.Context, ...string) (sandbox.Output, error) {
		return sandbox.Output{Exit: 125, Stderr: []byte("workcell: no session\n")}, nil
	}
	if pass, _, err := relayHeld("slow")(ctx, failed); err == nil || pass {
		t.Errorf("relayHeld on exit 125 = %v, %v; want an error", pass, err)
	}
}
