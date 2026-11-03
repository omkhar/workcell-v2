// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// SPEC I2, I4 and I12 on the network path of ADR-003. Every address is local
// to the guest: its kernel completes a TCP handshake to a listed port and the
// init carries the stream to the host as its own vsock stream, behind a
// 20-byte header that names the destination. Root in the guest (A1) can skip
// the init and speak that header itself, to the host end the adapter names,
// with any address, port, proto or version. The host must dial none of it:
// the canary's catch is the evidence of reach, and what the guest says is
// detail. A stream whose header never completes must be dropped: a host that
// holds it past headerWait holds a slot of a bounded relay for a guest that
// sent ten bytes, and the guest's side of that stream is the only witness.
const (
	relayVersion = 1
	protoTCP     = 6
	protoUDP     = 17
	headerLen    = 20
	shortHeader  = 10               // header bytes the short kind sends
	dripBytes    = headerLen - 1    // the slow kind sends every header byte but the last
	dripEvery    = 400 * ms         // between bytes of the slow header
	answerWait   = 3 * time.Second  // how long a whole-header stream waits for the host's answer
	headerWait   = 8 * time.Second  // a stream with no complete header must be dropped within this
	relayWait    = 25 * time.Second // a relay run must end within this
	relayBound   = 30 * time.Second // Test.Bound for the header kinds that wait
)

// errHeld is read's answer when the peer neither wrote nor closed in time.
var errHeld = errors.New("the stream is still open")

// relayHeader encodes the relay's header: version, proto, the port big-endian
// and the address as 16 bytes, an IPv4 address mapped.
func relayHeader(version, proto byte, ip net.IP, port uint16) []byte {
	h := []byte{version, proto, byte(port >> 8), byte(port)}
	ip16 := ip.To16()
	if ip16 == nil {
		ip16 = make(net.IP, 16)
	}
	return append(h, ip16...)
}

// framed is a datagram as the relay carries it on a UDP stream: a two-byte
// big-endian length, then the bytes.
func framed(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }

// relayProbe dials the host end of the relay at args[1] afresh and speaks the
// header itself. The kinds tcp, udp, version-N and proto-N name args[2], a
// canary, as the destination and send the token args[3] behind the header;
// short and slow send part of a header and wait for the host to drop the
// stream.
func relayProbe(args []string) Result {
	if len(args) < 2 {
		return Result{Status: "error", Detail: "want kind and relay address"}
	}
	kind, addr := args[0], args[1]
	c, err := dialChannel(addr)
	if err != nil {
		return Result{Status: "no-relay", Detail: err.Error()}
	}
	defer c.close()
	switch kind {
	case "short", "slow":
		return headless(c, kind)
	}
	if len(args) != 4 {
		return Result{Status: "error", Detail: "want kind, relay address, target and token"}
	}
	host, port, err := net.SplitHostPort(args[2])
	ip := net.ParseIP(host)
	p, perr := strconv.ParseUint(port, 10, 16)
	if err != nil || ip == nil || perr != nil {
		return Result{Status: "error", Detail: "want an IP address and port, got " + args[2]}
	}
	version, proto := byte(relayVersion), byte(protoTCP)
	payload := []byte(args[3] + "\n")
	switch kind {
	case "tcp":
	case "udp":
		proto, payload = protoUDP, framed(payload)
	case "version-0":
		version = 0
	case "version-2":
		version = 2
	case "proto-0":
		proto = 0
	case "proto-1":
		proto = 1
	default:
		return Result{Status: "error", Detail: "unknown kind " + kind}
	}
	b := append(relayHeader(version, proto, ip, uint16(p)), payload...)
	what := fmt.Sprintf("%s: a version %d proto %d header for %s then %d bytes", kind, version, proto, args[2], len(payload))
	if n, err := c.write(b, sendWait); err != nil {
		return Result{Status: "cut", Detail: fmt.Sprintf("%s; the host took %d of %d bytes: %v", what, n, len(b), err)}
	}
	return relayAnswer(c, what, answerWait)
}

// headless sends shortHeader bytes of a header at once, or dripBytes of it a
// byte at a time, and reports whether the host dropped the stream.
func headless(c *rawConn, kind string) Result {
	start := time.Now()
	h := relayHeader(relayVersion, protoTCP, net.IPv4(127, 0, 0, 1), 443)
	if kind == "short" {
		if n, err := c.write(h[:shortHeader], sendWait); err != nil {
			return Result{Status: "closed", Detail: fmt.Sprintf("short: the host dropped the stream as %d of %d header bytes went: %v", n, headerLen, err)}
		}
		return relayAnswer(c, fmt.Sprintf("short: %d of %d header bytes", shortHeader, headerLen), headerWait)
	}
	for sent := 0; sent < dripBytes; sent++ {
		if _, err := c.write(h[sent:sent+1], sendWait); err != nil {
			return Result{Status: "closed", Detail: fmt.Sprintf("slow: the host dropped the stream after %d of %d header bytes, %s in: %v", sent, headerLen, time.Since(start).Round(ms), err)}
		}
		if r := relayAnswer(c, fmt.Sprintf("slow: %d of %d header bytes, %s in", sent+1, headerLen, time.Since(start).Round(ms)), dripEvery); r.Status != "held" {
			return r
		}
	}
	return relayAnswer(c, fmt.Sprintf("slow: %d of %d header bytes over %s, then silence", dripBytes, headerLen, time.Since(start).Round(ms)), headerWait)
}

// relayAnswer waits at most wait for the host's side of the stream: it
// answered, it closed, or it held the stream open.
func relayAnswer(c *rawConn, what string, wait time.Duration) Result {
	start := time.Now()
	n, err := c.read(make([]byte, 64), wait)
	took := time.Since(start).Round(ms)
	switch {
	case n > 0:
		return Result{Status: "answered", Detail: fmt.Sprintf("%s; %d bytes came back after %s", what, n, took)}
	case errors.Is(err, errHeld):
		return Result{Status: "held", Detail: fmt.Sprintf("%s; the host held the stream open for %s", what, took)}
	}
	return Result{Status: "closed", Detail: fmt.Sprintf("%s; the host closed the stream after %s (%v)", what, took, err)}
}

// relayRun runs the relay probe with args and holds the host process to I12
// as channelRun does: it must end within relayWait, must not crash and must
// write no control bytes. It returns the probe's result, or why the host end
// fell short. A run the host could not complete is an error, never a pass.
func relayRun(ctx context.Context, s Session, args ...string) (Result, string, error) {
	rctx, cancel := context.WithTimeout(ctx, relayWait)
	defer cancel()
	start := time.Now()
	out, err := s.Exec(rctx, args...)
	if err != nil {
		if rctx.Err() != nil && ctx.Err() == nil {
			return Result{}, fmt.Sprintf("%s: the run did not end within %s", args[0], relayWait), nil
		}
		return Result{}, "", err
	}
	if why := hostFault(out); why != "" {
		return Result{}, fmt.Sprintf("%s: exit %d after %s: %s", args[0], out.Exit, time.Since(start).Round(100*ms), why), nil
	}
	if out.Exit != 0 {
		return Result{}, "", fmt.Errorf("%s: payload exited %d: %s", args[0], out.Exit, firstLine(out.Stderr))
	}
	r, err := ParseResult(out.Stdout)
	if err == nil && r.Status == "error" {
		err = fmt.Errorf("probe error: %s", r.Detail)
	}
	return r, "", err
}

// relayCanary listens on network at listen and has the guest name that canary
// in a relay header of each kind in turn, all against the same canary. The
// invariant holds only if nothing arrives there and the host end stands.
func relayCanary(network, listen string, kinds ...string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		addr, err := resolve(listen)
		if err != nil {
			return false, "", err
		}
		relay, err := s.Relay(ctx)
		if err != nil {
			return false, "", err
		}
		t, err := listenTrap(network, addr)
		if err != nil {
			return false, "", err
		}
		defer t.stop()
		want := newToken()
		var say []string
		for _, kind := range kinds {
			r, why, err := relayRun(ctx, s, kind, relay.Addr, t.addr(), want)
			if err != nil || why != "" {
				return false, why, err
			}
			say = append(say, fmt.Sprintf("%s: %s", r.Status, r.Detail))
		}
		got := t.stop()
		pass, detail := verdict(got, lineToken, want, t.addr(), t.pc == nil, "via the relay at "+relay.Addr+"; guest says "+strings.Join(say, "; "))
		return pass, detail, nil
	}
}

// relayHeld has the guest offer the host end a header that never completes,
// of the kind, and holds the host to dropping the stream within headerWait.
// A host end that is not there cannot hold anything.
func relayHeld(kind string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		relay, err := s.Relay(ctx)
		if err != nil {
			return false, "", err
		}
		r, why, err := relayRun(ctx, s, kind, relay.Addr)
		if err != nil || why != "" {
			return false, why, err
		}
		switch r.Status {
		case "closed", "no-relay":
			return true, says(r), nil
		}
		return false, fmt.Sprintf("the host end at %s kept a stream whose header never completed (%s)", relay.Addr, says(r)), nil
	}
}
