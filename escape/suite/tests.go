// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// All is the suite. Add a test by adding an entry; no other plumbing exists.
// Every canary a Judge starts is an address of the test host itself: its
// loopback, its own interface address (hostAddr), or an address the judge adds
// to loopback for the test's duration (onLoopback). No packet leaves the host
// (SPEC T8, S12). The guest gets a literal address, never a name.
var All = []Test{
	{ID: "I2", Name: "raw-ip-odd-port-tcp4", Probe: dialProbe, Host: tcpCanary("tcp4", hostAddr+":0", "")},
	{ID: "I2", Name: "ipv4-mapped-ipv6-tcp", Probe: dialProbe, Host: tcpCanary("tcp4", hostAddr+":0", "::ffff:"+hostAddr)},
	{ID: "I2", Name: "udp4-datagram", Probe: udpProbe, Host: udpCanary(lineToken)},
	{ID: "I2", Name: "quic-initial", Probe: quicProbe, Host: udpCanary(quicToken)},
	{ID: "I2", Name: "icmp-echo", Probe: icmpProbe, Host: icmpJudge},
	// A real guest's 127.0.0.1 is its own loopback. The host's loopback services
	// it could reach are those bound to every host address, dialled as the host.
	{ID: "I4", Name: "host-loopback-tcp4", Probe: dialProbe, Host: tcpCanary("tcp4", "0.0.0.0:0", hostAddr)},
	{ID: "I4", Name: "lan-rfc1918-tcp4", Probe: dialProbe, Host: onLoopback("10.255.255.254", tcpCanary("tcp4", "10.255.255.254:0", ""))},
	{ID: "I4", Name: "link-local-tcp4", Probe: dialProbe, Host: onLoopback("169.254.1.1", tcpCanary("tcp4", "169.254.1.1:0", ""))},
	{ID: "I4", Name: "metadata-tcp4", Probe: dialProbe, Host: onLoopback("169.254.169.254", tcpCanary("tcp4", "169.254.169.254:0", ""))},
	// DNS for a name no policy allows, sent past the guest's resolver straight to
	// a host-side capture: as plain DNS, as DoT, as DoH, and as a tunnel.
	{ID: "I3", Name: "direct-resolver-udp4", Probe: dnsUDPProbe, Host: dnsCanary(dnsOverUDP, queried)},
	{ID: "I3", Name: "direct-resolver-tcp4", Probe: dnsTCPProbe, Host: dnsCanary(dnsOverTCP(false), queried)},
	{ID: "I3", Name: "dot-tcp4", Probe: dotProbe, Host: dnsCanary(dnsOverTCP(true), queried)},
	{ID: "I3", Name: "doh-post-tcp4", Probe: dohProbe(http.MethodPost), Host: dnsCanary(dnsOverHTTPS, queried)},
	{ID: "I3", Name: "doh-get-tcp4", Probe: dohProbe(http.MethodGet), Host: dnsCanary(dnsOverHTTPS, queried)},
	{ID: "I3", Name: "tunnel-txt-udp4", Probe: tunnelProbe, Host: dnsCanary(dnsOverUDP, tunnelled)},
	// A secret lies beside the export on the host. The guest goes for it, and
	// for the directory holding it, by path, by link, by mount and by file
	// handle, and for the host's disks by device node.
	{ID: "I1", Name: "dotdot-traversal", Probe: traversalProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "planted-symlink", Probe: symlinkProbe, Host: outside(plantLinks), Want: exported},
	{ID: "I1", Name: "bind-mount", Probe: mountProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "open-by-handle", Probe: handleProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "device-node", Probe: deviceProbe, Host: deviceJudge, Want: exported},
	{ID: "I7", Name: "cross-session-residue", Probe: residueProbe, Host: residueJudge, Want: exported},
	// The guest asks for twice its cap; the host, watched from outside, must
	// give no more than the cap.
	{ID: "I10", Name: "fork-flood", Probe: forkProbe, Host: forkJudge, Want: capped},
	{ID: "I10", Name: "memory-flood", Probe: memoryProbe, Host: memoryJudge, Want: capped},
	{ID: "I10", Name: "disk-flood", Probe: diskProbe, Host: diskJudge, Want: capped},
	{ID: "I10", Name: "descriptor-flood", Probe: fileProbe, Host: fileJudge, Want: capped},
	{ID: "I10", Name: "log-flood", Probe: logProbe, Host: logJudge, Want: capped},
	{ID: "I10", Name: "cpu-flood", Probe: cpuProbe, Host: cpuJudge, Want: capped},
	// A secret is bound to one allowed name. The guest hunts for its value in
	// every process, on disk and in memory, and replays whatever credential it
	// was given at the other allowed name.
	{ID: "I5", Name: "secret-in-guest", Probe: secretProbe, Host: secretJudge, Want: withSecret},
	{ID: "I5", Name: "placeholder-replay", Probe: replayProbe, Host: twoCanaries(false, nil, leakJudge), Want: withSecret},
	// On a connection whose TLS names the bound host, the request names the
	// other, in the Host header, in :authority, or hidden from the SNI by
	// ECH; and a redirect from the bound host carries the credential on.
	{ID: "I6", Name: "sni-host-mismatch-h1", Probe: mismatchProbe(false), Host: twoCanaries(false, nil, strictJudge), Want: withSecret},
	{ID: "I6", Name: "sni-authority-mismatch-h2", Probe: mismatchProbe(true), Host: twoCanaries(false, nil, strictJudge), Want: withSecret},
	{ID: "I6", Name: "ech-hidden-sni", Probe: echProbe, Host: twoCanaries(true, nil, strictJudge), Want: withSecret},
	{ID: "I6", Name: "redirect-carries-secret", Probe: redirectProbe, Host: twoCanaries(false, redirectTo, leakJudge), Want: withSecret},
	// The repository the guest hands back is hostile: its hooks, config,
	// attributes and submodule URL aim at the host, and its tree names paths
	// through "..", through a symlink an earlier pull brought, and twice in
	// different case.
	{ID: "I8", Name: "pull-runs-hook", Probe: repoProbe, Host: obeyed("hooks"), Want: exported},
	{ID: "I8", Name: "pull-obeys-git-config", Probe: repoProbe, Host: obeyed("config"), Want: exported},
	{ID: "I8", Name: "pull-fetches-submodule", Probe: repoProbe, Host: fetched, Want: exported},
	{ID: "I8", Name: "pull-dotdot-path", Probe: repoProbe, Host: obeyed("dotdot"), Want: exported},
	{ID: "I8", Name: "pull-through-symlink", Probe: repoProbe, Host: obeyed("link", "fill"), Want: exported},
	{ID: "I8", Name: "pull-case-collision", Probe: repoProbe, Host: collided, Want: exported},
	// A workcell.toml in the repository tries to widen the policy: the
	// allowlist, the secret's binding, the workspace mode and the caps.
	{ID: "I13", Name: "repo-policy-widens-allowlist", Probe: replayProbe, Host: twoCanaries(false, nil, reachJudge), Want: widened},
	{ID: "I13", Name: "repo-policy-rebinds-secret", Probe: replayProbe, Host: twoCanaries(false, nil, leakJudge), Want: rebound},
	{ID: "I13", Name: "repo-policy-mounts-workspace", Probe: liveProbe, Host: liveJudge, Want: mounted},
	{ID: "I13", Name: "repo-policy-lifts-memory-cap", Probe: memoryProbe, Host: memoryJudge, Want: uncapped},
	// The guest, told where the host keeps the session's record, plants a
	// record, sends the record's path to /dev/null, or empties it; and a user
	// with the file edits it after the fact, which verify must notice.
	{ID: "I9", Name: "audit-forge-record", Probe: auditProbe, Host: auditJudge("forge"), Want: exported},
	{ID: "I9", Name: "audit-suppress-record", Probe: auditProbe, Host: auditJudge("suppress")},
	{ID: "I9", Name: "audit-truncate-record", Probe: auditProbe, Host: auditJudge("truncate")},
	{ID: "I9", Name: "verify-dropped-record", Probe: auditProbe, Host: offlineJudge("drop")},
	{ID: "I9", Name: "verify-altered-byte", Probe: auditProbe, Host: offlineJudge("alter")},
	{ID: "I9", Name: "verify-truncated-record", Probe: auditProbe, Host: offlineJudge("truncate")},
	{ID: "I9", Name: "verify-appended-record", Probe: auditProbe, Host: offlineJudge("append")},
	// Each host helper is killed with SIGKILL while the guest has reached an
	// allowed name; after, the guest must reach neither it nor a denied one.
	{ID: "I11", Name: "proxy-killed", Probe: reachProbe, Host: helperKilled("proxy"), Want: reachable},
	{ID: "I11", Name: "resolver-killed", Probe: reachProbe, Host: helperKilled("resolver"), Want: reachable},
	{ID: "I11", Name: "broker-killed", Probe: reachProbe, Host: helperKilled("broker"), Want: reachable},
	// Root in the guest writes on the init's own channel connection: frames
	// no decoder can take, a forged Exit under a version the host never
	// issued, an error text made of terminal escapes, a 4 GiB header then
	// silence, one byte a second; and a storm of fresh connections each
	// carrying a forged Exit. The host must end each run in time, without a
	// crash, with a clean stderr and the truthful status, and run again after.
	{ID: "I12", Name: "channel-malformed-frames", Probe: channelProbe, Host: channelJudge("exit-empty", "ack-short", "version-2", "unknown-type"), Bound: channelBound},
	{ID: "I12", Name: "channel-forged-exit-text", Probe: channelProbe, Host: channelJudge("exit-text"), Bound: channelBound},
	{ID: "I12", Name: "channel-oversized-frame", Probe: channelProbe, Host: channelJudge("giant-header"), Bound: channelBound},
	{ID: "I12", Name: "channel-slow-drip", Probe: channelProbe, Host: channelJudge("slow-drip"), Bound: channelBound},
	{ID: "I12", Name: "channel-connect-storm", Probe: channelProbe, Host: channelJudge("storm"), Bound: channelBound},
	{ID: "I12", Name: "channel-connect-flood", Probe: channelProbe, Host: floodJudge, Bound: channelBound},
	{ID: "I12", Name: "channel-cut-mid-frame", Probe: channelProbe, Host: channelJudge("half-close", "full-shutdown"), Bound: channelBound},
	{ID: "I12", Name: "channel-frames-after-exit", Probe: channelProbe, Host: channelJudge("after-exit"), Bound: channelBound},
	// The update client on the host, after one honest install from a channel
	// the judge signs and serves, meets a manifest signed by another key or
	// with a corrupted signature, past its expiry, below the last serial or
	// a day ahead, and an artifact whose bytes do not match, stop short,
	// come by a redirect, or come without TLS. None may install, and a
	// valid successor must.
	{ID: "I14", Name: "update-wrong-key", Probe: idleProbe, Host: updateJudge("wrong-key")},
	{ID: "I14", Name: "update-corrupt-signature", Probe: idleProbe, Host: updateJudge("corrupt-signature")},
	{ID: "I14", Name: "update-expired-manifest", Probe: idleProbe, Host: updateJudge("expired")},
	{ID: "I14", Name: "update-lower-serial", Probe: idleProbe, Host: updateJudge("lower-serial")},
	{ID: "I14", Name: "update-serial-ahead", Probe: idleProbe, Host: updateJudge("serial-ahead")},
	{ID: "I14", Name: "update-digest-mismatch", Probe: idleProbe, Host: updateJudge("digest-mismatch")},
	{ID: "I14", Name: "update-truncated-download", Probe: idleProbe, Host: updateJudge("truncated")},
	{ID: "I14", Name: "update-redirected-url", Probe: idleProbe, Host: updateJudge("redirected")},
	{ID: "I14", Name: "update-plain-http-url", Probe: idleProbe, Host: updateJudge("plain-http")},
	// The product's own start benchmark, run on the host: twenty warm boots,
	// and the median must be under the hosted budget.
	{ID: "P1", Name: "warm-start", Probe: idleProbe, Host: benchJudge, Bound: benchBound},
}

// hostAddr, in a canary address, stands for the host's own first non-loopback
// IPv4 address: what a real guest sees as the host.
const hostAddr = "host"

// dialProbe connects to args[0] and sends the token args[1] on one line.
func dialProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	c, err := net.DialTimeout("tcp", args[0], 3*time.Second)
	if err != nil {
		return dialFailed(err)
	}
	defer c.Close()
	if _, err := fmt.Fprintln(c, args[1]); err != nil {
		return Result{Status: "connected-write-failed", Detail: err.Error()}
	}
	return Result{Status: "connected", Detail: "to " + args[0]}
}

// udpProbe sends the token args[1] as a datagram line to args[0].
func udpProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	return sendUDP(args[0], []byte(args[1]+"\n"))
}

// quicProbe sends a QUIC v1 Initial packet to args[0] whose destination
// connection ID is the token args[1].
func quicProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	dcid, err := hex.DecodeString(args[1])
	if err != nil || len(dcid) > maxCID {
		return Result{Status: "error", Detail: "token is not a connection ID"}
	}
	return sendUDP(args[0], quicInitial(dcid))
}

func sendUDP(addr string, b []byte) Result {
	c, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return Result{Status: "unreachable", Detail: err.Error()}
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		return Result{Status: "send-failed", Detail: err.Error()}
	}
	return Result{Status: "sent", Detail: fmt.Sprintf("%d bytes to %s", len(b), addr)}
}

func newToken() string {
	token := make([]byte, 16)
	rand.Read(token)
	return hex.EncodeToString(token)
}

// resolve replaces hostAddr in a canary address with the host's own first
// non-loopback IPv4 address.
func resolve(addr string) (string, error) {
	if !strings.Contains(addr, hostAddr) {
		return addr, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				return strings.ReplaceAll(addr, hostAddr, ipn.IP.String()), nil
			}
		}
	}
	return "", errors.New("the host has no non-loopback IPv4 address for a canary")
}

// tcpCanary listens on addr and has the guest dial it, as dialHost when that is
// set (another address or spelling that reaches the same listener), else as
// the listener's own address. The invariant holds only if nothing arrives and
// the guest does not claim a connection.
func tcpCanary(network, addr, dialHost string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		addr, err := resolve(addr)
		if err == nil {
			dialHost, err = resolve(dialHost)
		}
		if err != nil {
			return false, "", err
		}
		ln, err := net.Listen(network, addr)
		if err != nil {
			return false, "", fmt.Errorf("canary listener: %w", err)
		}
		defer ln.Close()
		want := newToken()
		var got []string
		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.SetDeadline(time.Now().Add(2 * time.Second))
				line, _ := bufio.NewReaderSize(c, 128).ReadString('\n')
				c.Close()
				got = append(got, line)
			}
		})
		target := ln.Addr().String()
		if dialHost != "" {
			_, port, _ := net.SplitHostPort(target)
			target = net.JoinHostPort(dialHost, port)
		}
		r, err := s.Run(target, want)
		ln.Close()
		wg.Wait()
		if err != nil {
			return false, "", err
		}
		for _, line := range got {
			if line == want+"\n" {
				return false, "the guest reached the canary at " + target + " and delivered its token", nil
			}
		}
		if len(got) > 0 || r.Status == "connected" {
			return false, fmt.Sprintf("the guest connected to the canary at %s (%d connections; guest says %s: %s)", target, len(got), r.Status, r.Detail), nil
		}
		return true, fmt.Sprintf("guest says %s: %s", r.Status, r.Detail), nil
	}
}

// lineToken and quicToken say whether a datagram carries the token.
func lineToken(b []byte, token string) bool { return string(b) == token+"\n" }
func quicToken(b []byte, token string) bool {
	dcid, ok := quicDCID(b)
	return ok && hex.EncodeToString(dcid) == token
}

// udpCanary listens for datagrams on the host's own address and has the guest
// send the token there. A datagram is proof of reach; the guest's word is not.
func udpCanary(carries func(b []byte, token string) bool) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		addr, err := resolve(hostAddr + ":0")
		if err != nil {
			return false, "", err
		}
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return false, "", fmt.Errorf("canary listener: %w", err)
		}
		defer pc.Close()
		want := newToken()
		var hits, noise int
		var wg sync.WaitGroup
		wg.Go(func() {
			buf := make([]byte, 2048)
			for {
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if carries(buf[:n], want) {
					hits++
				} else {
					noise++
				}
			}
		})
		r, err := s.Run(pc.LocalAddr().String(), want)
		time.Sleep(200 * time.Millisecond) // a datagram in flight on loopback
		pc.Close()
		wg.Wait()
		if err != nil {
			return false, "", err
		}
		if hits > 0 {
			return false, fmt.Sprintf("%d datagrams from the guest carried the token to %s (guest says %s: %s)", hits, pc.LocalAddr(), r.Status, r.Detail), nil
		}
		return true, fmt.Sprintf("no datagram from the guest arrived (%d others; guest says %s: %s)", noise, r.Status, r.Detail), nil
	}
}

// icmpJudge has the guest ping the host's own address with the token as the
// echo payload. The invariant holds only if no reply carries the token back.
func icmpJudge(ctx context.Context, s Session) (bool, string, error) {
	host, err := resolve(hostAddr)
	if err != nil {
		return false, "", err
	}
	r, err := s.Run(host, newToken())
	if err != nil {
		return false, "", err
	}
	if r.Status == "echo-reply" {
		return false, "the host answered the guest's ICMP echo to " + host + " with its token: " + r.Detail, nil
	}
	return true, fmt.Sprintf("guest says %s: %s", r.Status, r.Detail), nil
}

// onLoopback runs judge while ip, which the host does not otherwise own, is an
// address of the host's loopback interface. A guest that reaches it has reached
// the host; no packet to it can leave the host.
func onLoopback(ip string, judge Judge) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		remove, err := loopbackAddr(net.ParseIP(ip))
		if err != nil {
			return false, "", err
		}
		defer remove()
		return judge(ctx, s)
	}
}
