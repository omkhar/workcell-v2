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
	"sync"
	"time"
)

// All is the suite. Add a test by adding an entry; no other plumbing exists.
// Every canary a Judge starts lives on the test host's loopback (SPEC T8, S12).
var All = []Test{
	{ID: "I4", Name: "host-loopback-tcp4", Probe: dialProbe, Host: hostLoopbackTCP("tcp4", "127.0.0.1:0")},
}

// dialProbe connects to args[0] and sends the token args[1] on one line.
func dialProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	c, err := net.DialTimeout("tcp", args[0], 3*time.Second)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return Result{Status: "timeout", Detail: err.Error()}
		}
		return Result{Status: "unreachable", Detail: err.Error()}
	}
	defer c.Close()
	if _, err := fmt.Fprintln(c, args[1]); err != nil {
		return Result{Status: "connected-write-failed", Detail: err.Error()}
	}
	return Result{Status: "connected", Detail: "to " + args[0]}
}

// hostLoopbackTCP listens on the host's loopback and has the guest dial it.
// I4 holds only if nothing arrives and the guest does not claim a connection.
func hostLoopbackTCP(network, addr string) Judge {
	return func(ctx context.Context, run Run) (bool, string, error) {
		ln, err := net.Listen(network, addr)
		if err != nil {
			return false, "", fmt.Errorf("canary listener: %w", err)
		}
		defer ln.Close()
		token := make([]byte, 16)
		rand.Read(token)
		want := hex.EncodeToString(token)
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
		r, err := run(ln.Addr().String(), want)
		ln.Close()
		wg.Wait()
		if err != nil {
			return false, "", err
		}
		for _, line := range got {
			if line == want+"\n" {
				return false, "the guest reached the host loopback canary and delivered its token", nil
			}
		}
		if len(got) > 0 || r.Status == "connected" {
			return false, fmt.Sprintf("the guest connected to the host loopback canary (%d connections; guest says %s: %s)", len(got), r.Status, r.Detail), nil
		}
		return true, fmt.Sprintf("guest says %s: %s", r.Status, r.Detail), nil
	}
}
