// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F6, finding C11 of S-1005 (I10, with I12's hang). This file waits here, where Go does not compile it, until its fix lands; the fix unit moves it into internal/proxy/.
// The terminated server keeps http.Server's default MaxHeaderBytes, 1 MiB, and after the header block no read has a deadline. A request to a
// sign-in row's token endpoint that declares a body and never sends it is held in tokenRequest's io.ReadAll with no upstream dialled, its header
// block live, for as long as the guest likes: "100 Continue" is the proxy saying it has parsed the block and now waits. A client needs a few KiB
// of headers, and ADR-003 budgets 69 KiB for an idle terminated keep-alive; here each held connection pins well over 512 KiB of the proxy's heap,
// about 1.6 GiB at the 1024-connection cap. Every connection is the test's own, on loopback (T8, S12).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

// TestTokenEndpointHoldsOversizedHeaders: not parallel, so that the heap it measures is its own. Sixteen connections each send a header block just
// under 1 MiB to the token endpoint with a body declared and withheld; those the proxy holds must cost under 512 KiB each of live heap.
func TestTokenEndpointHoldsOversizedHeaders(t *testing.T) {
	c, _, _, _ := signinFixture(t, &provider{}, &tokenBroker{})
	tr := c.Transport.(*http.Transport)
	block := "POST " + tokenEndpointPath + " HTTP/1.1\r\nHost: login.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n"
	for i := 0; i < 250; i++ {
		block += fmt.Sprintf("X-Pad-%03d: %s\r\n", i, strings.Repeat("x", 4000))
	}
	block += "\r\n"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	held := 0
	for i := 0; i < 16; i++ {
		raw, err := tr.DialContext(context.Background(), "tcp", "")
		if err != nil {
			t.Fatal(err)
		}
		conn := tls.Client(raw, &tls.Config{ServerName: "login.example.com", RootCAs: tr.TLSClientConfig.RootCAs})
		defer conn.Close()
		if _, err := conn.Write([]byte(block)); err != nil {
			continue // refused while the block was still going in
		}
		if line, _ := bufio.NewReader(conn).ReadString('\n'); strings.HasPrefix(line, "HTTP/1.1 100 ") {
			held++
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if growth := int(after.HeapAlloc) - int(before.HeapAlloc); held > 0 && growth > held*512<<10 {
		t.Errorf("%d connections of %d KiB headers held at the token endpoint pin %d KiB of live heap each, over 512 KiB; a client needs a few KiB", held, len(block)>>10, growth/held>>10)
	}
}
