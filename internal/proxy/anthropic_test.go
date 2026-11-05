// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestScriptedClaudeSession runs the Claude Code adapter's request against a fake Anthropic
// Messages API on a loopback listener of the test's own (T8), through the terminating proxy and
// the real broker, rule built as cmd/workcell builds it from provider claude (its test, with the
// same names, covers the policy side). The fake answers only for the real key and a version
// header; the guest's script holds the placeholder alone (A4, I5).
func TestScriptedClaudeSession(t *testing.T) {
	const key = "sk-ant-api03-REAL-0123456789"
	keyFile := filepath.Join(t.TempDir(), "key")
	must(0, os.WriteFile(keyFile, []byte(key+"\n"), 0o600))
	var mu sync.Mutex
	var seen []string // the x-api-key of each request that reached the fake
	fake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != key || r.Header.Get("Anthropic-Version") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"msg_01","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"Hello from the fake"}],"stop_reason":"end_turn"}`)
	}))
	authority := must(NewSessionCA([]string{"api.anthropic.com"}, time.Now().Add(time.Hour))) // the fake's own CA, trusted by the proxy alone
	fake.TLS = &tls.Config{Certificates: []tls.Certificate{*must(authority.leaf("api.anthropic.com"))}}
	fake.StartTLS()
	t.Cleanup(fake.Close)
	p, _, _ := testProxy(t, "api.anthropic.com:443 other.example:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, fake.Listener.Addr().String())
	p.upstreamRoots = caPool(t, authority)
	rule := must(NewTerminateRule("api.anthropic.com", "x-api-key", "", ""))
	ledger := must(os.OpenFile(filepath.Join(t.TempDir(), "secrets.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600))
	t.Cleanup(func() { ledger.Close() })
	broker := must(secret.NewBroker([]secret.Grant{{Name: "anthropic", Source: "file:" + keyFile, Host: rule.Host, Header: rule.Header}}, ledger))
	sessionCA := must(NewSessionCA([]string{"api.anthropic.com", "other.example"}, time.Now().Add(time.Hour)))
	must(0, p.Terminate(sessionCA, broker, []TerminateRule{rule}))
	client := clientVia(listen(t, p, 443), caPool(t, sessionCA))

	tests := []struct {
		name, host, header, value string
		ok                        bool // the fake's message comes back
		reached                   int  // requests the fake saw
	}{
		{"placeholder in x-api-key", "api.anthropic.com", "X-Api-Key", rule.Placeholder, true, 1},
		{"a key the guest made up is not swapped", "api.anthropic.com", "X-Api-Key", "sk-ant-guess", false, 1},
		{"placeholder in another header", "api.anthropic.com", "Authorization", "Bearer " + rule.Placeholder, false, 0},
		{"placeholder to another allowed name", "other.example", "X-Api-Key", rule.Placeholder, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()
			req, _ := http.NewRequest(http.MethodPost, "https://"+tc.host+"/v1/messages", strings.NewReader(`{"model":"claude-test","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
			req.Header.Set(tc.header, tc.value)
			req.Header.Set("Anthropic-Version", "2023-06-01")
			resp, err := client.Do(req)
			reply := ""
			if err == nil {
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				reply = resp.Status + " " + string(b) + resp.Header.Get("X-Api-Key")
			}
			if got := strings.Contains(reply, `"text":"Hello from the fake"`); got != tc.ok || tc.ok && !strings.HasPrefix(reply, "200") {
				t.Errorf("reply = %q (err %v), want the fake's message: %v", reply, err, tc.ok)
			}
			if strings.Contains(reply, key) {
				t.Errorf("the guest's client saw the real key: %q", reply)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(seen) != tc.reached {
				t.Fatalf("the fake saw %d requests, want %d", len(seen), tc.reached)
			}
			for _, k := range seen {
				if k == rule.Placeholder || tc.ok != (k == key) {
					t.Errorf("the fake saw x-api-key %q: want the real key only when the message comes back", k)
				}
			}
		})
	}
}

// must is the value of a setup step that cannot fail in a working test; a failure panics.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
