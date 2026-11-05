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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestScriptedProviderSession runs the Claude Code and Codex adapters' requests against a fake of
// each one's API on a loopback listener of the test's own (T8), through the terminating proxy and
// the real broker. The rule is built as cmd/workcell builds it from the provider's secret, written
// out here because internal/provider imports this package; the tests of internal/provider and
// cmd/workcell read the data files. The fake answers only for the real key (A4, I5).
func TestScriptedProviderSession(t *testing.T) {
	const key = "REAL-0123456789"
	providers := []struct {
		secret, host, header, prefix string // as the provider's data file has them
		path, extra, val, other      string // the API's path, a header it also requires and its value, a header no rule covers
		body, answer                 string // the request, the reply
	}{
		{"anthropic", "api.anthropic.com", "x-api-key", "", "/v1/messages", "Anthropic-Version", "2023-06-01", "authorization", `{"model":"claude-test","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`,
			`{"id":"msg_01","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"Hello from the fake"}],"stop_reason":"end_turn"}`},
		{"openai", "api.openai.com", "authorization", "Bearer ", "/v1/responses", "Content-Type", "application/json", "x-api-key", `{"model":"codex-test","input":"hi","instructions":"be brief","stream":false}`,
			`{"id":"resp_01","object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"Hello from the fake"}]}]}`},
	}
	for _, pv := range providers {
		t.Run(pv.secret, func(t *testing.T) {
			keyFile := filepath.Join(t.TempDir(), "key")
			must(0, os.WriteFile(keyFile, []byte(key+"\n"), 0o600))
			var mu sync.Mutex
			var seen []string // the credential header of each request that reached the fake
			fake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.Header.Get(pv.header))
				mu.Unlock()
				if r.Method != http.MethodPost || r.URL.Path != pv.path || r.Header.Get(pv.header) != pv.prefix+key || r.Header.Get(pv.extra) != pv.val {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":{"type":"authentication_error","message":"invalid credential"}}`)
					return
				}
				_, _ = io.WriteString(w, pv.answer)
			}))
			authority := must(NewSessionCA([]string{pv.host}, time.Now().Add(time.Hour))) // the fake's own CA, trusted by the proxy alone
			fake.TLS = &tls.Config{Certificates: []tls.Certificate{*must(authority.leaf(pv.host))}}
			fake.StartTLS()
			t.Cleanup(fake.Close)
			p, _, _ := testProxy(t, pv.host+":443 other.example:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, fake.Listener.Addr().String())
			p.upstreamRoots = caPool(t, authority)
			rule := must(NewTerminateRule(pv.host, pv.header, "", ""))
			ledger := must(os.OpenFile(filepath.Join(t.TempDir(), "secrets.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600))
			t.Cleanup(func() { ledger.Close() })
			broker := must(secret.NewBroker([]secret.Grant{{Name: pv.secret, Source: "file:" + keyFile, Host: rule.Host, Header: rule.Header}}, ledger))
			sessionCA := must(NewSessionCA([]string{pv.host, "other.example"}, time.Now().Add(time.Hour)))
			must(0, p.Terminate(sessionCA, broker, []TerminateRule{rule}))
			client := clientVia(listen(t, p, 443), caPool(t, sessionCA))
			tests := []struct {
				name, host, header, value string
				ok                        bool     // the fake's message comes back
				saw                       []string // the credential header of each request the fake saw
			}{
				{"placeholder in the header", pv.host, pv.header, pv.prefix + rule.Placeholder, true, []string{pv.prefix + key}},
				{"a key the guest made up is not swapped", pv.host, pv.header, pv.prefix + "guess", false, []string{pv.prefix + "guess"}},
				{"placeholder in another header", pv.host, pv.other, "Bearer " + rule.Placeholder, false, nil},
				{"placeholder to another allowed name", "other.example", pv.header, pv.prefix + rule.Placeholder, false, nil},
				{"a bare placeholder is swapped bare, the prefix is the client's", pv.host, pv.header, rule.Placeholder, pv.prefix == "", []string{key}},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					mu.Lock()
					seen = nil
					mu.Unlock()
					req, _ := http.NewRequest(http.MethodPost, "https://"+tc.host+pv.path, strings.NewReader(pv.body))
					req.Header.Set(tc.header, tc.value)
					req.Header.Set(pv.extra, pv.val)
					resp, err := client.Do(req)
					reply := ""
					if err == nil {
						defer resp.Body.Close()
						b, _ := io.ReadAll(resp.Body)
						reply = resp.Status + " " + string(b) + resp.Header.Get(pv.header)
					}
					if got := strings.Contains(reply, `"text":"Hello from the fake"`); got != tc.ok || tc.ok && !strings.HasPrefix(reply, "200") || strings.Contains(reply, key) {
						t.Errorf("reply = %q (err %v), want the fake's message: %v, and never the real key", reply, err, tc.ok)
					}
					mu.Lock()
					defer mu.Unlock()
					if !slices.Equal(seen, tc.saw) {
						t.Errorf("the fake saw %q, want %q: the real key only for the placeholder in its header, never the placeholder", seen, tc.saw)
					}
				})
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
