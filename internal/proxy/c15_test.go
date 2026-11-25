// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C15 of S-1007 (I5, medium). learn in internal/proxy/signin.go hides only the tokens the broker holds when the answer arrives, plus the ones the answer itself issues. Two refresh requests sent at once both carry the one real refresh token R1 to the endpoint; the provider rotates on the
// first and answers the second, now stale, 400 with the presented token echoed. By then the broker holds (A2, R2), so R1, real a moment before, reaches the guest verbatim. That the provider echoes is a precondition the attacker does not control. This file lives here as finding C15's regression test (S4).
package proxy

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestConcurrentRefreshHidesTheReplacedToken: after a sign-in through the real proxy, broker and ledger, two refresh requests race. The loopback provider holds both until both have arrived, rotates on the first, and answers the second only once the guest holds the first answer, with the stale token echoed. Pass: neither answer carries a byte of sk-ref-1. The second answer spells it: FAIL (I5).
func TestConcurrentRefreshHidesTheReplacedToken(t *testing.T) {
	t.Parallel()
	var arrived atomic.Int32
	both, release := make(chan struct{}), make(chan struct{}) // closed when both refresh requests have arrived; when the guest holds the first answer
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		if q.Get("grant_type") == "authorization_code" {
			_, _ = io.WriteString(w, `{"access_token":"sk-acc-1","token_type":"Bearer","refresh_token":"sk-ref-1"}`)
			return
		}
		n := arrived.Add(1)
		if n == 2 {
			close(both)
		}
		<-both
		if n == 1 {
			_, _ = io.WriteString(w, `{"access_token":"sk-acc-2","token_type":"Bearer","refresh_token":"sk-ref-2"}`)
			return
		}
		<-release
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"refresh token %s was already used"}`, q.Get("refresh_token"))
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	px, _, _ := testProxy(t, "api.example.com:443 login.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = roots
	ca := must(NewSessionCA([]string{"api.example.com", "login.example.com"}, time.Now().Add(time.Hour)))
	rule := TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}
	broker := must(secret.NewBroker([]secret.Grant{{Name: "api", Source: "signin:login.example.com" + tokenEndpointPath, Host: rule.Host, Header: rule.Header}}, testLedger(t)))
	must(0, px.Terminate(ca, broker, []TerminateRule{rule}))
	c, endpoint, form := clientVia(listen(t, px, 443), caPool(t, ca)), "https://login.example.com"+tokenEndpointPath, "application/x-www-form-urlencoded"
	grant, answers := "grant_type=refresh_token&refresh_token="+testRefreshPlaceholder, make(chan string, 2)
	send(t, c, "POST", endpoint, form, "grant_type=authorization_code&code=c0de") // the broker now holds sk-acc-1 and sk-ref-1
	refresh := func() { answers <- fmt.Sprintln(send(t, c, "POST", endpoint, form, grant)) }
	go refresh()
	go refresh()
	first := <-answers
	close(release)
	second := <-answers
	if !strings.HasPrefix(first, "200 ") || !strings.HasPrefix(second, "400 ") || strings.Contains(first+second, "sk-ref-1") {
		t.Errorf("the guest read %q then %q; want 200 then 400 with no byte of the replaced refresh token sk-ref-1", first, second)
	}
}
