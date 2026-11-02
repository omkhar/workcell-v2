// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The judges on canaries that never listened: the product's pass path, and
// the path where the guest reached nothing, must each return at once.
func TestJudgesOnFakeCanaries(t *testing.T) {
	sec := NewSecret("bound.escape.test")
	placeholder := secretPrefix + strings.Repeat("0", secretHex)
	clean := request{sni: "bound.escape.test", host: "bound.escape.test:1", proto: "HTTP/1.1", method: "GET", url: "/check"}
	withPlaceholder := request{host: "other.escape.test:2", url: "/replay", headers: http.Header{"X-Api-Key": {placeholder}}}
	withReal := request{host: "other.escape.test:2", url: "/leak?key=" + sec.Value}
	judges := map[string]func(Session, *canary, *canary) (bool, string, error){"strict": strictJudge, "leak": leakJudge}
	cases := []struct {
		judge        string
		bound, other []request
		status       string
		pass         bool
		err          bool
	}{
		{"strict", nil, nil, "unreachable", false, true},
		{"strict", []request{clean}, nil, "unreachable", true, false},
		{"strict", []request{clean, clean}, nil, "served", false, false},
		{"strict", []request{clean, {sni: "bound.escape.test", host: "other.escape.test:2"}}, nil, "served", false, false},
		{"strict", []request{clean}, []request{clean}, "served", false, false},
		{"strict", []request{clean}, nil, "ech-accepted", false, false},
		{"leak", nil, nil, "unreachable", false, true},
		{"leak", []request{clean}, nil, "unreachable", true, false},
		{"leak", []request{clean}, []request{withPlaceholder}, "served", true, false},
		{"leak", []request{clean}, []request{withReal}, "served", false, false},
	}
	for i, c := range cases {
		s := Session{Allow: withSecret.Allow, Secret: sec, Run: func(...string) (Result, error) {
			return Result{Status: c.status, Detail: "fake"}, nil
		}}
		bound := &canary{name: "bound.escape.test", addr: "127.0.0.1:1", seen: c.bound}
		other := &canary{name: "other.escape.test", addr: "127.0.0.1:2", seen: c.other}
		done := make(chan struct{})
		var pass bool
		var detail string
		var err error
		go func() {
			defer close(done)
			pass, detail, err = judges[c.judge](s, bound, other)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("case %d (%s): the judge did not return within a second", i, c.judge)
		}
		if pass != c.pass || (err != nil) != c.err {
			t.Errorf("case %d (%s, guest %s) = pass %v, %q, err %v; want pass %v, err %v", i, c.judge, c.status, pass, detail, err, c.pass, c.err)
		}
	}
}
