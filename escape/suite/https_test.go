// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The judges on canaries that never listened: the product's pass path, and the path where the guest reached nothing, must each return at once.
func TestJudgesOnFakeCanaries(t *testing.T) {
	sec := NewSecret(withSecret)
	placeholder := secretPrefix + strings.Repeat("0", secretHex)
	clean := request{sni: "bound.escape.test", host: "bound.escape.test:1", proto: "HTTP/1.1", method: "GET", url: "/check"}
	withPlaceholder := request{host: "other.escape.test:2", url: "/replay", headers: http.Header{"X-Api-Key": {placeholder}}}
	swapped := request{method: "GET", url: "/check", headers: http.Header{"X-Api-Key": {sec.Value}}}
	unswapped := request{method: "GET", url: "/check", headers: http.Header{"X-Api-Key": {placeholder}}}
	elsewhere := request{method: "GET", url: "/check", headers: http.Header{"X-Api-Key": {sec.Value}, "Cookie": {"k=" + sec.Value}}}
	judges := map[string]func(Session, *canary, *canary) (bool, string, error){"strict": strictJudge, "termination": terminationJudge, "upstream": upstreamJudge,
		"swap": swapJudge("GET,bound,/check,header", "GET,other,/replay,header")}
	cases := []struct {
		judge        string
		bound, other []request
		status       string
		pass         bool
		err          bool
	}{
		{"strict", nil, nil, "unreachable", false, true},
		{"strict", []request{clean}, nil, "unreachable", true, false},
		{"strict", []request{clean, clean}, nil, "served", true, false}, // the mismatch rewritten to the one name
		{"strict", []request{clean, {sni: "bound.escape.test", host: "other.escape.test:2"}}, nil, "served", false, false},
		{"strict", []request{clean}, []request{clean}, "served", false, false},
		{"strict", []request{clean}, nil, "ech-accepted", false, false},
		{"termination", []request{clean}, nil, "terminated", true, false},
		{"termination", []request{clean}, nil, "spliced", false, false},
		{"termination", []request{clean}, nil, "untrusted", false, false},
		{"termination", []request{clean}, []request{clean}, "terminated", false, false},
		{"termination", []request{{sni: "", host: "bound.escape.test:1"}}, nil, "terminated", false, false},
		{"termination", nil, nil, "terminated", false, true},
		{"upstream", nil, []request{clean}, "served", true, false},
		{"upstream", []request{clean}, []request{clean}, "served", false, false},
		{"upstream", nil, nil, "unreachable", false, true},
		{"swap", []request{swapped}, nil, "sent", true, false},
		{"swap", []request{unswapped}, nil, "sent", false, false},                      // the bound name got the placeholder, not the value
		{"swap", []request{swapped}, []request{withPlaceholder}, "sent", false, false}, // the other name got anything
		{"swap", []request{elsewhere}, nil, "sent", false, false},                      // the value in another header
		{"swap", nil, nil, "unreachable", false, true},
		{"swap", nil, []request{clean}, "sent", false, false},                                                                                        // nothing admitted arrived
		{"swap", []request{swapped, {method: "GET", url: "/octo/other", headers: http.Header{"X-Api-Key": {sec.Value}}}}, nil, "sent", false, false}, // a request no admitted exchange sent
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
	// And the swap judge on a guest that holds the real value, whatever the canaries saw.
	s := Session{Allow: withSecret.Allow, Secret: sec, Run: func(...string) (Result, error) { return Result{Status: "sent", Detail: "sent=" + sec.Value}, nil }}
	if pass, detail, err := judges["swap"](s, &canary{name: "bound.escape.test", seen: []request{swapped}}, &canary{name: "other.escape.test"}); pass || err != nil {
		t.Errorf("a guest holding the real value: pass %v, %q, %v", pass, detail, err)
	}
}

// TestExchange checks the parser of an exchange and what the swap rule admits under a binding, narrowed and not.
func TestExchange(t *testing.T) {
	wide, narrow := NewSecret(withSecret), NewSecret(narrowed)
	cases := []struct {
		spec       string
		ok         bool
		wide, narr bool // admitted
	}{
		{"GET,bound,/check,header", true, true, false},
		{"GET,bound,/check,bearer", true, true, false},
		{"POST,bound,/v1/ok,header", true, true, true},
		{"POST,bound,/v1/ok,bearer", true, true, true},
		{"GET,bound,/v1/ok,header", true, true, false},
		{"POST,bound,/v2/no,header", true, true, false},
		{"POST,bound,/v1,header", true, true, false}, // not under the prefix
		{"GET,other,/replay,header", true, false, false},
		{"GET,bound,/auth,auth", true, false, false},
		{"GET,bound,/path,path", true, false, false},
		{"GET,bound,/query,query", true, false, false},
		{"GET,bound,/none,none", true, false, false},
		{"GET,bound,/basic,basic", true, false, false},
		{"GET,bound,/x,cookie", false, false, false},
		{"GET,elsewhere,/x,header", false, false, false},
		{"GET,bound,x,header", false, false, false},
		{",bound,/x,header", false, false, false},
		{"GET bound /x header", false, false, false},
	}
	for _, c := range cases {
		e, ok := parseExchange(c.spec)
		if ok != c.ok || ok && (e.admitted(wide) != c.wide || e.admitted(narrow) != c.narr) {
			t.Errorf("%q: ok %v, admitted %v/%v; want %v, %v/%v", c.spec, ok, e.admitted(wide), e.admitted(narrow), c.ok, c.wide, c.narr)
		}
	}
	repo := NewSecret(scoped)
	for spec, want := range map[string]bool{"GET,bound,/octo/allowed.git/info/refs?service=git-upload-pack,basic": true, "POST,bound,/octo/allowed,auth": true, "GET,bound,/octo/allowed.git,basic": true, "GET,bound,/octo/allowed,header": false, "GET,other,/octo/allowed,basic": false,
		"GET,bound,/octo/allowed.git/../other.git/x,basic": false, "GET,bound,/octo/allowed.git%2F..%2Fother.git/x,basic": false, "GET,bound,//octo/allowed.git/x,basic": false, "GET,bound,/octo/allowed-x,basic": false, "GET,bound,/octo/allowedx/../allowed,basic": false, "GET,bound,/octo/allowed.gitx,basic": false, "GET,bound,/Octo/allowed,basic": false} {
		if e, ok := parseExchange(spec); !ok || e.admitted(repo) != want {
			t.Errorf("%q: ok %v, admitted %v under a repository scope; want %v", spec, ok, !want, want)
		}
	}
	for spec, want := range map[string]string{"POST,bound,/path,path": "POST https://b:443/path/v map[]", "GET,bound,//octo/allowed.git/x,basic": "GET https://b:443//octo/allowed.git/x map[Authorization:[Basic eC1hY2Nlc3MtdG9rZW46dg==]]"} {
		e, _ := parseExchange(spec)
		if req := e.request(targets{bound: "b", other: "o", addrs: map[string]string{"b": "1.2.3.4:443"}, value: "v"}); fmt.Sprintf("%s %s %v", req.Method, req.URL, req.Header) != want {
			t.Errorf("%q: request %s %s %v", spec, req.Method, req.URL, req.Header)
		}
	}
	e, _ := parseExchange("POST,bound,/path,path")
	seen := []request{{method: "POST", url: "/path/v"}, {method: "POST", url: "/pathology"}, {method: "GET", url: "/path/v"}, {method: "POST", url: "/path?k=v"}, {method: "POST", url: "/path"}}
	if got := e.at(&canary{seen: seen}); len(got) != 3 || got[0].url != "/path/v" || got[1].url != "/path?k=v" || got[2].url != "/path" {
		t.Errorf("at matched %v", got)
	}
}
