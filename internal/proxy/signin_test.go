// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRefreshPlaceholder = "wcph-00000000000000000000000000000001"
	tokenEndpointPath      = "/oauth/token"
)

func TestNewSignIn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		source     string
		host, path string // "" host: refused
	}{
		{"signin:login.example.com/oauth/token", "login.example.com", "/oauth/token"},
		{"signin:LOGIN.example.com./oauth/token", "login.example.com", "/oauth/token"},
		{"signin:login.example.com/", "login.example.com", "/"},
		{"login.example.com/oauth/token", "", ""}, {"file:/oauth/token", "", ""}, {"signin:", "", ""},
		{"signin:login.example.com", "", ""}, {"signin:/oauth/token", "", ""},
		{"signin:login.example.com:8443/oauth/token", "", ""}, {"signin:login.example.com:443/oauth/token", "", ""},
		{"signin:https://login.example.com/oauth/token", "", ""}, {"signin:192.0.2.1/oauth/token", "", ""},
		{"signin:login.example.com/oauth/token?x=1", "", ""}, {"signin:login.example.com/oauth/token#f", "", ""},
		{"signin:login.example.com/oauth/tokén", "", ""}, {"signin:lögin.example/oauth/token", "", ""},
		{"signin:login.example.com/oauth/ token", "", ""}, {"signin:login.example.com/oauth/token\n", "", ""},
	}
	for _, tc := range cases {
		got, err := NewSignIn(tc.source)
		if (err == nil) != (tc.host != "") {
			t.Errorf("NewSignIn(%q) = %v, %v; want refused %t", tc.source, got, err, tc.host == "")
		}
		if err == nil && (got.Host != tc.host || got.Path != tc.path || !IsPlaceholder(got.Refresh)) {
			t.Errorf("NewSignIn(%q) = %+v, want host %q path %q and a placeholder", tc.source, got, tc.host, tc.path)
		}
	}
}

func TestSwapRefresh(t *testing.T) {
	t.Parallel()
	const form, js = "application/x-www-form-urlencoded", "application/json"
	ph := testRefreshPlaceholder
	cases := []struct {
		name, mediaType, body, real, want string
		asked                             bool
	}{
		{"form", form, "grant_type=refresh_token&refresh_token=" + ph, "sk-r", "grant_type=refresh_token&refresh_token=sk-r", true},
		{"form, escaped value", form, "refresh_token=" + ph + "&scope=x", "a+b/c=", "refresh_token=a%2Bb%2Fc%3D&scope=x", true},
		{"form, other field", form, "code=" + ph, "sk-r", "code=" + ph, false},
		{"form, suffixed", form, "refresh_token=" + ph + "x", "sk-r", "refresh_token=" + ph + "x", false},
		{"form, encoded key", form, "refresh%5Ftoken=" + ph, "sk-r", "refresh%5Ftoken=" + ph, false},
		{"json", js, `{"grant_type":"refresh_token","refresh_token":"` + ph + `"}`, "sk-r", `{"grant_type":"refresh_token","refresh_token":"sk-r"}`, true},
		{"json, spaced", js, `{ "refresh_token" : "` + ph + `" }`, `a"b`, `{"refresh_token":"a\"b"}`, true},
		{"json, other field", js, `{"code":"` + ph + `"}`, "sk-r", `{"code":"` + ph + `"}`, false},
		{"json, nested", js, `{"a":{"refresh_token":"` + ph + `"}}`, "sk-r", `{"a":{"refresh_token":"` + ph + `"}}`, false},
		{"json, array", js, `["` + ph + `"]`, "sk-r", `["` + ph + `"]`, false},
		{"json, not json", js, "refresh_token=" + ph, "sk-r", "refresh_token=" + ph, false},
		{"text", "text/plain", "refresh_token=" + ph, "sk-r", "refresh_token=" + ph, false},
		{"no type", "", `{"refresh_token":"` + ph + `"}`, "sk-r", `{"refresh_token":"` + ph + `"}`, false},
	}
	for _, tc := range cases {
		asked := 0
		real := func() ([]byte, error) { asked++; return []byte(tc.real), nil }
		got, err := swapRefresh(tc.mediaType, []byte(tc.body), ph, real)
		if err != nil || string(got) != tc.want || (asked == 1) != tc.asked {
			t.Errorf("%s: swapRefresh = %q, %v, asked %d; want %q, asked %t", tc.name, got, err, asked, tc.want, tc.asked)
		}
	}
	refused := func() ([]byte, error) { return nil, errors.New("not signed in") }
	if got, err := swapRefresh(form, []byte("refresh_token="+ph), ph, refused); err == nil || got != nil {
		t.Errorf("a withheld token: swapRefresh = %q, %v; want the error", got, err)
	}
}

func TestHide(t *testing.T) {
	t.Parallel()
	swaps := []swap{{[]byte("sk-acc/1"), testPlaceholder}, {[]byte("sk-ref-1"), testRefreshPlaceholder}, {nil, "wcph-none"}}
	cases := []struct{ name, body, want string }{
		{"json", `{"access_token":"sk-acc/1","token_type":"Bearer","expires_in":3600,"refresh_token":"sk-ref-1"}`,
			`{"access_token":"` + testPlaceholder + `","expires_in":3600,"refresh_token":"` + testRefreshPlaceholder + `","token_type":"Bearer"}`},
		{"escaped", `{"t":"sk-acc\/1","u":"sk-ref-1"}`, `{"t":"` + testPlaceholder + `","u":"` + testRefreshPlaceholder + `"}`},
		{"nested, inside a string", `{"a":[{"b":"x sk-ref-1 y"}],"c":"&"}`, `{"a":[{"b":"x ` + testRefreshPlaceholder + ` y"}],"c":"&"}`},
		{"in a key", `{"sk-ref-1":1}`, `{"` + testRefreshPlaceholder + `":1}`},
		{"big number", `{"n":12345678901234567890}`, `{"n":12345678901234567890}`},
		{"text", "error=sk-ref-1&x=sk-acc/1", "error=" + testRefreshPlaceholder + "&x=" + testPlaceholder},
		{"not json, no token", "{x", "{x"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := hide([]byte(tc.body), swaps); string(got) != tc.want {
			t.Errorf("%s: hide = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestTokenEndpoint: a path a case-folding router, or one that drops a ;param suffix from a segment, would serve as the endpoint is the endpoint; another path
// is not. Match only the exact spelling → the guest reads the unrewritten answer of /OAUTH/TOKEN → FAIL (I5).
func TestTokenEndpoint(t *testing.T) {
	t.Parallel()
	rule := TerminateRule{Host: "api.example.com", SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath}}
	p := &Proxy{signin: map[string][]TerminateRule{"login.example.com": {rule}}}
	cases := []struct {
		host, target string
		want         bool
	}{
		{"login.example.com", "/oauth/token", true},
		{"login.example.com", "/OAUTH/TOKEN", true},
		{"login.example.com", "/oauth/Token", true},
		{"login.example.com", "/oauth/token;jsessionid=1", true},
		{"login.example.com", "/oauth;v=2/token", true},
		{"login.example.com", "/oauth/token%3Bx", true},
		{"login.example.com", "/oauth/%54oken/", true},
		{"login.example.com", "/oauth/./x/../token?refresh_token=1", true},
		{"login.example.com", "/oauth/token;", true},
		{"login.example.com", "/oauth/tokens", false},
		{"login.example.com", "/oauth/token/x", false},
		{"login.example.com", "/oauth/revoke", false},
		{"login.example.com", "/oauth/token%2Fx", false},
		{"api.example.com", "/oauth/token", false},
	}
	for _, tc := range cases {
		u := must(url.Parse("https://" + tc.host + tc.target))
		if _, got := p.tokenEndpoint(tc.host, u); got != tc.want {
			t.Errorf("tokenEndpoint(%q, %q) = %t, want %t", tc.host, tc.target, got, tc.want)
		}
	}
}

// TestLearn: a 2xx that is not a JSON object, as encoding/json reads one, is refused whole and the broker is not asked, while a 2xx object goes to the broker
// and a non-2xx is only hidden. Pass a 2xx through after hiding → a BOM before the object carries both tokens to the guest → FAIL (I5).
func TestLearn(t *testing.T) {
	t.Parallel()
	pair := `{"access_token":"sk-acc-1","refresh_token":"sk-ref-1"}`
	cases := []struct {
		name, body string
		status     int
		want       string // "" is refused
		issued     bool
	}{
		{"object", pair, 200, `{"access_token":"` + testPlaceholder + `","refresh_token":"` + testRefreshPlaceholder + `"}`, true},
		{"object, 201", pair, 201, `{"access_token":"` + testPlaceholder + `","refresh_token":"` + testRefreshPlaceholder + `"}`, true},
		{"bom", "\ufeff" + pair, 200, "", false},
		{"trailing comma", `{"access_token":"sk-acc-1","refresh_token":"sk-ref-1",}`, 200, "", false},
		{"comment", "/*x*/" + pair, 200, "", false},
		{"nan", `{"access_token":"sk-acc-1","n":NaN}`, 200, "", false},
		{"two values", pair + pair, 200, "", false},
		{"array", `[` + pair + `]`, 200, "", false},
		{"string", `"sk-acc-1"`, 200, "", false},
		{"empty", "", 200, "", false},
		{"empty, 204", "", 204, "", false},
		{"form", "access_token=sk-acc-1", 200, "", false},
		{"error, not json", "error=invalid_grant&refresh_token=sk-ref-0", 400, "error=invalid_grant&refresh_token=" + testRefreshPlaceholder, false},
		{"error, bom", "\ufeff" + `{"refresh_token":"sk-ref-0"}`, 400, "\ufeff" + `{"refresh_token":"` + testRefreshPlaceholder + `"}`, false},
	}
	for _, tc := range cases {
		broker := &tokenBroker{refresh: []byte("sk-ref-0")}
		p := &Proxy{broker: broker}
		rule := TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}
		got, err := p.learn(rule, tc.status, []byte(tc.body))
		if (err == nil) != (tc.want != "") || string(got) != tc.want {
			t.Errorf("%s: learn = %q, %v; want %q", tc.name, got, err, tc.want)
		}
		if issued := strings.Contains(strings.Join(broker.calls, ";"), "issue"); issued != tc.issued || tc.issued != (string(broker.access) == "sk-acc-1") {
			t.Errorf("%s: broker calls %v, holds %q; want issued %t", tc.name, broker.calls, broker.access, tc.issued)
		}
	}
}

// tokenBroker holds one row's tokens, as the credential broker does.
type tokenBroker struct {
	mu              sync.Mutex
	access, refresh []byte
	calls           []string
	fail            error // Issue fails with it
}

func (b *tokenBroker) Lookup(_ context.Context, host, header string) ([]byte, error) {
	return b.release("lookup "+host+" "+header, false)
}

func (b *tokenBroker) Refresh(_ context.Context, host, header string) ([]byte, error) {
	return b.release("refresh "+host+" "+header, true)
}

func (b *tokenBroker) release(call string, refresh bool) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, call)
	v := b.access
	if refresh {
		v = b.refresh
	}
	if v == nil {
		return nil, errors.New("not signed in")
	}
	return bytes.Clone(v), nil
}

func (b *tokenBroker) Issue(_, _ string, access, refresh []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, fmt.Sprintf("issue %d %d", len(access), len(refresh)))
	if b.fail != nil {
		return b.fail
	}
	if len(access) > 0 {
		b.access = access
	}
	if len(refresh) > 0 {
		b.refresh = refresh
	}
	return nil
}

func (b *tokenBroker) Tokens(string, string) ([]byte, []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.access), bytes.Clone(b.refresh)
}

// provider is a fake token endpoint on login.example.com and API on api.example.com:
// a code grant or the current refresh token gets a new pair, another grant
// 400 with the refresh token echoed; the API echoes Authorization. mode
// frames a pair: "chunked" splits it inside a token, "gzip" compresses it,
// "escaped" spells the tokens with JSON escapes, "big" pads it past the bound.
type provider struct {
	mu     sync.Mutex
	mode   string
	issued int
	seen   []string // "<method> <host><path> auth=<Authorization> body=<body>"
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, fmt.Sprintf("%s %s%s auth=%s body=%s", r.Method, r.Host, r.URL.RequestURI(), r.Header.Get("Authorization"), body))
	if r.Host != "login.example.com" || r.URL.Path != tokenEndpointPath || r.Method != http.MethodPost {
		return
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		m = map[string]any{}
		q, _ := url.ParseQuery(string(body))
		for k, v := range q {
			m[k] = v[0]
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if m["scope"] == "bad" || m["grant_type"] != "authorization_code" && (p.issued == 0 || m["refresh_token"] != fmt.Sprintf("sk-ref-%d", p.issued)) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","refresh_token":%q}`, m["refresh_token"])
		return
	}
	p.issued++
	access, refresh := fmt.Sprintf("sk-acc-%d", p.issued), fmt.Sprintf("sk-ref-%d", p.issued)
	pair := fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":3600,"refresh_token":%q}`, access, refresh)
	switch p.mode {
	case "gzip":
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		_, _ = z.Write([]byte(pair))
		_ = z.Close()
	case "chunked":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		i := strings.Index(pair, access) + len(access)/2
		_, _ = io.WriteString(w, pair[:i])
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, pair[i:])
	case "escaped":
		fmt.Fprintf(w, `{"access_token":"sk-acc-%d","refresh_token":"sk-ref-%d"}`, p.issued, p.issued)
	case "big":
		fmt.Fprintf(w, `{"pad":%q,"access_token":%q}`, strings.Repeat("x", maxTokenBody), access)
	default:
		_, _ = io.WriteString(w, pair)
	}
}

// signinFixture terminates api.example.com, where the rule binds the access token as a bearer, and login.example.com, the token host, both served by p.
func signinFixture(t *testing.T, p *provider, broker Broker) (*http.Client, TerminateRule, *Proxy, *recorder) {
	t.Helper()
	server := httptest.NewTLSServer(p)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	px, log, _ := testProxy(t, "api.example.com:443 login.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	px.upstreamRoots = roots
	ca := must(NewSessionCA([]string{"api.example.com", "login.example.com"}, time.Now().Add(time.Hour)))
	rule := TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: "login.example.com", Path: tokenEndpointPath, Refresh: testRefreshPlaceholder}}
	must(0, px.Terminate(ca, broker, []TerminateRule{rule}))
	return clientVia(listen(t, px, 443), caPool(t, ca)), rule, px, log
}

// send returns the status and body of one request, and fails the test on a body that carries a real token: the guest never reads one (I5).
func send(t *testing.T, c *http.Client, method, target, ctype, body string, header ...string) (int, string) {
	t.Helper()
	req := must(http.NewRequest(method, target, strings.NewReader(body)))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	code, got := do(t, c, req)
	if strings.Contains(got, "sk-acc") || strings.Contains(got, "sk-ref") {
		t.Errorf("%s %s: the guest read a real token: %d %q", method, target, code, got)
	}
	return code, got
}

// TestSignInFlow: before a sign-in the access placeholder is refused; a sign-in's answer reaches the guest with the two placeholders in place of the tokens and
// a fresh Content-Length; the access placeholder then goes out as the real access token, the refresh placeholder in a form or a JSON grant as the real refresh
// token, and after a refresh the same access placeholder is the new token; a 400 that echoes the refresh token is hidden too; and either placeholder anywhere
// else is refused or passed as it is. Drop tokenResponse → the guest reads a real token → FAIL.
func TestSignInFlow(t *testing.T) {
	t.Parallel()
	p := &provider{}
	c, rule, px, log := signinFixture(t, p, &tokenBroker{})
	api, login := "https://api.example.com", "https://login.example.com"
	form, js := "application/x-www-form-urlencoded", "application/json"
	bearer, refreshBearer := "Bearer "+testPlaceholder, "Bearer "+testRefreshPlaceholder
	tokens := `{"access_token":"` + testPlaceholder + `","expires_in":3600,"refresh_token":"` + testRefreshPlaceholder + `","token_type":"Bearer"}`
	steps := []struct {
		name, method, target, ctype, body, header string
		code                                      int
		want                                      string // the body, or "" for any
		saw                                       string // what the provider saw, or "" for nothing
	}{
		{"api before sign-in", "GET", api + "/v1/me", "", "", bearer, 502, "", ""},
		{"sign-in", "POST", login + tokenEndpointPath, form, "grant_type=authorization_code&code=c0de", "", 200, tokens, "POST login.example.com/oauth/token auth= body=grant_type=authorization_code&code=c0de"},
		{"api", "GET", api + "/v1/me", "", "", bearer, 200, "", "GET api.example.com/v1/me auth=Bearer sk-acc-1 body="},
		{"refresh", "POST", login + tokenEndpointPath, form, "grant_type=refresh_token&refresh_token=" + testRefreshPlaceholder, "", 200, tokens, "POST login.example.com/oauth/token auth= body=grant_type=refresh_token&refresh_token=sk-ref-1"},
		{"api after refresh", "GET", api + "/v1/me", "", "", bearer, 200, "", "GET api.example.com/v1/me auth=Bearer sk-acc-2 body="},
		{"refresh as json", "POST", login + tokenEndpointPath, js, `{"grant_type":"refresh_token","refresh_token":"` + testRefreshPlaceholder + `"}`, "", 200, tokens, `POST login.example.com/oauth/token auth= body={"grant_type":"refresh_token","refresh_token":"sk-ref-2"}`},
		{"bad grant echoes the refresh token", "POST", login + tokenEndpointPath, form, "grant_type=refresh_token&scope=bad&refresh_token=" + testRefreshPlaceholder, "", 400, `{"error":"invalid_grant","refresh_token":"` + testRefreshPlaceholder + `"}`, "POST login.example.com/oauth/token auth= body=grant_type=refresh_token&scope=bad&refresh_token=sk-ref-3"},
		{"access at the token host", "GET", login + "/userinfo", "", "", bearer, 502, "", ""},
		{"access in a query", "GET", api + "/v1/me?access_token=" + testPlaceholder, "", "", "", 502, "", ""},
		{"refresh as a bearer", "GET", api + "/v1/me", "", "", refreshBearer, 502, "", ""},
		{"refresh in the endpoint's query", "GET", login + tokenEndpointPath + "?refresh_token=" + testRefreshPlaceholder, "", "", "", 502, "", ""},
		{"refresh in another field", "POST", login + tokenEndpointPath, js, `{"code":"` + testRefreshPlaceholder + `"}`, "", 502, "", ""},
		{"access in the grant", "POST", login + tokenEndpointPath, form, "grant_type=refresh_token&refresh_token=" + testPlaceholder, "", 502, "", ""},
		{"encoded endpoint path", "POST", login + "/oauth/%74oken", form, "grant_type=authorization_code&code=c0de", "", 200, tokens, ""},
		{"refresh at the API host", "POST", api + tokenEndpointPath, form, "refresh_token=" + testRefreshPlaceholder, "", 200, "", "POST api.example.com/oauth/token auth= body=refresh_token=" + testRefreshPlaceholder},
		{"refresh at another path", "POST", login + "/oauth/revoke", form, "token=" + testRefreshPlaceholder, "", 200, "", "POST login.example.com/oauth/revoke auth= body=token=" + testRefreshPlaceholder},
	}
	for _, s := range steps {
		before := len(p.seen)
		code, body := send(t, c, s.method, s.target, s.ctype, s.body, "Authorization", s.header)
		if code != s.code || s.want != "" && body != s.want {
			t.Errorf("%s: got (%d, %q), want (%d, %q)", s.name, code, body, s.code, s.want)
		}
		p.mu.Lock()
		saw := strings.Join(p.seen[before:], ";")
		p.mu.Unlock()
		if s.saw != "" && saw != s.saw || s.saw == "" && s.code != 200 && saw != "" {
			t.Errorf("%s: the provider saw %q, want %q", s.name, saw, s.saw)
		}
	}
	reasons := map[string]uint64{}
	for _, d := range denies(t, px, log) {
		reasons[d.Reason]++
	}
	if want := map[string]uint64{"broker_denied": 1, "placeholder_unswapped": 6}; fmt.Sprint(reasons) != fmt.Sprint(want) {
		t.Errorf("deny reasons = %v, want %v", reasons, want)
	}
	_ = rule
}

// TestTokenAnswerFramings: a pair split inside a token across chunks, under a media type with a charset, one gzipped, and one spelt with JSON escapes all reach
// the guest as placeholders; an answer over the bound, and one the broker cannot record, are refused whole.
func TestTokenAnswerFramings(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"chunked", "gzip", "escaped", "big", "unrecorded"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			broker := &tokenBroker{}
			p := &provider{mode: mode}
			if mode == "unrecorded" {
				broker.fail = errors.New("ledger failed")
			}
			c, _, px, log := signinFixture(t, p, broker)
			code, body := send(t, c, "POST", "https://login.example.com"+tokenEndpointPath, "application/x-www-form-urlencoded", "grant_type=authorization_code&code=c0de")
			switch mode {
			case "big", "unrecorded":
				if code != 502 || body != "" {
					t.Errorf("got (%d, %q), want an empty 502", code, body)
				}
				if d := denies(t, px, log); len(d) != 1 || d[0].Reason != "token_answer_refused" || d[0].Host != "login.example.com" {
					t.Errorf("deny lines = %+v, want one token_answer_refused for login.example.com", d)
				}
				return
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(body), &m); code != 200 || err != nil || m["access_token"] != testPlaceholder || m["refresh_token"] != testRefreshPlaceholder {
				t.Errorf("got (%d, %q), want 200 with the placeholders", code, body)
			}
			if string(broker.access) != "sk-acc-1" || string(broker.refresh) != "sk-ref-1" {
				t.Errorf("broker holds (%q, %q), want the pair", broker.access, broker.refresh)
			}
		})
	}
}

func TestTerminateRefusesBadSignIn(t *testing.T) {
	t.Parallel()
	p, _, _ := testProxy(t, "api.example.com:443 db.example:5432", nil, "")
	rule := func(host, path string) TerminateRule {
		return TerminateRule{Host: "api.example.com", Header: "authorization", Placeholder: testPlaceholder, SignIn: &SignIn{Host: host, Path: path, Refresh: testRefreshPlaceholder}}
	}
	for name, rules := range map[string][]TerminateRule{
		"off allowlist": {rule("login.example.com", "/t")},
		"plain port":    {rule("db.example", "/t")},
		"twice":         {rule("api.example.com", "/t"), {Host: "api.example.com", Header: "x-api-key", Placeholder: testAuthPlaceholder, SignIn: &SignIn{Host: "api.example.com", Path: "/t", Refresh: testRefreshPlaceholder}}},
	} {
		if err := p.Terminate(nil, nil, rules); err == nil {
			t.Errorf("%s: Terminate succeeded, want refusal", name)
		}
	}
}

// FuzzSwapRefresh: a body the guest wrote never makes swapRefresh panic; one that does not carry the placeholder in its own field comes back as it was, with
// the token not asked for, and one that does carries the token.
func FuzzSwapRefresh(f *testing.F) {
	f.Add(0, "grant_type=refresh_token&refresh_token="+testRefreshPlaceholder)
	f.Add(1, `{"refresh_token":"`+testRefreshPlaceholder+`"}`)
	f.Add(1, `{"a":[1,"`+testRefreshPlaceholder+`"],"refresh_token":null}`)
	f.Fuzz(func(t *testing.T, kind int, body string) {
		mediaType := []string{"application/x-www-form-urlencoded", "application/json", "text/plain"}[(kind%3+3)%3]
		asked := false
		got, err := swapRefresh(mediaType, []byte(body), testRefreshPlaceholder, func() ([]byte, error) { asked = true; return []byte("sk-r+1"), nil })
		if err != nil || !asked && string(got) != body || asked && !bytes.Contains(got, []byte("sk-r")) {
			t.Fatalf("swapRefresh(%q, %q) = %q, %v, asked %t", mediaType, body, got, err, asked)
		}
	})
}

// FuzzHide: whatever the token endpoint answers, no real value is left in the bytes the guest reads, nor in any string a JSON reading of them holds.
func FuzzHide(f *testing.F) {
	f.Add(`{"access_token":"sk-acc\/1","refresh_token":"sk-ref-1","n":1e400}`)
	f.Add("sk-acc/1 sk-ref-1")
	f.Add(`"sk-acc\/1"0`) // a first value a lenient client reads, then what is not JSON
	swaps := []swap{{[]byte("sk-acc/1"), testPlaceholder}, {[]byte("sk-ref-1"), testRefreshPlaceholder}}
	f.Fuzz(func(t *testing.T, body string) {
		got := hide([]byte(body), swaps)
		var v any
		if dec := json.NewDecoder(bytes.NewReader(got)); dec.Decode(&v) == nil {
			var strs []string
			var walk func(any)
			walk = func(v any) {
				switch x := v.(type) {
				case string:
					strs = append(strs, x)
				case map[string]any:
					for k, e := range x {
						strs = append(strs, k)
						walk(e)
					}
				case []any:
					for _, e := range x {
						walk(e)
					}
				}
			}
			walk(v)
			got = append(got, []byte(strings.Join(strs, " "))...)
		}
		for _, s := range swaps {
			if bytes.Contains(got, s.real) {
				t.Fatalf("hide(%q) = %q, carries %q", body, got, s.real)
			}
		}
	})
}
