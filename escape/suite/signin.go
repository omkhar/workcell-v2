// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// The sign-in rows of I5. A secret's source is a sign-in flow: a token endpoint on one allowed name issues an access token and a refresh token, and the access
// token is bound to the API on the other name. The judge is the provider, serving both names from the one listener (serveTwo); the guest is an agent that signs
// in and uses the tokens as the row's steps say. The provider chose every real token, so it knows them where the guest shows its hand (its word, its scan) and
// where a canary saw them.

const (
	tokenPath   = "/oauth/token"
	accessMark  = "acce55" // the hex after secretPrefix that starts an access token
	refreshMark = "5efe5"  // and a refresh token, so that the scan's shape fits both
	form        = "application/x-www-form-urlencoded"
)

// signedInWant is the sandbox the rows want: withSecret, with the API as the first name and the token host as the second, and the secret from a sign-in flow at
// the token endpoint there.
var signedInWant = Want{Workspace: true, Allow: []string{"api.escape.test", "login.escape.test"}, Resolver: judgeResolver, Isolated: true, Secret: true, Source: "signin:login.escape.test" + tokenPath}

// grant is one request body a canary received, and what the token endpoint made of it: the refresh token it presented, and whether a pair was issued for it.
type grant struct {
	at, path, method, body, refresh string
	issued                          bool
}

// provider is the fake OAuth provider: what it issued, in order, and every body it was sent. mode is how a token response is framed: "" plain JSON, "chunked"
// in two chunks split inside the access token under a media type with a charset, "gzip" compressed.
type provider struct {
	mode   string
	mu     sync.Mutex
	issued [][2]string // access, refresh
	grants []grant
}

// serve is the responder of canary c: the token endpoint when token, a recorder of every body that answers 200 otherwise.
func (p *provider) serve(c *canary, token bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		m := map[string]any{}
		if json.Unmarshal(b, &m) != nil {
			if v, err := url.ParseQuery(string(b)); err == nil {
				for k := range v {
					m[k] = v.Get(k)
				}
			}
		}
		typ, _ := m["grant_type"].(string)
		refresh, _ := m["refresh_token"].(string)
		scope, _ := m["scope"].(string)
		g := grant{at: c.name, path: r.URL.Path, method: r.Method, body: string(b), refresh: refresh}
		p.mu.Lock()
		defer p.mu.Unlock()
		cur := len(p.issued) - 1
		switch {
		case !token || r.URL.Path != tokenPath || r.Method != http.MethodPost:
			if token {
				w.WriteHeader(http.StatusNotFound)
			}
		case typ == "authorization_code", typ == "refresh_token" && cur >= 0 && refresh == p.issued[cur][1] && scope != "bad":
			pair := [2]string{secretPrefix + accessMark + newToken()[:secretHex-len(accessMark)], secretPrefix + refreshMark + newToken()[:secretHex-len(refreshMark)]}
			p.issued = append(p.issued, pair)
			g.issued = true
			p.write(w, fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":3600,"refresh_token":%q}`, pair[0], pair[1]), pair[0])
		default: // what a provider says to a bad grant: the parameters back, with an error
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"invalid_grant","grant_type":%q,"refresh_token":%q}`, typ, refresh)
		}
		p.grants = append(p.grants, g)
	}
}

// write sends an issued pair's body as mode says.
func (p *provider) write(w http.ResponseWriter, body, access string) {
	w.Header().Set("Content-Type", "application/json")
	switch p.mode {
	case "gzip":
		w.Header().Set("Content-Encoding", "gzip")
		z := gzip.NewWriter(w)
		z.Write([]byte(body))
		z.Close()
	case "chunked":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		i := strings.Index(body, access) + len(access)/2
		io.WriteString(w, body[:i])
		w.(http.Flusher).Flush()
		io.WriteString(w, body[i:])
	default:
		io.WriteString(w, body)
	}
}

// flow is the guest's side: the tokens it holds now, as the responses gave them, and every token value it was ever given.
type flow struct {
	t               targets
	client          *http.Client
	access, refresh string
	got             []string
}

// signinProbe is an agent signing in. args: the API name and address, the token host's name and address, "-", the export path, the credential variable, then
// the steps: signin (POST a code grant), refresh and refresh-json (POST the refresh token it holds, as a form or as JSON), refresh-bad (the same with a scope
// the provider refuses), api (GET the API with the access token it holds as a bearer), replay (misuse both tokens), scan (persist what it got and hunt for real
// tokens as secretProbe does). It reports every token value it was given and each step's status, or the scan's findings.
func signinProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	if len(t.extra) < 3 {
		return Result{Status: "error", Detail: "want the export path, the credential variable and steps"}
	}
	f := &flow{t: t, client: &http.Client{Timeout: 4 * time.Second, Transport: transport(t.addrs, &tls.Config{}, false)}}
	var out []string
	for _, step := range t.extra[2:] {
		switch step {
		case "signin":
			out = append(out, f.post(step, t.other, tokenPath, form, "grant_type=authorization_code&code=c0de"))
		case "refresh":
			out = append(out, f.post(step, t.other, tokenPath, form, "grant_type=refresh_token&refresh_token="+f.refresh))
		case "refresh-json":
			out = append(out, f.post(step, t.other, tokenPath, "application/json", fmt.Sprintf(`{"grant_type":"refresh_token","refresh_token":%q}`, f.refresh)))
		case "refresh-bad":
			out = append(out, f.post(step, t.other, tokenPath, form, "grant_type=refresh_token&scope=bad&refresh_token="+f.refresh))
		case "api":
			out = append(out, f.get(step, t.bound, "/v1/me", "Authorization", "Bearer "+f.access))
		case "replay":
			out = append(out, f.replay()...)
		case "scan": // as a CLI keeps its tokens: on disk, then the hunt
			os.WriteFile(filepath.Join(t.extra[0], ".tokens"), []byte(strings.Join(f.got, "\n")+"\n"), 0o600)
			return secretProbe([]string{t.extra[0], t.extra[1]})
		default:
			return Result{Status: "error", Detail: "not a step: " + step}
		}
	}
	return Result{Status: "signed", Detail: "got=" + strings.Join(f.got, ",") + " " + strings.Join(out, " ")}
}

// send sends req and takes the tokens from a JSON body, gzipped or not, as a client does: those of a 2xx are the ones it holds from here. It reports
// "<label>=<status>".
func (f *flow) send(label string, req *http.Request) string {
	resp, err := f.client.Do(req)
	if err != nil {
		return label + "=" + dialFailed(err).Status
	}
	defer resp.Body.Close()
	var rd io.Reader = io.LimitReader(resp.Body, 1<<16)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if z, err := gzip.NewReader(rd); err == nil {
			rd = z
		}
	}
	b, _ := io.ReadAll(rd)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"access_token", "refresh_token"} {
		if v, _ := m[k].(string); v != "" {
			f.got = append(f.got, v)
			if resp.StatusCode < 300 && k == "access_token" {
				f.access = v
			} else if resp.StatusCode < 300 {
				f.refresh = v
			}
		}
	}
	return fmt.Sprintf("%s=%d", label, resp.StatusCode)
}

func (f *flow) post(label, name, path, ctype, body string) string {
	req, _ := http.NewRequest(http.MethodPost, f.t.url(name, path), strings.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	return f.send(label, req)
}

func (f *flow) get(label, name, path, header, value string) string {
	req, _ := http.NewRequest(http.MethodGet, f.t.url(name, path), nil)
	req.Header.Set(header, value)
	return f.send(label, req)
}

// replay misuses what the guest holds: the access token at the token host, in the wrong header and in a query; the refresh token as a bearer, in a grant at the
// API host, on another path of the token host and in a query of the endpoint. None may reach a canary as a real value.
func (f *flow) replay() []string {
	t := f.t
	return []string{
		f.get("other-host", t.other, "/userinfo", "Authorization", "Bearer "+f.access),
		f.get("wrong-header", t.bound, "/v1/replay", boundHeader, f.access),
		f.get("query", t.bound, "/v1/replay?access_token="+f.access, "Accept", "*/*"),
		f.get("refresh-bearer", t.bound, "/v1/replay", "Authorization", "Bearer "+f.refresh),
		f.post("wrong-host", t.bound, tokenPath, form, "grant_type=refresh_token&refresh_token="+f.refresh),
		f.post("wrong-path", t.other, "/oauth/revoke", form, "token="+f.refresh),
		f.get("refresh-query", t.other, tokenPath+"?grant_type=refresh_token&refresh_token="+f.refresh, "Accept", "*/*"),
	}
}

// signedIn serves the API host, the first allowed name, and the token host, the second, with the token endpoint framing its answers as mode says, runs the
// guest through the steps and holds the session to I5.
func signedIn(mode string, steps ...string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		p := &provider{mode: mode}
		api, login := &canary{name: s.Allow[0]}, &canary{name: s.Allow[1]}
		api.respond, login.respond = p.serve(api, false), p.serve(login, true)
		ns, stop, err := serveTwo(ctx, s, nil, api, login)
		if err != nil {
			return false, "", err
		}
		defer ns.stop()
		defer stop()
		r, err := s.Run(append([]string{api.name, api.addr, login.name, login.addr, "-", s.Guest, s.Secret.Env}, steps...)...)
		if err != nil {
			return false, "", err
		}
		return p.judge(r, api, login, steps)
	}
}

// leaked names the first of reals in text that admit does not allow there.
func leaked(reals []string, text string, admit func(string) bool) string {
	for _, v := range reals {
		if strings.Contains(text, v) && (admit == nil || !admit(v)) {
			return v
		}
	}
	return ""
}

func isRefresh(v string) bool { return strings.HasPrefix(v, secretPrefix+refreshMark) }

// judge holds the session to I5 after the steps: no token the provider issued is in the guest's hands, in its word or where its scan looked; none reached a
// canary but the access token as the API host's bearer and the refresh token in a grant at the token endpoint; and each step that was to carry a real token
// did, in order: the API saw the access token current at the time, the endpoint the refresh token. A provider that issued nothing was never reached, which
// proves nothing.
func (p *provider) judge(r Result, api, login *canary, steps []string) (bool, string, error) {
	p.mu.Lock()
	issued, grants := slices.Clone(p.issued), slices.Clone(p.grants)
	p.mu.Unlock()
	say := " (" + says(r) + ")"
	if r.Status != "signed" && r.Status != "scanned" {
		return false, "", fmt.Errorf("the probe did not run its steps%s", say)
	}
	if len(issued) == 0 {
		return false, "", fmt.Errorf("the token endpoint issued nothing: the sign-in never reached it%s", say)
	}
	var reals []string
	for _, pair := range issued {
		reals = append(reals, pair[0], pair[1])
	}
	if v := leaked(reals, r.Detail, nil); v != "" {
		return false, "the guest holds the real token " + v + say, nil
	}
	if slices.Contains(steps, "scan") {
		if strings.HasPrefix(r.Detail, "env=unset ") {
			return false, "the guest was given no placeholder" + say, nil
		}
		if strings.Contains(r.Detail, "+ ") {
			return false, "", fmt.Errorf("the guest found more secret-shaped values than it can name%s", say)
		}
	}
	for _, c := range []*canary{api, login} {
		for _, q := range c.requests() {
			if v := leaked(reals, q.url, nil); v != "" {
				return false, fmt.Sprintf("the real token %s reached the URL %s at %s%s", v, q.url, c.name, say), nil
			}
			for k, vs := range q.headers {
				joined := strings.Join(vs, " ")
				if v := leaked(reals, joined, func(v string) bool { return c == api && k == "Authorization" && joined == "Bearer "+v && !isRefresh(v) }); v != "" {
					return false, fmt.Sprintf("the real token %s reached the %s header of %s %s at %s%s", v, k, q.method, q.url, c.name, say), nil
				}
			}
		}
	}
	var endpoint []grant
	for _, g := range grants {
		token := g.at == login.name && g.path == tokenPath && g.method == http.MethodPost
		if v := leaked(reals, g.body, func(v string) bool { return token && g.refresh == v && isRefresh(v) }); v != "" {
			return false, fmt.Sprintf("the real token %s reached the body of %s %s at %s%s", v, g.method, g.path, g.at, say), nil
		}
		if token {
			endpoint = append(endpoint, g)
		}
	}
	var me []request
	for _, q := range api.requests() {
		if q.url == "/v1/me" {
			me = append(me, q)
		}
	}
	cur := -1
	for _, step := range steps {
		switch step {
		case "signin", "refresh", "refresh-json", "refresh-bad":
			if len(endpoint) == 0 {
				return false, fmt.Sprintf("the %s grant never reached the token endpoint%s", step, say), nil
			}
			g := endpoint[0]
			endpoint = endpoint[1:]
			if step != "signin" && (cur < 0 || g.refresh != issued[cur][1]) {
				return false, fmt.Sprintf("the %s grant reached the token endpoint with refresh_token %q, not the real refresh token%s", step, g.refresh, say), nil
			}
			if g.issued {
				cur++
			}
		case "api":
			if len(me) == 0 {
				return false, "the API host saw no request with the access token" + say, nil
			}
			q := me[0]
			me = me[1:]
			if cur < 0 || q.headers.Get("Authorization") != "Bearer "+issued[cur][0] {
				return false, fmt.Sprintf("the API host saw Authorization %q, not the real access token current then%s", q.headers.Get("Authorization"), say), nil
			}
		}
	}
	return true, fmt.Sprintf("%d token pairs issued, none in the guest; %s; %s%s", len(issued), api.served(), login.served(), say), nil
}
