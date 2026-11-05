// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I6 probes and the placeholder replay drive HTTPS requests from the
// guest to canaries the judge runs under the session's two allowed names:
// the bound one (the one a secret is bound to, when there is one) and
// another. A request names a host three ways, in the TLS SNI, in the HTTP
// Host or :authority, and in the URL; the probes make them disagree, hide
// the SNI with ECH, or let a redirect carry the credential from the bound
// name to the other. What a canary received is the evidence; the guest's
// word is not.

// request is one HTTP request a canary received.
type request struct {
	sni, host, proto, method, url string
	ech                           bool // ECH was offered and accepted
	headers                       http.Header
}

// canary is one HTTPS server the judge runs for one allowed name, and what
// it received. ech is the config list under which it accepts a hidden name;
// respond writes the response once the request is recorded (else 200);
// leafFor is the name its certificate is for instead of its own. Canaries
// share one listener (serveCanaries), told apart by the connection's SNI.
type canary struct {
	name, addr string
	ech        []byte
	respond    http.HandlerFunc
	leafFor    string
	mu         sync.Mutex
	seen       []request
}

// serveCanaries serves the canaries on ln, which is theirs from here, under
// one certificate of the suite's authority for all their names. A request
// is the canary's whose name the SNI gave, the first's when none did.
func serveCanaries(ln net.Listener, keys []tls.EncryptedClientHelloKey, cs ...*canary) (func(), error) {
	var names []string
	for _, c := range cs {
		c.addr = ln.Addr().String()
		if n := cmp.Or(c.leafFor, c.name); !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	cfg, err := certificate(names...)
	if err != nil {
		ln.Close()
		return nil, err
	}
	if keys != nil {
		cfg.EncryptedClientHelloKeys, cfg.MinVersion = keys, tls.VersionTLS13
	}
	srv := &http.Server{
		TLSConfig:   cfg,
		ReadTimeout: 3 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := cs[0]
			for _, k := range cs {
				if k.name == r.TLS.ServerName {
					c = k
				}
			}
			c.mu.Lock()
			c.seen = append(c.seen, request{sni: r.TLS.ServerName, host: r.Host, proto: r.Proto, method: r.Method,
				url: r.URL.String(), ech: r.TLS.ECHAccepted, headers: r.Header.Clone()})
			c.mu.Unlock()
			if c.respond != nil {
				c.respond(w, r)
			}
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() { srv.ServeTLS(ln, "", "") })
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		srv.Close()
		wg.Wait()
	}, nil
}

// requests is a copy of what the canary has received, taken under its lock,
// so that nothing else ever holds the lock while it reads.
func (c *canary) requests() []request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.seen)
}

// carried says whether a request's URL or headers held the secret, the
// header it is bound to not counted.
func (c *canary) carried(secret, bound string) (string, bool) {
	for _, r := range c.requests() {
		if strings.Contains(r.url, secret) {
			return fmt.Sprintf("the URL of %s %s (Host %s) at %s", r.method, r.url, r.host, c.name), true
		}
		for k, vs := range r.headers {
			if k != http.CanonicalHeaderKey(bound) && strings.Contains(strings.Join(vs, " "), secret) {
				return fmt.Sprintf("the %s header of %s %s (Host %s) at %s", k, r.method, r.url, r.host, c.name), true
			}
		}
	}
	return "", false
}

// served describes what the canary received, or says it saw nothing.
func (c *canary) served() string {
	rs := c.requests()
	if len(rs) == 0 {
		return c.name + " saw nothing"
	}
	var out []string
	for _, r := range rs {
		s := fmt.Sprintf("%s %s %s (SNI %s, Host %s", r.proto, r.method, r.url, r.sni, r.host)
		if r.ech {
			s += ", ECH accepted"
		}
		out = append(out, s+")")
	}
	return c.name + " served " + strings.Join(out, "; ")
}

// wellFormed says whether the request named the canary's name in the SNI and
// the Host alike, in the open.
func (r request) wellFormed(name string) bool {
	h, _, err := net.SplitHostPort(r.host)
	if err != nil {
		h = r.host
	}
	return r.sni == name && h == name && !r.ech
}

// echKeys makes an ECH key pair whose public name is publicName: the config
// list a client is given, and the keys the canary holds (RFC 9849).
func echKeys(publicName string) ([]byte, []tls.EncryptedClientHelloKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var body []byte
	body = append(body, 1)                             // config_id
	body = binary.BigEndian.AppendUint16(body, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	body = binary.BigEndian.AppendUint16(body, 32)     // public_key
	body = append(body, key.PublicKey().Bytes()...)    //
	body = binary.BigEndian.AppendUint16(body, 4)      // cipher_suites
	body = binary.BigEndian.AppendUint16(body, 0x0001) // HKDF-SHA256
	body = binary.BigEndian.AppendUint16(body, 0x0001) // AES-128-GCM
	body = append(body, 0)                             // maximum_name_length
	body = append(body, byte(len(publicName)))         // public_name
	body = append(body, publicName...)                 //
	body = binary.BigEndian.AppendUint16(body, 0)      // extensions
	cfg := binary.BigEndian.AppendUint16(nil, 0xfe0d)  // version
	cfg = append(binary.BigEndian.AppendUint16(cfg, uint16(len(body))), body...)
	list := append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...)
	return list, []tls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}}, nil
}

// targets is what every HTTPS probe is given: the bound name and the other,
// each with the address of the judge's canary for it, the variable holding
// the credential as the guest sees it ("-" for none), and whatever else the
// test adds.
type targets struct {
	bound, other string
	addrs        map[string]string
	value        string
	header       http.Header // the credential in the header it is bound to
	extra        []string
}

func parseTargets(args []string) (targets, Result) {
	if len(args) < 5 {
		return targets{}, Result{Status: "error", Detail: "want two names with addresses and the credential variable"}
	}
	t := targets{bound: args[0], other: args[2], addrs: map[string]string{args[0]: args[1], args[2]: args[3]}, header: http.Header{}, extra: args[5:]}
	if args[4] != "-" {
		if t.value = os.Getenv(args[4]); t.value == "" {
			return targets{}, Result{Status: "no-credential", Detail: args[4] + " is empty"}
		}
		t.header.Set(boundHeader, t.value)
	}
	return t, Result{}
}

func (t targets) url(name, path string) string {
	return "https://" + name + ":" + port(t.addrs[name]) + path
}

func (t targets) get(name, path string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, t.url(name, path), nil)
	req.Header = t.header.Clone()
	return req
}

// check sends the bound name the request a well-behaved client would: SNI,
// Host and URL all name it, in the open. A correct product serves it, so the
// judge can tell "refused the attack" from "reached nothing".
func (t targets) check() string {
	return "check=" + report(fetch(t.get(t.bound, "/check"), t.addrs, &tls.Config{}, false)).Status
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// fetch sends req from the guest to the name in its URL, dialled at the
// address the judge gave for the name when nothing else resolves it (the
// address of a canary is chosen per run), through whatever proxy the
// environment names. The guest is the attacker: it verifies nothing, and it
// forwards every header, credential included, wherever a redirect points.
func fetch(req *http.Request, addrs map[string]string, cfg *tls.Config, h2 bool) (*http.Response, error) {
	return fetchWithin(req, addrs, cfg, h2, 4*time.Second)
}

// fetchWithin is fetch with the whole exchange bounded by within.
func fetchWithin(req *http.Request, addrs map[string]string, cfg *tls.Config, h2 bool, within time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: within, Transport: transport(addrs, cfg, h2), CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		r.Header = via[0].Header.Clone()
		return nil
	}}
	resp, err := client.Do(req)
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
	return resp, err
}

// transport is the guest's transport of fetch: dialling the judge's address
// for a name, verifying nothing, HTTP/1.1 unless h2.
func transport(addrs map[string]string, cfg *tls.Config, h2 bool) *http.Transport {
	cfg.InsecureSkipVerify = true //nolint:gosec // the probe is the attacker
	tr := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   cfg,
		ForceAttemptHTTP2: h2,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, err := net.SplitHostPort(addr); err == nil && addrs[host] != "" {
				addr = addrs[host]
			}
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // HTTP/1.1 only
	}
	return tr
}

// report turns a response, or the error instead, into a result.
func report(resp *http.Response, err error) Result {
	if err != nil {
		return dialFailed(err)
	}
	return Result{Status: "served", Detail: fmt.Sprintf("%s %d from %s", resp.Proto, resp.StatusCode, resp.Request.URL.Host)}
}

// after prefixes the hostile request's result with the check's.
func after(check string, r Result) Result {
	r.Detail = check + "; " + r.Detail
	return r
}

// mismatchProbe opens TLS to the bound name and asks, on that connection, for
// the other name in the Host header or the :authority pseudo-header.
func mismatchProbe(h2 bool) Probe {
	return func(args []string) Result {
		t, bad := parseTargets(args)
		if bad.Status != "" {
			return bad
		}
		check := t.check()
		req := t.get(t.bound, "/mismatch")
		req.Host = t.other + ":" + port(t.addrs[t.other])
		return after(check, report(fetch(req, t.addrs, &tls.Config{ServerName: t.bound}, h2)))
	}
}

// echProbe connects to the bound name with the name hidden by ECH under the
// config list in args[5] (base64), whose public name is the other.
func echProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	if len(t.extra) != 1 {
		return Result{Status: "error", Detail: "want an ECH config list"}
	}
	list, err := base64.StdEncoding.DecodeString(t.extra[0])
	if err != nil {
		return Result{Status: "error", Detail: "ECH config list: " + err.Error()}
	}
	check := t.check()
	cfg := &tls.Config{ServerName: t.bound, MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list,
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil }}
	resp, err := fetch(t.get(t.bound, "/ech"), t.addrs, cfg, false)
	var rejected *tls.ECHRejectionError
	if errors.As(err, &rejected) {
		return after(check, Result{Status: "ech-rejected", Detail: err.Error()})
	}
	r := report(resp, err)
	if err == nil && resp.TLS != nil && resp.TLS.ECHAccepted {
		r.Status = "ech-accepted"
	}
	return after(check, r)
}

// run gives the probe its targets, for a canary that accepts ECH the
// config list, and whatever else the judge adds.
func run(s Session, bound, other *canary, extra ...string) (Result, error) {
	credential := s.Secret.Env
	if credential == "" {
		credential = "-"
	}
	args := []string{bound.name, bound.addr, other.name, other.addr, credential}
	if bound.ech != nil {
		args = append(args, base64.StdEncoding.EncodeToString(bound.ech))
	}
	return s.Run(append(args, extra...)...)
}

// strictJudge expects every request at the bound name to name it in the
// open, in the SNI and the Host alike, and the other name to see nothing. A
// request that named another host, hid its name, or reached the other name
// was a mismatch served; one the product rewrote to the name it terminated
// for is as a client's own. No request at all means the product reached
// nothing, which proves nothing.
func strictJudge(s Session, bound, other *canary) (bool, string, error) {
	r, err := run(s, bound, other)
	if err != nil {
		return false, "", err
	}
	rs := bound.requests()
	for _, q := range rs {
		if !q.wellFormed(bound.name) {
			return false, fmt.Sprintf("%s served %s %s with SNI %s and Host %s, ECH %v (guest says %s: %s)", bound.name, q.proto, q.method, q.sni, q.host, q.ech, r.Status, r.Detail), nil
		}
	}
	if len(other.requests()) > 0 {
		return false, fmt.Sprintf("%s (the connection named %s; guest says %s: %s)", other.served(), bound.name, r.Status, r.Detail), nil
	}
	if r.Status == "ech-accepted" {
		return false, "the guest completed an ECH handshake: " + r.Detail, nil
	}
	if len(rs) == 0 {
		return false, "", fmt.Errorf("%s saw nothing, not even the well-formed request a correct product serves (guest says %s: %s)", bound.name, r.Status, r.Detail)
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", bound.served(), r.Status, r.Detail), nil
}

// redirectTo has the bound name send the guest on to the other; the guest
// follows, headers and all (fetchWithin).
func redirectTo(other *canary) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+other.name+":"+port(other.addr)+"/leak", http.StatusFound)
	}
}

// The placeholder rows have the guest send a table of requests, each
// carrying the credential it holds somewhere, and hold the canaries to the
// swap rule: the credential alone, behind "Bearer ", or as the password of
// a Basic value, in the bound header of a request to the bound name, of the
// method, under the path and within a repository the binding names when it
// names them, reaches the canary as the real value; anything else reaches
// no canary. An exchange is "method,name,path,where": name is bound or
// other, and where says where the credential goes: header (x-api-key),
// bearer (x-api-key, "Bearer "), auth (Authorization, "Bearer "), basic
// (Authorization, as git sends a token: Basic base64("x-access-token:" +
// credential)), path (a last element of the path), query (?key=), or none.
type exchange struct{ method, name, path, where string }

// headerOf is the header each where kind puts the credential in; none for the rest.
var headerOf = map[string]string{"header": boundHeader, "bearer": boundHeader, "auth": "authorization", "basic": "authorization"}

// credential is the value of the exchange's header for the credential v.
func (e exchange) credential(v string) string {
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+v))
	return cmp.Or(map[string]string{"bearer": "Bearer " + v, "auth": "Bearer " + v, "basic": basic}[e.where], v)
}

func parseExchange(spec string) (exchange, bool) {
	f := strings.Split(spec, ",")
	if len(f) != 4 || f[0] == "" || f[1] != "bound" && f[1] != "other" || !strings.HasPrefix(f[2], "/") ||
		!slices.Contains([]string{"header", "bearer", "auth", "basic", "path", "query", "none"}, f[3]) {
		return exchange{}, false
	}
	return exchange{f[0], f[1], f[2], f[3]}, true
}

// admitted says whether the binding swaps the exchange's credential: it is
// in the bound header, to the bound name, of the bound method, under the
// bound path, and, when the binding names repositories, the path as sent
// and the path decoded and cleaned both lie within one of them (SPEC I5: a
// placeholder is useless anywhere else).
func (e exchange) admitted(sec sandbox.Secret) bool {
	raw, _, _ := strings.Cut(e.path, "?")
	decoded, _ := url.PathUnescape(raw)
	return e.name == "bound" && strings.EqualFold(headerOf[e.where], sec.Header) && (sec.Method == "" || sec.Method == e.method) && strings.HasPrefix(e.path, sec.Path) &&
		(len(sec.Repos) == 0 || slices.ContainsFunc(sec.Repos, func(repo string) bool { return within(raw, repo) && within(path.Clean(decoded), repo) }))
}

// within says whether p is /repo or /repo.git, or lies under either.
func within(p, repo string) bool {
	return slices.ContainsFunc([]string{"/" + repo, "/" + repo + ".git"}, func(root string) bool { return p == root || strings.HasPrefix(p, root+"/") })
}

// request is the exchange as the guest sends it, with its credential.
func (e exchange) request(t targets) *http.Request {
	name, path := t.bound, e.path
	if e.name == "other" {
		name = t.other
	}
	switch e.where {
	case "path":
		path += "/" + t.value
	case "query":
		path += "?key=" + t.value
	}
	req, _ := http.NewRequest(e.method, t.url(name, path), nil)
	if h := headerOf[e.where]; h != "" {
		req.Header.Set(h, e.credential(t.value))
	}
	return req
}

// at lists the canary's requests of the exchange's method under its path.
func (e exchange) at(c *canary) []request {
	var out []request
	for _, r := range c.requests() {
		if r.method == e.method && (r.url == e.path || strings.HasPrefix(r.url, e.path+"/") || strings.HasPrefix(r.url, e.path+"?")) {
			out = append(out, r)
		}
	}
	return out
}

// exchangeProbe sends every exchange in args[5:], in order, and reports the
// credential it holds and what each got.
func exchangeProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	detail := "sent=" + t.value
	for i, spec := range t.extra {
		e, ok := parseExchange(spec)
		if !ok {
			return Result{Status: "error", Detail: "not an exchange: " + spec}
		}
		detail += fmt.Sprintf(" %d=%s", i, report(fetch(e.request(t), t.addrs, &tls.Config{}, false)).Status)
	}
	return Result{Status: "sent", Detail: detail}
}

// swapJudge has the guest send the exchanges and holds the canaries to the
// swap rule: an exchange the binding admits must have reached the bound
// canary with the real value in the bound header, no other may have
// reached either canary, nor anything the admitted ones did not send (a
// path rewritten on the way), and the other name sees nothing at all. The
// real value anywhere else, or in the guest's own hands, is a leak.
// Canaries that saw nothing proved nothing.
func swapJudge(specs ...string) func(s Session, bound, other *canary) (bool, string, error) {
	return func(s Session, bound, other *canary) (bool, string, error) {
		r, err := run(s, bound, other, specs...)
		if err != nil {
			return false, "", err
		}
		say := " (" + says(r) + ")"
		if len(bound.requests())+len(other.requests()) == 0 {
			return false, "", fmt.Errorf("no canary saw the guest, not even %s, which a correct product serves%s", bound.name, say)
		}
		expected := 0
		for i, spec := range specs {
			e, ok := parseExchange(spec)
			if !ok {
				return false, "", errors.New("not an exchange: " + spec)
			}
			c := bound
			if e.name == "other" {
				c = other
			}
			got, admitted := e.at(c), e.admitted(s.Secret)
			want := e.credential(s.Secret.Value)
			switch {
			case !admitted && len(got) > 0:
				return false, fmt.Sprintf("exchange %d (%s), which the binding does not admit, reached %s %d times%s", i, spec, c.name, len(got), say), nil
			case admitted && len(got) == 0:
				return false, fmt.Sprintf("exchange %d (%s), which the binding admits, reached no canary%s", i, spec, say), nil
			case admitted && got[0].headers.Get(s.Secret.Header) != want:
				return false, fmt.Sprintf("exchange %d (%s) reached %s with the bound header holding %q, not the real value%s", i, spec, c.name, got[0].headers.Get(s.Secret.Header), say), nil
			}
			expected += len(got)
		}
		if n := len(bound.requests()); n > expected {
			return false, fmt.Sprintf("%s, %d requests, of which the admitted exchanges account for %d%s", bound.served(), n, expected, say), nil
		}
		if what, ok := bound.carried(s.Secret.Value, s.Secret.Header); ok {
			return false, "the real secret reached " + what + say, nil
		}
		if len(other.requests()) > 0 {
			return false, other.served() + ", though nothing was bound to it" + say, nil
		}
		if strings.Contains(r.Detail, s.Secret.Value) {
			return false, "the guest holds the real secret" + say, nil
		}
		return true, fmt.Sprintf("%s; %s%s", bound.served(), other.served(), say), nil
	}
}
