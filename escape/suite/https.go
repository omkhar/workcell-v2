// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
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
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// The I6 probes and the placeholder replay drive HTTPS requests from the
// guest to canaries the judge runs under the session's two allowed names:
// the one the secret is bound to and another. A request names a host three
// ways, in the TLS SNI, in the HTTP Host or :authority, and in the URL; the
// probes make them disagree, hide the SNI with ECH, or let a redirect carry
// the credential from the bound name to the other. What a canary received is
// the evidence; the guest's word is not.

// request is one HTTP request a canary received.
type request struct {
	sni, host, proto, method, url string
	ech                           bool // ECH was offered and accepted
	headers                       http.Header
}

// canary is one HTTPS server the judge runs on the host's own address, for
// one allowed name. ech, when set, is the config list under which it accepts
// a hidden name.
type canary struct {
	name, addr string
	ech        []byte
	mu         sync.Mutex
	seen       []request
	stop       func()
}

// listen starts a canary for name at a port of the host's choosing. respond,
// if set, writes the response after the request is recorded; else the canary
// answers 200. keys, if set, make the canary accept ECH.
func listen(name string, keys []tls.EncryptedClientHelloKey, respond http.HandlerFunc) (*canary, error) {
	return listenAt(name, hostAddr+":0", keys, respond)
}

// listenAt is listen at addr, an address of the test host with hostAddr
// standing for its own, so that a canary can sit at the one port a forward
// entry opens.
func listenAt(name, addr string, keys []tls.EncryptedClientHelloKey, respond http.HandlerFunc) (*canary, error) {
	addr, err := resolve(addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("canary listener: %w", err)
	}
	return serveCanary(name, ln, keys, respond)
}

// serveCanary serves a canary for name on ln, which is its from here.
func serveCanary(name string, ln net.Listener, keys []tls.EncryptedClientHelloKey, respond http.HandlerFunc) (*canary, error) {
	cfg, err := selfSigned()
	if err != nil {
		ln.Close()
		return nil, err
	}
	if keys != nil {
		cfg.EncryptedClientHelloKeys, cfg.MinVersion = keys, tls.VersionTLS13
	}
	c := &canary{name: name, addr: ln.Addr().String()}
	srv := &http.Server{
		TLSConfig:   cfg,
		ReadTimeout: 3 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.mu.Lock()
			c.seen = append(c.seen, request{sni: r.TLS.ServerName, host: r.Host, proto: r.Proto, method: r.Method,
				url: r.URL.String(), ech: r.TLS.ECHAccepted, headers: r.Header.Clone()})
			c.mu.Unlock()
			if respond != nil {
				respond(w, r)
			}
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() { srv.ServeTLS(ln, "", "") })
	c.stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		srv.Close()
		wg.Wait()
	}
	return c, nil
}

// requests is a copy of what the canary has received, taken under its lock,
// so that nothing else ever holds the lock while it reads.
func (c *canary) requests() []request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.seen)
}

// carried says whether a request's URL or headers held the secret.
func (c *canary) carried(secret string) (string, bool) {
	for _, r := range c.requests() {
		if strings.Contains(r.url, secret) {
			return fmt.Sprintf("the URL of %s %s (Host %s) at %s", r.method, r.url, r.host, c.name), true
		}
		for k, vs := range r.headers {
			if strings.Contains(strings.Join(vs, " "), secret) {
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
// the credential as the guest sees it, and whatever else the test adds.
type targets struct {
	bound, other string
	addrs        map[string]string
	value        string
	header       http.Header // the two headers a client sends a credential in
	extra        []string
}

func parseTargets(args []string) (targets, Result) {
	if len(args) < 5 {
		return targets{}, Result{Status: "error", Detail: "want two names with addresses and the credential variable"}
	}
	v := os.Getenv(args[4])
	if v == "" {
		return targets{}, Result{Status: "no-credential", Detail: args[4] + " is empty"}
	}
	return targets{bound: args[0], other: args[2], addrs: map[string]string{args[0]: args[1], args[2]: args[3]}, value: v,
		header: http.Header{"X-Api-Key": {v}, "Authorization": {"Bearer " + v}}, extra: args[5:]}, Result{}
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

// replayProbe presents the credential it was given to the other name, as a
// client would to the bound one.
func replayProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	check := t.check()
	return after(check, report(fetch(t.get(t.other, "/replay"), t.addrs, &tls.Config{}, false)))
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

// redirectProbe asks the bound name with the credential in the query and the
// headers, and follows wherever it is sent, headers and all; the judge sends
// it to the other name.
func redirectProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	return report(fetch(t.get(t.bound, "/start?key="+t.value), t.addrs, &tls.Config{}, false))
}

// twoCanaries starts a canary for the bound name and one for the other, the
// first with ECH keys under the other's name when ech is set, and hands them
// to judge with the session, stopping both after.
func twoCanaries(ech bool, respondBound func(other *canary) http.HandlerFunc, judge func(s Session, bound, other *canary) (bool, string, error)) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		var otherName string
		for _, n := range slices.Concat(s.Deny, s.Allow) { // a denied name, or the allowed one the secret is not bound to
			if n != s.Secret.Host {
				otherName = n
			}
		}
		other, err := listen(otherName, nil, nil)
		if err != nil {
			return false, "", err
		}
		defer other.stop()
		var respond http.HandlerFunc
		if respondBound != nil {
			respond = respondBound(other)
		}
		var list []byte
		var keys []tls.EncryptedClientHelloKey
		if ech {
			if list, keys, err = echKeys(other.name); err != nil {
				return false, "", err
			}
		}
		bound, err := listen(s.Secret.Host, keys, respond)
		if err != nil {
			return false, "", err
		}
		defer bound.stop()
		bound.ech = list
		return judge(s, bound, other)
	}
}

// run gives the probe its targets and, for a canary that accepts ECH, the
// config list.
func run(s Session, bound, other *canary) (Result, error) {
	args := []string{bound.name, bound.addr, other.name, other.addr, s.Secret.Env}
	if bound.ech != nil {
		args = append(args, base64.StdEncoding.EncodeToString(bound.ech))
	}
	return s.Run(args...)
}

// strictJudge expects the bound name to serve exactly the one well-formed
// request the probe sends first, and the other name nothing. A request that
// named another host, hid its name, or reached the other name was a mismatch
// served; no request at all means the product reached nothing, which proves
// nothing.
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
	switch {
	case r.Status == "ech-accepted":
		return false, "the guest completed an ECH handshake: " + r.Detail, nil
	case len(rs) == 0:
		return false, "", fmt.Errorf("%s saw nothing, not even the well-formed request a correct product serves (guest says %s: %s)", bound.name, r.Status, r.Detail)
	case len(rs) > 1:
		return false, fmt.Sprintf("%s served %d requests where the well-formed one alone was due: the mismatch was served with its names rewritten (guest says %s: %s)", bound.name, len(rs), r.Status, r.Detail), nil
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", bound.served(), r.Status, r.Detail), nil
}

// leakJudge fails if the other name received the real secret. If neither
// canary saw the guest, nothing was proven.
func leakJudge(s Session, bound, other *canary) (bool, string, error) {
	r, err := run(s, bound, other)
	if err != nil {
		return false, "", err
	}
	if what, ok := other.carried(s.Secret.Value); ok {
		return false, "the real secret reached " + what + " (guest says " + r.Status + ": " + r.Detail + ")", nil
	}
	if len(bound.requests()) == 0 && len(other.requests()) == 0 {
		return false, "", fmt.Errorf("no canary saw the guest, not even %s, which a correct product serves (guest says %s: %s)", bound.name, r.Status, r.Detail)
	}
	return true, fmt.Sprintf("%s; %s (guest says %s: %s)", bound.served(), other.served(), r.Status, r.Detail), nil
}

// redirectTo has the bound name send the guest on to the other with the
// query it came with.
func redirectTo(other *canary) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+other.name+":"+port(other.addr)+"/leak?key="+r.URL.Query().Get("key"), http.StatusFound)
	}
}
