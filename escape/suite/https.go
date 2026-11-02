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
// one allowed name.
type canary struct {
	name, addr string
	mu         sync.Mutex
	seen       []request
	stop       func()
}

// listen starts a canary for name. respond, if set, writes the response after
// the request is recorded; else the canary answers 200. keys, if set, make the
// canary accept ECH.
func listen(name string, keys []tls.EncryptedClientHelloKey, respond http.HandlerFunc) (*canary, error) {
	addr, err := resolve(hostAddr + ":0")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("canary listener: %w", err)
	}
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

// carried says whether a request's URL or headers held the secret.
func (c *canary) carried(secret string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.seen {
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) == 0 {
		return c.name + " saw nothing"
	}
	var out []string
	for _, r := range c.seen {
		s := fmt.Sprintf("%s %s %s (SNI %s, Host %s", r.proto, r.method, r.url, r.sni, r.host)
		if r.ech {
			s += ", ECH accepted"
		}
		out = append(out, s+")")
	}
	return c.name + " served " + strings.Join(out, "; ")
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

// credential is what the guest was given under the variable name, with the
// two headers a client would send it in.
func credential(env string) (string, http.Header, bool) {
	v := os.Getenv(env)
	if v == "" {
		return "", nil, false
	}
	return v, http.Header{"X-Api-Key": {v}, "Authorization": {"Bearer " + v}}, true
}

// fetch sends req from the guest to the name in its URL, dialled at the
// address the judge gave for the name when nothing else resolves it (the
// address of a canary is chosen per run), through whatever proxy the
// environment names. The guest is the attacker: it verifies nothing, and it
// forwards every header, credential included, wherever a redirect points.
func fetch(req *http.Request, addrs map[string]string, cfg *tls.Config, h2 bool) (*http.Response, error) {
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
	client := &http.Client{Timeout: 4 * time.Second, Transport: tr, CheckRedirect: func(r *http.Request, via []*http.Request) error {
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

// replayProbe presents the credential it was given to the other allowed name,
// args[0] at args[1], as a client would to the bound one.
func replayProbe(args []string) Result {
	if len(args) != 3 {
		return Result{Status: "error", Detail: "want the other name, its address and the credential variable"}
	}
	_, hdr, ok := credential(args[2])
	if !ok {
		return Result{Status: "no-credential", Detail: args[2] + " is empty"}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+args[0]+":"+port(args[1])+"/replay", nil)
	req.Header = hdr
	return report(fetch(req, map[string]string{args[0]: args[1]}, &tls.Config{}, false))
}

// mismatchProbe opens TLS to the bound name args[0] at args[1] and asks, on
// that connection, for the other name args[2] at args[3] in the Host header
// or the :authority pseudo-header, with the credential.
func mismatchProbe(h2 bool) Probe {
	return func(args []string) Result {
		if len(args) != 5 {
			return Result{Status: "error", Detail: "want two names with addresses and the credential variable"}
		}
		_, hdr, ok := credential(args[4])
		if !ok {
			return Result{Status: "no-credential", Detail: args[4] + " is empty"}
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+args[0]+":"+port(args[1])+"/mismatch", nil)
		req.Header, req.Host = hdr, args[2]+":"+port(args[3])
		return report(fetch(req, map[string]string{args[0]: args[1], args[2]: args[3]}, &tls.Config{ServerName: args[0]}, h2))
	}
}

// echProbe connects to the bound name args[0] at args[1] with the name hidden
// by ECH under the config list args[2] (base64), with the credential.
func echProbe(args []string) Result {
	if len(args) != 4 {
		return Result{Status: "error", Detail: "want the name, its address, an ECH config list and the credential variable"}
	}
	list, err := base64.StdEncoding.DecodeString(args[2])
	if err != nil {
		return Result{Status: "error", Detail: "ECH config list: " + err.Error()}
	}
	_, hdr, ok := credential(args[3])
	if !ok {
		return Result{Status: "no-credential", Detail: args[3] + " is empty"}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+args[0]+":"+port(args[1])+"/ech", nil)
	req.Header = hdr
	cfg := &tls.Config{ServerName: args[0], MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list,
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil }}
	resp, err := fetch(req, map[string]string{args[0]: args[1]}, cfg, false)
	var rejected *tls.ECHRejectionError
	if errors.As(err, &rejected) {
		return Result{Status: "ech-rejected", Detail: err.Error()}
	}
	r := report(resp, err)
	if err == nil && resp.TLS != nil && resp.TLS.ECHAccepted {
		r.Status = "ech-accepted"
	}
	return r
}

// redirectProbe asks the bound name args[0] at args[1] with the credential in
// the query and the headers, and follows wherever it is sent, headers and
// all; the judge sends it to the other name args[2] at args[3].
func redirectProbe(args []string) Result {
	if len(args) != 5 {
		return Result{Status: "error", Detail: "want two names with addresses and the credential variable"}
	}
	v, hdr, ok := credential(args[4])
	if !ok {
		return Result{Status: "no-credential", Detail: args[4] + " is empty"}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+args[0]+":"+port(args[1])+"/start?key="+v, nil)
	req.Header = hdr
	return report(fetch(req, map[string]string{args[0]: args[1], args[2]: args[3]}, &tls.Config{}, false))
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}

// report turns a response, or the error instead, into a result.
func report(resp *http.Response, err error) Result {
	if err != nil {
		return dialFailed(err)
	}
	return Result{Status: "served", Detail: fmt.Sprintf("%s %d from %s", resp.Proto, resp.StatusCode, resp.Request.URL.Host)}
}

// twoCanaries starts the bound name's canary and the other's, and hands them
// to judge with the session, stopping both after.
func twoCanaries(respondBound func(other *canary) http.HandlerFunc, judge func(s Session, bound, other *canary) (bool, string, error)) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		other, err := listen(otherName(s), nil, nil)
		if err != nil {
			return false, "", err
		}
		defer other.stop()
		var respond http.HandlerFunc
		if respondBound != nil {
			respond = respondBound(other)
		}
		bound, err := listen(s.Secret.Host, nil, respond)
		if err != nil {
			return false, "", err
		}
		defer bound.stop()
		return judge(s, bound, other)
	}
}

// otherName is the allowed name the session's secret is not bound to.
func otherName(s Session) string {
	for _, n := range withSecret.Allow {
		if n != s.Secret.Host {
			return n
		}
	}
	return ""
}

// replayJudge fails if the other name received the real secret.
var replayJudge = twoCanaries(nil, func(s Session, bound, other *canary) (bool, string, error) {
	r, err := s.Run(other.name, other.addr, s.Secret.Env)
	if err != nil {
		return false, "", err
	}
	if what, ok := other.carried(s.Secret.Value); ok {
		return false, "the real secret reached " + what + " (guest says " + r.Status + ": " + r.Detail + ")", nil
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", other.served(), r.Status, r.Detail), nil
})

// mismatchJudge fails if the bound name served a request that named another
// host, or if the other name received anything on a connection opened to the
// bound one.
func mismatchJudge(s Session, bound, other *canary) (bool, string, error) {
	r, err := s.Run(bound.name, bound.addr, other.name, other.addr, s.Secret.Env)
	if err != nil {
		return false, "", err
	}
	bound.mu.Lock()
	defer bound.mu.Unlock()
	for _, q := range bound.seen {
		if h, _, _ := net.SplitHostPort(q.host); h != bound.name && q.host != bound.name {
			return false, fmt.Sprintf("%s served %s %s with SNI %s and Host %s (guest says %s: %s)", bound.name, q.proto, q.method, q.sni, q.host, r.Status, r.Detail), nil
		}
	}
	other.mu.Lock()
	defer other.mu.Unlock()
	if len(other.seen) > 0 {
		return false, fmt.Sprintf("%s (routed by Host, SNI was %s; guest says %s: %s)", other.served(), bound.name, r.Status, r.Detail), nil
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", bound.served(), r.Status, r.Detail), nil
}

// echJudge runs the bound name's canary with ECH keys whose public name is the
// other name, and fails if a request completed with ECH accepted.
func echJudge(ctx context.Context, s Session) (bool, string, error) {
	list, keys, err := echKeys(otherName(s))
	if err != nil {
		return false, "", err
	}
	bound, err := listen(s.Secret.Host, keys, nil)
	if err != nil {
		return false, "", err
	}
	defer bound.stop()
	r, err := s.Run(bound.name, bound.addr, base64.StdEncoding.EncodeToString(list), s.Secret.Env)
	if err != nil {
		return false, "", err
	}
	bound.mu.Lock()
	defer bound.mu.Unlock()
	for _, q := range bound.seen {
		if q.ech {
			return false, fmt.Sprintf("%s served %s %s with the name hidden by ECH (guest says %s: %s)", bound.name, q.proto, q.method, r.Status, r.Detail), nil
		}
	}
	if r.Status == "ech-accepted" {
		return false, "the guest completed an ECH handshake: " + r.Detail, nil
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", bound.served(), r.Status, r.Detail), nil
}

// redirectJudge has the bound name send the guest on to the other with the
// query it came with, and fails if the other received the real secret.
var redirectJudge = twoCanaries(func(other *canary) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+other.name+":"+port(other.addr)+"/leak?key="+r.URL.Query().Get("key"), http.StatusFound)
	}
}, func(s Session, bound, other *canary) (bool, string, error) {
	r, err := s.Run(bound.name, bound.addr, other.name, other.addr, s.Secret.Env)
	if err != nil {
		return false, "", err
	}
	if what, ok := other.carried(s.Secret.Value); ok {
		return false, "the real secret reached " + what + " (guest says " + r.Status + ": " + r.Detail + ")", nil
	}
	return true, fmt.Sprintf("%s; %s (guest says %s: %s)", bound.served(), other.served(), r.Status, r.Detail), nil
})
