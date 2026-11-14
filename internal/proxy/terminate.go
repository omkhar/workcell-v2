// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/terminate.go

package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// MaxCALifetime caps the session CA lifetime.
const MaxCALifetime = 24 * time.Hour

var discardLog = log.New(io.Discard, "", 0)

var (
	headerNamePattern  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	methodPattern      = regexp.MustCompile(`^[A-Z]+$`)
	placeholderPattern = regexp.MustCompile(`^wcph-[0-9a-f]{32}$`)
	// placeholderAnywhere matches any placeholder in case-folded text.
	placeholderAnywhere = regexp.MustCompile(`wcph-[0-9a-f]{32}`)
)

// NewPlaceholder returns a fresh random placeholder. The agent holds it in place of a brokered credential; the proxy swaps it on the way out.
func NewPlaceholder() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return "wcph-" + hex.EncodeToString(b)
}

// IsPlaceholder reports whether text is exactly one placeholder.
func IsPlaceholder(text string) bool { return placeholderPattern.MatchString(text) }

// Broker is the credential broker as the proxy uses it. Lookup returns the real value of a brokered header; the proxy owns the bytes it gets, wipes them once
// the request carries the value, and never holds a value between requests. The rest serve a rule's sign-in flow, each for the row bound to (host, header):
// Issue takes the tokens its endpoint issued, an empty one for a token the answer did not carry, which the broker owns and holds in place of those before;
// Refresh returns the refresh token it holds, recorded as Lookup records a value; Tokens returns copies of both tokens it holds, nil before a sign-in, which
// the caller wipes.
type Broker interface {
	Lookup(ctx context.Context, host, header string) ([]byte, error)
	Issue(host, header string, access, refresh []byte) error
	Refresh(ctx context.Context, host, header string) ([]byte, error)
	Tokens(host, header string) (access, refresh []byte)
}

// TerminateRule names a host whose TLS the proxy terminates and the header
// whose placeholder value it swaps for the brokered value. Method, when set,
// narrows the swap to requests of that method, and Path to requests under
// that path prefix; Repos, instead of those, to the git repositories
// "owner/name" it lists, at /owner/name or /owner/name.git and under either:
// a placeholder sent any other way to the host is refused. SignIn, when set,
// is the flow that issues the value (signin.go).
type TerminateRule struct {
	Host        string
	Header      string
	Placeholder string
	Method      string
	Path        string
	Repos       []string
	SignIn      *SignIn
}

// repoSegment is one segment of a repository name: lower-case letters, digits, ".", "_" and "-".
var repoSegment = regexp.MustCompile(`^[a-z0-9._-]+$`)

// NewTerminateRule mints a placeholder for the rule binding header on host, narrowed to method and path when either is not "", or to repos when it has entries.
// The host comes back canonical and the header lowercase, the forms the broker's grants use; the method is capital letters and the path begins with "/" and
// holds printable ASCII with no query or fragment, as a request target carries it; a repository is exactly two segments, neither "." or ".." nor ending in
// ".git", which the path matcher adds itself.
func NewTerminateRule(host, header, method, path string, repos []string) (TerminateRule, error) {
	r := TerminateRule{Host: canonicalHost(host), Header: strings.ToLower(header), Placeholder: NewPlaceholder(), Method: method, Path: path, Repos: repos}
	if _, err := ParseAllowlist(r.Host+":443", "terminate rule"); err != nil {
		return TerminateRule{}, err
	}
	switch {
	case !headerNamePattern.MatchString(r.Header):
		return TerminateRule{}, fmt.Errorf("terminate rule has an invalid header name: %q", header)
	case method != "" && !methodPattern.MatchString(method):
		return TerminateRule{}, fmt.Errorf("terminate rule method must be capital letters: %q", method)
	case path != "" && !validPath(path):
		return TerminateRule{}, fmt.Errorf("terminate rule path must begin with / and hold printable ASCII without ? or #: %q", path)
	case len(repos) > 0 && (method != "" || path != ""):
		return TerminateRule{}, errors.New("terminate rule repos cannot go with a method or a path: one narrows a row")
	}
	for _, repo := range repos {
		if segs := strings.Split(repo, "/"); len(segs) != 2 || slices.ContainsFunc(segs, func(s string) bool {
			return !repoSegment.MatchString(s) || s == "." || s == ".." || strings.HasSuffix(s, ".git")
		}) {
			return TerminateRule{}, fmt.Errorf("terminate rule repository must be owner/name in lower-case letters, digits, '.', '_' and '-', without .git: %q", repo)
		}
	}
	return r, nil
}

// admits reports whether the rule swaps on a request of method to u: the rule's method when it names one, and a path under its prefix, or within one of its
// repositories, when it names either. The path is judged as sent and as folded (see fold), so that neither an encoded slash, a backslash, a ;param nor ".."
// leads out from under the prefix on either reading.
func (r TerminateRule) admits(method string, u *url.URL) bool {
	if r.Method != "" && method != r.Method {
		return false
	}
	sent, clean := u.EscapedPath(), fold(u.EscapedPath())
	if r.Path != "" {
		return strings.HasPrefix(sent, r.Path) && (strings.HasPrefix(clean, r.Path) || clean+"/" == r.Path)
	}
	return len(r.Repos) == 0 || slices.ContainsFunc(r.Repos, func(repo string) bool { return within(sent, repo) && within(clean, repo) })
}

// within reports whether p is /repo or /repo.git, or lies under either.
func within(p, repo string) bool {
	for _, root := range []string{"/" + repo, "/" + repo + ".git"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

// SessionCA issues leaf certificates for the terminated hosts only. Its key lives only in memory.
type SessionCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// NewSessionCA returns a CA whose critical name constraints permit only hosts and no IP address. notAfter must be in the future and within MaxCALifetime.
func NewSessionCA(hosts []string, notAfter time.Time) (*SessionCA, error) {
	now := time.Now()
	if !notAfter.After(now) || notAfter.Sub(now) > MaxCALifetime {
		return nil, fmt.Errorf("session CA expiry must be within %s from now", MaxCALifetime)
	}
	if len(hosts) == 0 {
		return nil, errors.New("session CA needs at least one host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject:                     pkix.Name{CommonName: "Workcell session CA"},
		NotBefore:                   now.Add(-time.Minute), // a peer whose clock is a little behind still accepts the CA
		NotAfter:                    notAfter,
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         hosts,
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	cert, err := sign(template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &SessionCA{cert: cert, key: key, leaves: map[string]*tls.Certificate{}}, nil
}

// sign issues template under parent, whose private key is signer.
func sign(template, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) (*x509.Certificate, error) {
	var err error
	if template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertPEM returns the CA certificate for clients to trust.
func (ca *SessionCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// leaf returns the cached leaf for host, issuing it on first use.
func (ca *SessionCA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := ca.issue(host, key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
	ca.leaves[host] = c
	return c, nil
}

func (ca *SessionCA) issue(host string, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	return sign(&x509.Certificate{
		Subject:     pkix.Name{CommonName: host},
		DNSNames:    []string{host},
		NotBefore:   ca.cert.NotBefore,
		NotAfter:    ca.cert.NotAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.cert, &key.PublicKey, ca.key)
}

// Terminate makes p terminate TLS for every host on the SNI allowlist, with a leaf from ca, and swap each rule's placeholder header via broker. A rule's host
// must be on the SNI allowlist, as must its sign-in host; a host can have one rule per header, and a token endpoint serves one rule. Header names are stored
// lowercase, the form the credential broker's grants use, since HTTP header names ignore case.
func (p *Proxy) Terminate(ca *SessionCA, broker Broker, rules []TerminateRule) error {
	terminate := make(map[string][]TerminateRule, len(p.allow.sni))
	for host := range p.allow.sni {
		terminate[host] = nil
	}
	signin := map[string][]TerminateRule{}
	seen := map[string]bool{}
	for _, r := range rules {
		if !p.allow.sni[r.Host] {
			return fmt.Errorf("terminate host %s is not on the port 443 allowlist", r.Host)
		}
		r.Header = strings.ToLower(r.Header)
		key := r.Host + " " + r.Header
		if seen[key] {
			return fmt.Errorf("terminate host %s has more than one rule for header %s", r.Host, r.Header)
		}
		seen[key] = true
		terminate[r.Host] = append(terminate[r.Host], r)
		if s := r.SignIn; s != nil {
			if !p.allow.sni[s.Host] {
				return fmt.Errorf("sign-in host %s is not on the port 443 allowlist", s.Host)
			}
			if seen[s.Host+s.Path] {
				return fmt.Errorf("token endpoint %s%s serves more than one rule", s.Host, s.Path)
			}
			seen[s.Host+s.Path] = true
			signin[s.Host] = append(signin[s.Host], r)
		}
	}
	if p.upstreamRoots == nil {
		var err error
		if p.upstreamRoots, err = upstreamRoots(os.Getenv("SSL_CERT_FILE")); err != nil {
			return err
		}
	}
	p.ca, p.broker, p.terminate, p.signin = ca, broker, terminate, signin
	p.transport = &http.Transport{
		ForceAttemptHTTP2: false,
		IdleConnTimeout:   90 * time.Second,
		TLSClientConfig:   &tls.Config{RootCAs: p.upstreamRoots, MinVersion: tls.VersionTLS12},
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if _, ok := p.terminate[host]; !ok {
				return nil, fmt.Errorf("upstream %s is not a terminate host", host)
			}
			conn, reason := p.connect(host, tlsPort)
			if reason != "" {
				p.Deny(host, tlsPort, reason)
				return nil, errors.New(reason)
			}
			return conn, nil
		},
	}
	return nil
}

// upstreamRoots is the pool the proxy verifies an upstream with: the system roots and, when certFile is the file SSL_CERT_FILE names, the operator's own
// authorities in it. Go reads that file itself on Linux only; on macOS nil roots mean the platform verifier, which ignores it, so a private authority the
// operator trusts there verified nothing. One explicit pool is the same on every OS, and a file that cannot be read refuses termination rather than trusting
// less.
func upstreamRoots(certFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || certFile == "" {
		return pool, err
	}
	b, err := os.ReadFile(certFile)
	pool.AppendCertsFromPEM(b)
	return pool, err
}

// replayConn yields the replayed ClientHello bytes before the rest of the client stream.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// oneConnListener hands out one connection, then blocks until it closes.
type oneConnListener struct {
	conn chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conn:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

// closeNotifyConn closes its listener when the HTTP server closes it.
type closeNotifyConn struct {
	net.Conn
	ln *oneConnListener
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	_ = c.ln.Close()
	return err
}

// sameHost reports whether an HTTP Host or :authority names sni, which is canonical: the same name in any letter case, with or without a trailing dot and the
// port, :443 or the one the connection came in on, which is 443 too except on a test's listener. As in route, a non-ASCII fold is no match.
func sameHost(host, sni, port string) bool {
	lower := strings.ToLower(host)
	if len(lower) != len(host) {
		return false
	}
	name, p, hasPort := strings.Cut(lower, ":")
	return (!hasPort || p == "443" || p == port) && strings.TrimSuffix(name, ".") == sni
}

// serveTerminated terminates TLS for host with a session leaf and proxies HTTP/1.1 requests to the real host, swapping the placeholder headers. It refuses a
// request that names another host than the SNI did (I6), one that sends a placeholder outside the method and path its rule binds it to (I5), and one that still
// carries a placeholder after the swap.
func (p *Proxy) serveTerminated(client net.Conn, host string, replay []byte) {
	rules := p.terminate[host]
	tlsConn := tls.Server(&replayConn{Conn: client, r: io.MultiReader(bytes.NewReader(replay), client)}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.ca.leaf(host)
		},
	})
	ln := &oneConnListener{conn: make(chan net.Conn, 1), done: make(chan struct{}), addr: client.LocalAddr()}
	ln.conn <- &closeNotifyConn{Conn: tlsConn, ln: ln}
	_, port, _ := net.SplitHostPort(ln.addr.String())
	proxy := &httputil.ReverseProxy{
		FlushInterval:  -1,
		ErrorLog:       discardLog,
		Transport:      p.transport,
		ModifyResponse: p.tokenResponse,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "https"
			r.Out.URL.Host = host
			r.Out.Host = host
		},
	}
	// ponytail: no idle timeout, like splice; a peer that never closes holds the conn.
	srv := &http.Server{
		ReadHeaderTimeout: peekTimeout,
		MaxHeaderBytes:    64 << 10, // a client needs a few KiB; this bounds what a held slot pins (I10, C11)
		ErrorLog:          discardLog,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TRACE echoes request headers and CONNECT tunnels past the rewrite, so neither may carry a swapped key.
			if r.Method == http.MethodTrace || r.Method == http.MethodConnect {
				p.Deny(host, tlsPort, "method_refused")
				http.Error(w, "method not allowed through the credential broker", http.StatusMethodNotAllowed)
				return
			}
			if !sameHost(r.Host, host, port) {
				p.Deny(host, tlsPort, "host_mismatch")
				http.Error(w, fmt.Sprintf("the request names %q on a connection whose TLS names %s", r.Host, host), http.StatusMisdirectedRequest)
				return
			}
			for _, rule := range rules {
				form, ok := placeholderForm(r.Header.Values(rule.Header), rule.Placeholder)
				if !ok {
					continue
				}
				if !rule.admits(r.Method, r.URL) {
					scope := fmt.Sprintf("method %s under path %s", cmp.Or(rule.Method, "*"), cmp.Or(rule.Path, "/"))
					if len(rule.Repos) > 0 {
						scope = "repositories " + strings.Join(rule.Repos, ", ")
					}
					p.Deny(host, tlsPort, "binding_mismatch")
					http.Error(w, "the credential in "+rule.Header+" is bound to "+scope, http.StatusForbidden)
					return
				}
				value, err := p.broker.Lookup(r.Context(), host, rule.Header)
				if err != nil {
					p.Deny(host, tlsPort, "broker_denied")
					http.Error(w, "credential broker denied the request", http.StatusBadGateway)
					return
				}
				r.Header.Set(rule.Header, form(value)) // the one copy the request carries
				clear(value)
			}
			// At a token endpoint the body is read whole, its refresh placeholder swapped, and the answer rewritten (signin.go).
			if rule, ok := p.tokenEndpoint(host, r.URL); ok {
				body, reason := p.tokenRequest(r, rule)
				if reason != "" {
					p.Deny(host, tlsPort, reason)
					http.Error(w, "request to the token endpoint refused: "+reason, http.StatusBadGateway)
					return
				}
				defer clear(body) // the one copy the request carries, once it has gone
				r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, rule))
			}
			if carriesPlaceholder(r) {
				p.Deny(host, tlsPort, "placeholder_unswapped")
				http.Error(w, "request carries an unswapped credential placeholder", http.StatusBadGateway)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	_ = srv.Serve(ln)
}

// placeholderForm reports whether values is exactly one value carrying placeholder in a form the proxy swaps: the placeholder alone, "Bearer " before it, or as
// the password of a Basic value, which git sends as base64(user:token). It returns the function that puts the real value in the same form; the Basic one wipes
// the pair it encoded.
func placeholderForm(values []string, placeholder string) (func([]byte) string, bool) {
	if len(values) != 1 {
		return nil, false
	}
	switch v := values[0]; v {
	case placeholder:
		return func(b []byte) string { return string(b) }, true
	case "Bearer " + placeholder:
		return func(b []byte) string { return "Bearer " + string(b) }, true
	default:
		pair, ok := basicDecode(v)
		if user, password, cut := strings.Cut(string(pair), ":"); ok && cut && password == placeholder {
			return func(b []byte) string {
				pair := append([]byte(user+":"), b...)
				defer clear(pair)
				return "Basic " + base64.StdEncoding.EncodeToString(pair)
			}, true
		}
	}
	return nil, false
}

// maxBasic bounds the Basic value the proxy decodes: the bytes are the guest's.
const maxBasic = 4096

// basicDecode is what a Basic authorization value encodes: strict standard base64 of at most maxBasic bytes after the scheme, so that what the proxy re-encodes
// is the value it matched. Anything else is no Basic value.
func basicDecode(value string) ([]byte, bool) {
	raw, ok := strings.CutPrefix(value, "Basic ")
	if !ok || len(raw) > maxBasic || strings.ContainsAny(raw, "\r\n") {
		return nil, false
	}
	pair, err := base64.StdEncoding.Strict().DecodeString(raw)
	return pair, err == nil
}

// carriesPlaceholder reports whether any header name or value, a Basic value decoded, or the request target raw or percent-decoded, holds a placeholder in any
// letter case. A target that does not decode counts as a hit, so an escape cannot hide one. A declared request trailer counts as a hit too: its values arrive
// after the body has already streamed upstream, so they can never be checked here.
func carriesPlaceholder(r *http.Request) bool {
	has := func(text string) bool { return placeholderAnywhere.MatchString(strings.ToLower(text)) }
	decoded, err := url.PathUnescape(r.RequestURI)
	if err != nil || has(r.RequestURI) || has(decoded) || len(r.Trailer) > 0 {
		return true
	}
	for name, values := range r.Header {
		if has(name) {
			return true
		}
		for _, v := range values {
			if pair, _ := basicDecode(v); has(v) || has(string(pair)) {
				return true
			}
		}
	}
	return false
}
