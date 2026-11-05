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
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

// MaxCALifetime caps the session CA lifetime.
const MaxCALifetime = 24 * time.Hour

// CABackdate is how far NewSessionCA sets NotBefore before its clock, so a
// peer whose clock is a little behind still accepts the CA.
const CABackdate = time.Minute

var discardLog = log.New(io.Discard, "", 0)

var (
	headerNamePattern  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	methodPattern      = regexp.MustCompile(`^[A-Z]+$`)
	placeholderPattern = regexp.MustCompile(`^wcph-[0-9a-f]{32}$`)
	// placeholderAnywhere matches any placeholder in case-folded text.
	placeholderAnywhere = regexp.MustCompile(`wcph-[0-9a-f]{32}`)
)

// NewPlaceholder returns a fresh random placeholder. The agent holds it in
// place of a brokered credential; the proxy swaps it on the way out.
func NewPlaceholder() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return "wcph-" + hex.EncodeToString(b)
}

// IsPlaceholder reports whether text is exactly one placeholder.
func IsPlaceholder(text string) bool { return placeholderPattern.MatchString(text) }

// Broker is the credential broker as the proxy uses it. Lookup returns the
// real value of a brokered header; the proxy owns the bytes it gets, wipes
// them once the request carries the value, and never holds a value between
// requests. The rest serve a rule's sign-in flow, each for the row bound to
// (host, header): Issue takes the tokens its endpoint issued, an empty one
// for a token the answer did not carry, which the broker owns and holds in
// place of those before; Refresh returns the refresh token it holds,
// recorded as Lookup records a value; Tokens returns copies of both tokens
// it holds, nil before a sign-in, which the caller wipes.
type Broker interface {
	Lookup(ctx context.Context, host, header string) ([]byte, error)
	Issue(host, header string, access, refresh []byte) error
	Refresh(ctx context.Context, host, header string) ([]byte, error)
	Tokens(host, header string) (access, refresh []byte)
}

// TerminateRule names a host whose TLS the proxy terminates and the header
// whose placeholder value it swaps for the brokered value. Method, when set,
// narrows the swap to requests of that method, and Path to requests under
// that path prefix: a placeholder sent any other way to the host is refused.
// SignIn, when set, is the flow that issues the value (signin.go).
type TerminateRule struct {
	Host        string
	Header      string
	Placeholder string
	Method      string
	Path        string
	SignIn      *SignIn
}

// NewTerminateRule mints a placeholder for the rule binding header on host,
// narrowed to method and path when either is not "". The host comes back
// canonical and the header lowercase, the forms the broker's grants use; the
// method is capital letters and the path begins with "/" and holds printable
// ASCII with no query or fragment, as a request target carries it.
func NewTerminateRule(host, header, method, path string) (TerminateRule, error) {
	r := TerminateRule{Host: canonicalHost(host), Header: strings.ToLower(header), Placeholder: NewPlaceholder(), Method: method, Path: path}
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
	}
	return r, nil
}

// admits reports whether the rule swaps on a request of method to u: the
// rule's method when it names one, and a path under its prefix when it names
// one. The path is judged as sent and as decoded with its dot segments
// resolved, so that neither an encoded slash nor ".." leads out from under
// the prefix on either reading.
func (r TerminateRule) admits(method string, u *url.URL) bool {
	if r.Method != "" && method != r.Method {
		return false
	}
	if r.Path == "" {
		return true
	}
	clean := path.Clean(u.Path)
	return strings.HasPrefix(u.EscapedPath(), r.Path) && (strings.HasPrefix(clean, r.Path) || clean+"/" == r.Path)
}

// SessionCA issues leaf certificates for the terminated hosts only. Its key
// lives only in memory.
type SessionCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// ValidCAExpiry reports whether a session CA that expires at notAfter is
// unexpired at now and expires within MaxCALifetime of now.
func ValidCAExpiry(notAfter, now time.Time) bool {
	return notAfter.After(now) && notAfter.Sub(now) <= MaxCALifetime
}

// ValidCALifetime reports whether a CA's own validity period, NotAfter minus
// NotBefore, is positive and at most MaxCALifetime plus CABackdate. Unlike
// ValidCAExpiry it needs no clock, so a host can check a CA that another
// clock (the VM's) issued without skew between the two.
func ValidCALifetime(notBefore, notAfter time.Time) bool {
	d := notAfter.Sub(notBefore)
	return d > 0 && d <= MaxCALifetime+CABackdate
}

// NewSessionCA returns a CA whose critical name constraints permit only hosts
// and no IP address. notAfter must be in the future and within MaxCALifetime.
func NewSessionCA(hosts []string, notAfter time.Time) (*SessionCA, error) {
	now := time.Now()
	if !ValidCAExpiry(notAfter, now) {
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
		NotBefore:                   now.Add(-CABackdate),
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
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serial
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

// Terminate makes p terminate TLS for every host on the SNI allowlist, with a
// leaf from ca, and swap each rule's placeholder header via broker. A rule's
// host must be on the SNI allowlist, as must its sign-in host; a host can
// have one rule per header, and a token endpoint serves one rule. Header
// names are stored lowercase, the form the credential broker's grants use,
// since HTTP header names ignore case.
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
				p.deny(host, tlsPort, reason)
				return nil, errors.New(reason)
			}
			return conn, nil
		},
	}
	return nil
}

// replayConn yields the replayed ClientHello bytes before the rest of the
// client stream.
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

// sameHost reports whether an HTTP Host or :authority names sni, which is
// canonical: the same name in any letter case, with or without the :443 port
// and a trailing dot. As in route, a non-ASCII fold is no match.
func sameHost(host, sni string) bool {
	lower := strings.ToLower(host)
	if len(lower) != len(host) {
		return false
	}
	return strings.TrimSuffix(strings.TrimSuffix(lower, ":443"), ".") == sni
}

// serveTerminated terminates TLS for host with a session leaf and proxies
// HTTP/1.1 requests to the real host, swapping the placeholder headers. It
// refuses a request that names another host than the SNI did (I6), one that
// sends a placeholder outside the method and path its rule binds it to (I5),
// and one that still carries a placeholder after the swap.
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
		ErrorLog:          discardLog,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TRACE echoes request headers and CONNECT tunnels past the
			// rewrite, so neither may carry a swapped key.
			if r.Method == http.MethodTrace || r.Method == http.MethodConnect {
				p.deny(host, tlsPort, "method_refused")
				http.Error(w, "method not allowed through the credential broker", http.StatusMethodNotAllowed)
				return
			}
			if !sameHost(r.Host, host) {
				p.deny(host, tlsPort, "host_mismatch")
				http.Error(w, fmt.Sprintf("the request names %q on a connection whose TLS names %s", r.Host, host), http.StatusMisdirectedRequest)
				return
			}
			for _, rule := range rules {
				prefix, ok := placeholderPrefix(r.Header.Values(rule.Header), rule.Placeholder)
				if !ok {
					continue
				}
				if !rule.admits(r.Method, r.URL) {
					p.deny(host, tlsPort, "binding_mismatch")
					http.Error(w, fmt.Sprintf("the credential in %s is bound to method %s under path %s", rule.Header, cmp.Or(rule.Method, "*"), cmp.Or(rule.Path, "/")), http.StatusForbidden)
					return
				}
				value, err := p.broker.Lookup(r.Context(), host, rule.Header)
				if err != nil {
					p.deny(host, tlsPort, "broker_denied")
					http.Error(w, "credential broker denied the request", http.StatusBadGateway)
					return
				}
				r.Header.Set(rule.Header, prefix+string(value)) // the one copy the request carries
				clear(value)
			}
			// At a token endpoint the body is read whole, its refresh
			// placeholder swapped, and the answer rewritten (signin.go).
			if rule, ok := p.tokenEndpoint(host, r.URL); ok {
				body, reason := p.tokenRequest(r, rule)
				if reason != "" {
					p.deny(host, tlsPort, reason)
					http.Error(w, "request to the token endpoint refused: "+reason, http.StatusBadGateway)
					return
				}
				defer clear(body) // the one copy the request carries, once it has gone
				r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, rule))
			}
			if carriesPlaceholder(r) {
				p.deny(host, tlsPort, "placeholder_unswapped")
				http.Error(w, "request carries an unswapped credential placeholder", http.StatusBadGateway)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	_ = srv.Serve(ln)
}

// placeholderPrefix reports whether values is exactly one value equal to
// placeholder or "Bearer " + placeholder, and returns the prefix to keep.
func placeholderPrefix(values []string, placeholder string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	switch values[0] {
	case placeholder:
		return "", true
	case "Bearer " + placeholder:
		return "Bearer ", true
	}
	return "", false
}

// carriesPlaceholder reports whether any header name or value, or the request
// target raw or percent-decoded, holds a placeholder in any letter case. A
// target that does not decode counts as a hit, so an escape cannot hide one.
// A declared request trailer counts as a hit too: its values arrive after the
// body has already streamed upstream, so they can never be checked here.
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
			if has(v) {
				return true
			}
		}
	}
	return false
}
