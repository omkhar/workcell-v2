// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/terminate_test.go

package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testPlaceholder     = "wcph-0123456789abcdef0123456789abcdef"
	testAuthPlaceholder = "wcph-fedcba9876543210fedcba9876543210"
)

type fakeBroker struct {
	mu    sync.Mutex
	calls []string
	value string
	err   error
	last  []byte // the bytes of the last lookup, which the proxy must wipe
}

func (b *fakeBroker) Lookup(_ context.Context, host, header string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, host+" "+header)
	b.last = []byte(b.value)
	return b.last, b.err
}

// No rule of the fixture has a sign-in flow; signin_test.go has a broker that holds tokens.
func (b *fakeBroker) Issue(string, string, []byte, []byte) error              { return b.err }
func (b *fakeBroker) Refresh(context.Context, string, string) ([]byte, error) { return nil, b.err }
func (b *fakeBroker) Tokens(string, string) ([]byte, []byte)                  { return nil, nil }

func (b *fakeBroker) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.calls)
}

// terminateFixture runs an upstream that echoes the x-api-key and Authorization
// it received and a proxy that terminates example.com, with a rule for each of
// those headers, a.example.com, with none, n.example.com, with an x-api-key
// rule narrowed to POST under /v1/, and r.example.com, with an Authorization
// rule scoped to the repository octo/allowed.
func terminateFixture(t *testing.T, broker Broker) (proxyAddr string, ca *SessionCA, p *Proxy, log *recorder) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host+" "+strings.Join(r.Header.Values("X-Api-Key"), ","))
		if auth := r.Header.Get("Authorization"); auth != "" {
			_, _ = io.WriteString(w, " auth="+auth)
		}
	}))
	t.Cleanup(server.Close)
	p, buf, _ := testProxy(t, "example.com:443 a.example.com:443 n.example.com:443 r.example.com:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	p.upstreamRoots = x509.NewCertPool()
	p.upstreamRoots.AddCert(server.Certificate())
	ca = must(NewSessionCA([]string{"example.com", "a.example.com", "n.example.com", "r.example.com"}, time.Now().Add(time.Hour)))
	// Mixed-case header names: the broker must still get the lowercase form
	// its grants use (TestTerminateSwapsOnlyExactPlaceholder checks the call).
	must(0, p.Terminate(ca, broker, []TerminateRule{
		{Host: "example.com", Header: "X-Api-Key", Placeholder: testPlaceholder},
		{Host: "example.com", Header: "Authorization", Placeholder: testAuthPlaceholder},
		{Host: "n.example.com", Header: "X-Api-Key", Placeholder: testPlaceholder, Method: "POST", Path: "/v1/"},
		{Host: "r.example.com", Header: "Authorization", Placeholder: testAuthPlaceholder, Repos: []string{"octo/allowed"}},
	}))
	return listen(t, p, 443), ca, p, buf
}

// basic is password as git sends a token: a Basic value of base64("x-access-token:" + password).
func basic(password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+password))
}

func caPool(t *testing.T, ca *SessionCA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CertPEM is not a PEM certificate")
	}
	return pool
}

func clientVia(proxyAddr string, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", proxyAddr)
			},
		},
	}
}

func get(t *testing.T, c *http.Client, url, key string) (int, string) {
	t.Helper()
	req := must(http.NewRequest(http.MethodGet, url, nil))
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	return do(t, c, req)
}

func do(t *testing.T, c *http.Client, req *http.Request) (int, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", req.URL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestTerminateSwapsOnlyExactPlaceholder(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{value: "real-secret"}
	addr, ca, p, log := terminateFixture(t, broker)
	c := clientVia(addr, caPool(t, ca))
	cases := []struct{ sent, want string }{
		{testPlaceholder, "example.com real-secret"},
		{"Bearer " + testPlaceholder, "example.com Bearer real-secret"},
		{"user-key", "example.com user-key"},
		{"", "example.com "},
	}
	for _, tc := range cases {
		if code, body := get(t, c, "https://example.com/v1?key=user-key", tc.sent); code != http.StatusOK || body != tc.want {
			t.Errorf("sent %q: upstream saw (%d, %q), want %q", tc.sent, code, body, tc.want)
		}
	}
	// A Host that is not the SNI's name, another allowed name included, is
	// refused before the broker or the upstream hears of it (I6); one that
	// spells the name differently is the name.
	for host, code := range map[string]int{"evil.example": 421, "a.example.com": 421, "EXAMPLE.COM:443": 200, "example.com.": 200} {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Host = host
		req.Header.Set("X-Api-Key", testPlaceholder)
		if got, body := do(t, c, req); got != code || code == 200 && body != "example.com real-secret" {
			t.Errorf("Host %s: got (%d, %q), want %d", host, got, body, code)
		}
	}
	if n := broker.callCount(); n != 4 {
		t.Errorf("broker calls = %d, want 4 (placeholder values only)", n)
	}
	if broker.calls[0] != "example.com x-api-key" {
		t.Errorf("broker call = %q, want host and header", broker.calls[0])
	}
	want := denyLine{Host: "example.com", Port: 443, Reason: "host_mismatch", Count: 2, Seq: 2}
	if d := denies(t, p, log); len(d) != 2 || d[1] != want {
		t.Errorf("deny lines = %+v, want 2 ending in %+v", d, want)
	}

	// Every allowed name is terminated, with or without a rule: the client
	// sees a session leaf for a.example.com too.
	if code, body := get(t, c, "https://a.example.com/", "user-key"); code != http.StatusOK || body != "a.example.com user-key" {
		t.Errorf("GET to the host without a rule = (%d, %q), want it served through the session leaf", code, body)
	}
}

func TestSameHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true}, {"EXAMPLE.com", true}, {"example.com:443", true}, {"example.com.", true}, {"Example.COM.:443", true},
		{"", false}, {"a.example.com", false}, {"example.com:8443", false}, {"example.com:443.", false}, {"example.com:443:443", false},
		{"example.com\u212a", false}, {"exam\u212ale.com", false}, {"example.com evil", false},
	}
	for _, tc := range cases {
		if got := sameHost(tc.host, "example.com", "443"); got != tc.want {
			t.Errorf("sameHost(%q) = %t, want %t", tc.host, got, tc.want)
		}
	}
	// A test's listener has a port of its own, which a Host may then name; :443 still may.
	if !sameHost("example.com:8443", "example.com", "8443") || !sameHost("Example.com.:443", "example.com", "8443") || sameHost("example.com:8443.", "example.com", "8443") {
		t.Error("sameHost does not take the connection's own port alone beside 443")
	}
}

// Claude Code with apiKeyHelper sends the key in x-api-key and in
// Authorization; both rules for one host must swap.
func TestTerminateSwapsBothHeaders(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{value: "real-secret"}
	addr, ca, _, _ := terminateFixture(t, broker)
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("X-Api-Key", testPlaceholder)
	req.Header.Set("Authorization", "Bearer "+testAuthPlaceholder)
	if code, body := do(t, clientVia(addr, caPool(t, ca)), req); code != http.StatusOK || body != "example.com real-secret auth=Bearer real-secret" {
		t.Fatalf("both headers: upstream saw (%d, %q), want both swapped", code, body)
	}
	if got := strings.Join(broker.calls, ","); got != "example.com x-api-key,example.com authorization" {
		t.Errorf("broker calls = %q, want one per header", got)
	}
}

// A placeholder left anywhere after the swap fails closed with 502 and a deny
// line; it never reaches upstream.
func TestTerminateRefusesUnswappedPlaceholder(t *testing.T) {
	t.Parallel()
	addr, ca, p, log := terminateFixture(t, &fakeBroker{value: "real-secret"})
	c := clientVia(addr, caPool(t, ca))
	encoded := "%77cph-0123456789abcdef0123456789abcdef"
	cases := map[string]struct {
		target string
		header map[string][]string
	}{
		"query string":          {"/v1?key=" + testPlaceholder, nil},
		"encoded query string":  {"/v1?key=" + encoded, nil},
		"path":                  {"/v1/" + testPlaceholder, nil},
		"undecodable target":    {"/v1?x=%zz&key=" + encoded, nil},
		"other header":          {"/", map[string][]string{"X-Goog-Api-Key": {testPlaceholder}}},
		"other header upper":    {"/", map[string][]string{"X-Goog-Api-Key": {strings.ToUpper(testPlaceholder)}}},
		"header name":           {"/", map[string][]string{"X-" + testPlaceholder: {"v"}}},
		"suffixed value":        {"/", map[string][]string{"X-Api-Key": {testPlaceholder + "x"}}},
		"basic scheme":          {"/", map[string][]string{"X-Api-Key": {"Basic " + testPlaceholder}}},
		"two values":            {"/", map[string][]string{"X-Api-Key": {testPlaceholder, "user-key"}}},
		"wrong header for rule": {"/", map[string][]string{"Authorization": {"Bearer " + testPlaceholder}}},
		"one of two swapped":    {"/", map[string][]string{"X-Api-Key": {testPlaceholder}, "X-Other": {testAuthPlaceholder}}},
		"basic in other header": {"/", map[string][]string{"X-Goog-Api-Key": {basic(testPlaceholder)}}},
		"basic of other rule":   {"/", map[string][]string{"Authorization": {basic(testPlaceholder)}}},
		"basic upper-case":      {"/", map[string][]string{"Authorization": {basic(strings.ToUpper(testAuthPlaceholder))}}},
		"basic as the user":     {"/", map[string][]string{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(testAuthPlaceholder+":x"))}}},
		"basic with no colon":   {"/", map[string][]string{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(testAuthPlaceholder))}}},
	}
	for name, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com"+tc.target, nil)
		for k, v := range tc.header {
			req.Header[k] = v
		}
		if code, body := do(t, c, req); code != http.StatusBadGateway || !strings.Contains(body, "unswapped") {
			t.Errorf("%s: got (%d, %q), want 502 from the proxy", name, code, body)
		}
	}
	// A trailer is declared before the body and delivered after it, so the
	// proxy refuses every request trailer, placeholder-named or benign.
	trailers := []string{"X-" + testPlaceholder, "X-Checksum"}
	for _, name := range trailers {
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/v1", strings.NewReader("body"))
		req.ContentLength = -1
		req.Header.Set("X-Api-Key", testPlaceholder)
		req.Trailer = http.Header{name: {"v"}}
		if code, body := do(t, c, req); code != http.StatusBadGateway || !strings.Contains(body, "unswapped") {
			t.Errorf("trailer %s: got (%d, %q), want 502 from the proxy", name, code, body)
		}
	}
	d := denies(t, p, log)
	total := len(cases) + len(trailers)
	want := denyLine{Host: "example.com", Port: 443, Reason: "placeholder_unswapped", Count: uint64(total), Seq: uint64(total)}
	if len(d) != total || d[len(d)-1] != want {
		t.Fatalf("deny lines = %+v, want %d ending in %+v", d, total, want)
	}
}

func TestTerminateBrokerErrorIs502(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{err: errors.New("no grant")}
	addr, ca, p, log := terminateFixture(t, broker)
	code, body := get(t, clientVia(addr, caPool(t, ca)), "https://example.com/", testPlaceholder)
	if code != http.StatusBadGateway || strings.Contains(body, testPlaceholder) {
		t.Fatalf("broker error GET = (%d, %q), want 502 without reaching upstream", code, body)
	}
	want := denyLine{Host: "example.com", Port: 443, Reason: "broker_denied", Count: 1, Seq: 1}
	if d := denies(t, p, log); len(d) != 1 || d[0] != want {
		t.Fatalf("deny lines = %+v, want [%+v]", d, want)
	}
}

func TestTerminateOffersHTTP11Only(t *testing.T) {
	t.Parallel()
	addr, ca, _, _ := terminateFixture(t, &fakeBroker{})
	roots := caPool(t, ca)
	dial := func(protos ...string) (string, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{ServerName: "example.com", RootCAs: roots, NextProtos: protos})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.ConnectionState().NegotiatedProtocol, nil
	}
	if _, err := dial("h2"); err == nil {
		t.Error("h2-only handshake succeeded, want refusal")
	}
	if got, err := dial("h2", "http/1.1"); err != nil || got != "http/1.1" {
		t.Errorf("negotiated = (%q, %v), want http/1.1", got, err)
	}
}

func TestSessionCANameConstraints(t *testing.T) {
	t.Parallel()
	ca := must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour)))
	if !ca.cert.IsCA || ca.cert.MaxPathLen != 0 || !ca.cert.MaxPathLenZero || !ca.cert.PermittedDNSDomainsCritical {
		t.Fatalf("CA = IsCA %v MaxPathLen %d zero %v critical %v", ca.cert.IsCA, ca.cert.MaxPathLen, ca.cert.MaxPathLenZero, ca.cert.PermittedDNSDomainsCritical)
	}
	if ca.key.Curve != elliptic.P256() {
		t.Fatal("CA key is not P-256")
	}
	// The CA is trusted only through the file SSL_CERT_FILE would name, as an operator's private
	// authority is; a leaf of another authority is not, and a file that cannot be read refuses.
	file := filepath.Join(t.TempDir(), "roots.pem")
	must(0, os.WriteFile(file, ca.CertPEM(), 0o600))
	roots := must(upstreamRoots(file))
	verify := func(name string, leaf *x509.Certificate) error {
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots})
		return err
	}
	own := must(ca.leaf("api.example.com"))
	if err := verify("api.example.com", own.Leaf); err != nil {
		t.Fatalf("on-list leaf: %v", err)
	}
	if again, _ := ca.leaf("api.example.com"); again != own {
		t.Error("leaf was issued twice for one host")
	}
	other := must(NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour)))
	if err := verify("api.example.com", must(other.leaf("api.example.com")).Leaf); err == nil {
		t.Error("a leaf of another authority verified under the pool")
	}
	if _, err := upstreamRoots(file + ".missing"); err == nil {
		t.Error("upstreamRoots read a missing file without error")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, name := range []string{"evil.example", "example.com"} {
		off := must(ca.issue(name, key))
		var invalid x509.CertificateInvalidError
		if err := verify(name, off); !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Errorf("off-list leaf %s: verify error = %v, want CANotAuthorizedForThisName", name, err)
		}
	}
	ipLeaf := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("8.8.8.8")}, NotBefore: ca.cert.NotBefore, NotAfter: ca.cert.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	signed := must(sign(ipLeaf, ca.cert, &key.PublicKey, ca.key))
	if err := verify("8.8.8.8", signed); err == nil {
		t.Error("IP leaf verified, want refusal by the excluded IP ranges")
	}
}

func TestNewSessionCARefusesBadInput(t *testing.T) {
	t.Parallel()
	for name, notAfter := range map[string]time.Time{
		"past":       time.Now().Add(-time.Minute),
		"over a day": time.Now().Add(MaxCALifetime + time.Minute),
	} {
		if _, err := NewSessionCA([]string{"example.com"}, notAfter); err == nil {
			t.Errorf("%s: NewSessionCA succeeded, want refusal", name)
		}
	}
	if _, err := NewSessionCA(nil, time.Now().Add(time.Hour)); err == nil {
		t.Error("no hosts: NewSessionCA succeeded, want refusal")
	}
	if _, err := NewSessionCA([]string{"example.com"}, time.Now().Add(MaxCALifetime-time.Minute)); err != nil {
		t.Errorf("just under a day: %v", err)
	}
}

// TestNewTerminateRule: the host comes back canonical and the header lowercase,
// each rule gets a placeholder of its own, and a bad host, header, method,
// path or repository is refused, as are repositories beside a method or path.
func TestNewTerminateRule(t *testing.T) {
	t.Parallel()
	repo := func(repos ...string) []string { return repos }
	cases := []struct {
		host, header, method, path string
		repos                      []string
		ok                         bool
	}{
		{"API.example.com", "X-Api-Key", "", "", nil, true}, {"api.example.com.", "x-api-key", "POST", "/v1/", nil, true}, {"api.example.com", "x-api-key", "GET", "/", nil, true},
		{"api.example.com", "authorization", "", "", repo("octo/allowed", "octo-org/my.repo_1", "0/0"), true},
		{"192.0.2.1", "x-api-key", "", "", nil, false}, {"", "x-api-key", "", "", nil, false}, {"example.com", "x api key", "", "", nil, false}, {"example.com", "", "", "", nil, false},
		{"example.com", "x-api-key", "post", "", nil, false}, {"example.com", "x-api-key", "P O", "", nil, false},
		{"example.com", "x-api-key", "", "v1/", nil, false}, {"example.com", "x-api-key", "", "/v1?x", nil, false}, {"example.com", "x-api-key", "", "/v1#f", nil, false},
		{"example.com", "x-api-key", "", "/v 1", nil, false}, {"example.com", "x-api-key", "", "/caf\u00e9", nil, false},
		{"example.com", "authorization", "POST", "", repo("octo/allowed"), false}, {"example.com", "authorization", "", "/octo/", repo("octo/allowed"), false},
		{"example.com", "authorization", "", "", repo("octo"), false}, {"example.com", "authorization", "", "", repo("octo/allowed/x"), false},
		{"example.com", "authorization", "", "", repo("Octo/allowed"), false}, {"example.com", "authorization", "", "", repo("octo/allowed.git"), false},
		{"example.com", "authorization", "", "", repo("octo/"), false}, {"example.com", "authorization", "", "", repo("/allowed"), false},
		{"example.com", "authorization", "", "", repo("octo/.."), false}, {"example.com", "authorization", "", "", repo("./allowed"), false},
		{"example.com", "authorization", "", "", repo("octo/a b"), false}, {"example.com", "authorization", "", "", repo("octo/allowed", ""), false},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		got, err := NewTerminateRule(tc.host, tc.header, tc.method, tc.path, tc.repos)
		if (err == nil) != tc.ok {
			t.Errorf("NewTerminateRule(%q, %q, %q, %q, %q) = %v, want ok %t", tc.host, tc.header, tc.method, tc.path, tc.repos, err, tc.ok)
		}
		if err != nil {
			continue
		}
		if got.Host != "api.example.com" || got.Header != strings.ToLower(tc.header) || got.Method != tc.method || got.Path != tc.path || !slices.Equal(got.Repos, tc.repos) || !IsPlaceholder(got.Placeholder) || seen[got.Placeholder] {
			t.Errorf("NewTerminateRule(%q, %q, %q, %q, %q) = %+v", tc.host, tc.header, tc.method, tc.path, tc.repos, got)
		}
		seen[got.Placeholder] = true
	}
}

// TestTerminateNarrowedRule: a rule naming a method and a path prefix swaps a
// placeholder only on a request of that method under that prefix, and one
// naming repositories only on a request to /owner/name or /owner/name.git or
// under either, the placeholder bare, as a bearer or as a Basic password (as
// git sends a token), judged on the path as sent and as decoded; any other
// request carrying the placeholder in the bound header is refused before the
// broker hears of it, with nothing forwarded, and a request carrying no
// placeholder passes as is. The bytes the broker gave are wiped once the
// request carries them. Drop the check → the broker is asked and the upstream
// sees the value → FAIL.
func TestTerminateNarrowedRule(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{value: "real-secret"}
	addr, ca, p, log := terminateFixture(t, broker)
	c := clientVia(addr, caPool(t, ca))
	const n, r, auth = "n.example.com", "r.example.com", "Authorization"
	swapped := r + "  auth=" + basic("real-secret")
	cases := []struct {
		name, host, method, target, header, key string
		code                                    int
		body                                    string
	}{
		{"method and path match", n, "POST", "/v1/messages", "X-Api-Key", testPlaceholder, 200, "n.example.com real-secret"},
		{"the prefix itself", n, "POST", "/v1/", "X-Api-Key", testPlaceholder, 200, "n.example.com real-secret"},
		{"bearer under the prefix with a query", n, "POST", "/v1/x?q=1", "X-Api-Key", "Bearer " + testPlaceholder, 200, "n.example.com Bearer real-secret"},
		{"other method", n, "GET", "/v1/messages", "X-Api-Key", testPlaceholder, 403, ""},
		{"method in another case", n, "post", "/v1/messages", "X-Api-Key", testPlaceholder, 403, ""},
		{"other path", n, "POST", "/v2/no", "X-Api-Key", testPlaceholder, 403, ""},
		{"the prefix without its slash", n, "POST", "/v1", "X-Api-Key", testPlaceholder, 403, ""},
		{"dot segments leading out", n, "POST", "/v1/../v2/no", "X-Api-Key", testPlaceholder, 403, ""},
		{"encoded dot segments", n, "POST", "/v1/%2e%2e/v2/no", "X-Api-Key", testPlaceholder, 403, ""},
		{"encoded slash", n, "POST", "/v1%2Fx", "X-Api-Key", testPlaceholder, 403, ""},
		{"no placeholder", n, "GET", "/v2/no", "X-Api-Key", "user-key", 200, "n.example.com user-key"},
		{"a clone's refs within the repository", r, "GET", "/octo/allowed.git/info/refs?service=git-upload-pack", auth, basic(testAuthPlaceholder), 200, swapped},
		{"a fetch", r, "POST", "/octo/allowed.git/git-upload-pack", auth, basic(testAuthPlaceholder), 200, swapped},
		{"a push", r, "POST", "/octo/allowed.git/git-receive-pack", auth, basic(testAuthPlaceholder), 200, swapped},
		{"the repository itself, without .git", r, "GET", "/octo/allowed", auth, basic(testAuthPlaceholder), 200, swapped},
		{"a bearer within the repository", r, "GET", "/octo/allowed.git/info/refs?service=git-receive-pack", auth, "Bearer " + testAuthPlaceholder, 200, r + "  auth=Bearer real-secret"},
		{"a user's own token within the repository", r, "GET", "/octo/allowed.git/info/refs", auth, basic("user-key"), 200, r + "  auth=" + basic("user-key")},
		{"another repository", r, "GET", "/octo/other.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"a push to another repository", r, "POST", "/octo/other.git/git-receive-pack", auth, basic(testAuthPlaceholder), 403, ""},
		{"another owner", r, "GET", "/other/allowed.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"a longer name", r, "GET", "/octo/allowed-x.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"a longer suffix", r, "GET", "/octo/allowed.git-x/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"another letter case", r, "GET", "/Octo/Allowed.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"dot segments leading out of the repository", r, "GET", "/octo/allowed.git/../other.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"an encoded slash out of the repository", r, "GET", "/octo/allowed.git%2F..%2Fother.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"a doubled slash", r, "GET", "//octo/allowed.git/info/refs", auth, basic(testAuthPlaceholder), 403, ""},
		{"a bearer to another repository", r, "GET", "/octo/other.git/git-upload-pack", auth, "Bearer " + testAuthPlaceholder, 403, ""},
	}
	refused, swaps := map[string]uint64{}, 0
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, "https://"+tc.host+tc.target, nil)
		req.Header.Set(tc.header, tc.key)
		if code, body := do(t, c, req); code != tc.code || tc.body != "" && body != tc.body || code != 200 && strings.Contains(body, "real-secret") {
			t.Errorf("%s: got (%d, %q), want (%d, %q)", tc.name, code, body, tc.code, tc.body)
		}
		if tc.code == 403 {
			refused[tc.host]++
		} else if strings.Contains(tc.body, "real-secret") || tc.body == swapped {
			swaps++
		}
	}
	if got := broker.callCount(); got != swaps || !bytes.Equal(broker.last, make([]byte, len("real-secret"))) {
		t.Errorf("broker calls = %d, want %d (matching requests only); last value wiped = %t", got, swaps, got == swaps)
	}
	total := refused[n] + refused[r]
	want := denyLine{Host: r, Port: 443, Reason: "binding_mismatch", Count: refused[r], Seq: total}
	if d := denies(t, p, log); uint64(len(d)) != total || d[len(d)-1] != want {
		t.Errorf("deny lines = %+v, want %d ending in %+v", d, total, want)
	}
}

// TestPlaceholderForm: the three forms a placeholder is swapped in rebuild
// around the real value; a Basic value is a pair, the placeholder its whole
// password, strictly encoded and bounded; anything else is not swapped.
func TestPlaceholderForm(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString
	cases := []struct {
		values []string
		want   string // "" for no swap
	}{
		{[]string{testPlaceholder}, "real"}, {[]string{"Bearer " + testPlaceholder}, "Bearer real"}, {[]string{basic(testPlaceholder)}, basic("real")},
		{[]string{"Basic " + b64([]byte(":"+testPlaceholder))}, "Basic " + b64([]byte(":real"))},
		{[]string{testPlaceholder, testPlaceholder}, ""}, {nil, ""}, {[]string{"bearer " + testPlaceholder}, ""}, {[]string{"basic " + b64([]byte("x:"+testPlaceholder))}, ""},
		{[]string{"Basic " + b64([]byte(testPlaceholder))}, ""}, {[]string{"Basic " + b64([]byte(testPlaceholder+":x"))}, ""}, {[]string{"Basic " + b64([]byte("x:"+testPlaceholder+":y"))}, ""},
		{[]string{"Basic " + b64([]byte("x:" + testPlaceholder))[:10]}, ""}, {[]string{"Basic " + b64([]byte("x:"+testPlaceholder)) + "\n"}, ""}, {[]string{"Basic " + strings.Repeat("A", maxBasic+4)}, ""},
		{[]string{basic(testAuthPlaceholder)}, ""}, {[]string{"Basic  " + b64([]byte("x:"+testPlaceholder))}, ""},
	}
	for _, tc := range cases {
		form, ok := placeholderForm(tc.values, testPlaceholder)
		if got := ""; ok != (tc.want != "") || ok && func() string { got = form([]byte("real")); return got }() != tc.want {
			t.Errorf("placeholderForm(%q) = %q, %t; want %q", tc.values, got, ok, tc.want)
		}
	}
}

func TestTerminateRefusesBadRules(t *testing.T) {
	t.Parallel()
	p, _, _ := testProxy(t, "example.com:443 db.example.com:5432", nil, "")
	rule := TerminateRule{Host: "example.com", Header: "x-api-key", Placeholder: testPlaceholder}
	for name, rules := range map[string][]TerminateRule{
		"off allowlist":  {{Host: "other.example.com", Header: "x-api-key", Placeholder: testPlaceholder}},
		"plain port":     {{Host: "db.example.com", Header: "x-api-key", Placeholder: testPlaceholder}},
		"duplicate":      {rule, rule},
		"duplicate case": {rule, {Host: "example.com", Header: "X-API-KEY", Placeholder: testAuthPlaceholder}},
	} {
		if err := p.Terminate(nil, nil, rules); err == nil {
			t.Errorf("%s: Terminate succeeded, want refusal", name)
		}
	}
}

func TestNewPlaceholderIsFreshAndParses(t *testing.T) {
	t.Parallel()
	first, second := NewPlaceholder(), NewPlaceholder()
	if !IsPlaceholder(first) || first == second {
		t.Fatalf("NewPlaceholder() = %q then %q, want two distinct placeholders", first, second)
	}
	for _, bad := range []string{"", "wcph-", first + "0", first[:len(first)-1], "WCPH-" + first[5:], " " + first, first + "\n"} {
		if IsPlaceholder(bad) {
			t.Errorf("IsPlaceholder(%q) = true", bad)
		}
	}
}

// TestTerminateRefusesTraceAndConnect: TRACE could echo the swapped key and
// CONNECT tunnels past the rewrite, so both get 405 before the swap; a GET
// still reaches the upstream. Drop the method check → the broker is asked and
// the request goes upstream → FAIL.
func TestTerminateRefusesTraceAndConnect(t *testing.T) {
	t.Parallel()
	broker := &fakeBroker{value: "real-secret"}
	addr, ca, p, log := terminateFixture(t, broker)
	c := clientVia(addr, caPool(t, ca))
	for _, method := range []string{http.MethodTrace, http.MethodConnect} {
		req := must(http.NewRequest(method, "https://example.com/v1", nil))
		req.Header.Set("X-Api-Key", testPlaceholder)
		if code, body := do(t, c, req); code != http.StatusMethodNotAllowed || !strings.Contains(body, "method not allowed") {
			t.Errorf("%s: got (%d, %q), want 405 from the proxy", method, code, body)
		}
	}
	d := denies(t, p, log)
	want := denyLine{Host: "example.com", Port: 443, Reason: "method_refused", Count: 2, Seq: 2}
	if len(d) != 2 || d[1] != want {
		t.Fatalf("deny lines = %+v, want 2 ending in %+v", d, want)
	}
	req := must(http.NewRequest(http.MethodGet, "https://example.com/v1", nil))
	req.Header.Set("X-Api-Key", testPlaceholder)
	if code, _ := do(t, c, req); code == http.StatusMethodNotAllowed {
		t.Fatalf("GET got 405, want it forwarded")
	}
}

// FuzzCarriesPlaceholder: a placeholder in any case in a header name, a
// header value, a Basic value decoded or the raw target must be caught, and
// a swap form must rebuild the exact value it matched.
func FuzzCarriesPlaceholder(f *testing.F) {
	f.Add("X-Api-Key", "Bearer "+testPlaceholder, "/v1?key=%77cph-0123456789abcdef0123456789abcdef")
	f.Add("X-"+strings.ToUpper(testPlaceholder), "v", "/")
	f.Add("Authorization", basic(testPlaceholder), "/octo/allowed.git/info/refs")
	f.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(strings.ToUpper(testPlaceholder))), "/")
	f.Fuzz(func(t *testing.T, name, value, target string) {
		r := &http.Request{RequestURI: target, Header: http.Header{name: {value}}}
		hit := carriesPlaceholder(r)
		pair, _ := basicDecode(value)
		for _, s := range []string{name, value, target, string(pair)} {
			if strings.Contains(strings.ToLower(s), testPlaceholder) && !hit {
				t.Fatalf("carriesPlaceholder missed %q in (%q, %q, %q)", testPlaceholder, name, value, target)
			}
		}
		if form, ok := placeholderForm([]string{value}, testPlaceholder); ok && form([]byte(testPlaceholder)) != value {
			t.Fatalf("placeholderForm(%q) does not rebuild the value: %q", value, form([]byte(testPlaceholder)))
		}
	})
}
