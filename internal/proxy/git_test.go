// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestGitOverHTTPS is the accept clause of a token scoped to repositories: real git (on the host,
// since the guest image has none) clones from and pushes to a bare repository that git's own
// http-backend serves over smart HTTP on a loopback TLS listener of the test's own (T8), through
// the terminating proxy and the real broker, with the placeholder as the password of its Basic
// credential, the one form the guest holds. The server sees the real token alone, the clone and
// git's output never hold it, and the same placeholder is refused for another repository on the
// same host before the server hears of it.
func TestGitOverHTTPS(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH")
	}
	execPath, err := exec.Command(git, "--exec-path").Output()
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, statErr := os.Stat(backend); err != nil || statErr != nil {
		t.Skip("git-http-backend is not installed")
	}
	const token = "REAL-0123456789abcdef"
	root, home := t.TempDir(), t.TempDir() // the server's repositories; the user's side, with nothing but the test's own
	bare := func(name string) string { return filepath.Join(root, "octo", name+".git") }
	env := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_SSL_CAINFO=" + filepath.Join(home, "ca.pem"),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example"}
	run := func(dir string, args ...string) (string, error) { // git with no credential helper; its output never holds the token
		cmd := exec.Command(git, append([]string{"-c", "credential.helper="}, args...)...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), token) {
			t.Errorf("git %v printed the real token: %q", args, out)
		}
		return strings.TrimSpace(string(out)), err
	}
	ok := func(dir string, args ...string) string {
		t.Helper()
		out, err := run(dir, args...)
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return out
	}
	for _, name := range []string{"allowed", "other"} { // two bare repositories of octo that take pushes
		ok(root, "init", "-q", "--bare", "-b", "main", bare(name))
		ok(root, "-C", bare(name), "config", "http.receivepack", "true")
	}
	seed := filepath.Join(root, "seed") // allowed holds one commit, so that a clone has content
	ok(root, "init", "-q", "-b", "main", seed)
	must(0, os.WriteFile(filepath.Join(seed, "README"), []byte("hello\n"), 0o644))
	ok(seed, "add", "README")
	ok(seed, "commit", "-q", "-m", "seed")
	ok(seed, "push", "-q", bare("allowed"), "main")

	var mu sync.Mutex
	var seen []string // "path password" of each request that carried a credential
	backendHandler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, password, carried := r.BasicAuth()
		if carried {
			mu.Lock()
			seen = append(seen, r.URL.Path+" "+password)
			mu.Unlock()
		}
		if password != token {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		backendHandler.ServeHTTP(w, r)
	}))
	authority := must(NewSessionCA([]string{"localhost"}, time.Now().Add(time.Hour))) // the server's own CA, trusted by the proxy alone
	server.TLS = &tls.Config{Certificates: []tls.Certificate{*must(authority.leaf("localhost"))}}
	server.StartTLS()
	t.Cleanup(server.Close)

	p, _, _ := testProxy(t, "localhost:443", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, server.Listener.Addr().String())
	p.upstreamRoots = caPool(t, authority)
	rule := must(NewTerminateRule("localhost", "authorization", "", "", []string{"octo/allowed"}))
	must(0, os.WriteFile(filepath.Join(home, "token"), []byte(token+"\n"), 0o600))
	ledger := must(os.OpenFile(filepath.Join(home, "secrets.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600))
	t.Cleanup(func() { ledger.Close() })
	broker := must(secret.NewBroker([]secret.Grant{{Name: "git", Source: "file:" + filepath.Join(home, "token"), Host: rule.Host, Header: rule.Header}}, ledger))
	sessionCA := must(NewSessionCA([]string{"localhost"}, time.Now().Add(time.Hour)))
	must(0, p.Terminate(sessionCA, broker, []TerminateRule{rule}))
	must(0, os.WriteFile(filepath.Join(home, "ca.pem"), sessionCA.CertPEM(), 0o644))
	_, port, _ := net.SplitHostPort(listen(t, p, 443))
	remote := func(name string) string {
		return "https://x-access-token:" + rule.Placeholder + "@localhost:" + port + "/octo/" + name + ".git"
	}

	clone := filepath.Join(home, "allowed")
	ok(home, "clone", "-q", remote("allowed"), clone)
	if b, err := os.ReadFile(filepath.Join(clone, "README")); err != nil || string(b) != "hello\n" {
		t.Errorf("the clone's README = %q, %v; want the seeded content", b, err)
	}
	must(0, os.WriteFile(filepath.Join(clone, "work.txt"), []byte("pushed\n"), 0o644))
	ok(clone, "add", "work.txt")
	ok(clone, "commit", "-q", "-m", "work")
	ok(clone, "push", "-q", "origin", "main")
	if head, pushed := ok(clone, "rev-parse", "HEAD"), ok(root, "-C", bare("allowed"), "rev-parse", "main"); head != pushed {
		t.Errorf("after the push the bare repository's main is %s, the clone's HEAD %s", pushed, head)
	}
	if cfg, err := os.ReadFile(filepath.Join(clone, ".git", "config")); err != nil || strings.Contains(string(cfg), token) {
		t.Errorf("the clone's config holds the real token (%v)", err)
	}
	if out, err := run(home, "clone", "-q", remote("other"), filepath.Join(home, "other")); err == nil || !strings.Contains(out, "403") {
		t.Errorf("clone of the other repository = %v, %q; want a failure on the proxy's 403", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if path, password, _ := strings.Cut(s, " "); !strings.HasPrefix(path, "/octo/allowed.git/") || password != token {
			t.Errorf("the server saw a credential %q for %s, want the real token for octo/allowed alone", password, path)
		}
	}
	for _, want := range []string{"/octo/allowed.git/git-upload-pack " + token, "/octo/allowed.git/git-receive-pack " + token} {
		if !slices.Contains(seen, want) {
			t.Errorf("the server saw %q, want the clone's fetch and the push, %q", seen, want)
		}
	}
}
