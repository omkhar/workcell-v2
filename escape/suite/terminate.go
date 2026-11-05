// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The I6 rows. A bare allowed name is one the product terminates: the guest
// is to meet a leaf for the name from a per-session authority whose key is
// the host's alone, and the host is to carry the request on to the name the
// SNI gave, verifying the upstream's certificate as itself. The canaries for
// both allowed names share one listener at port 443 where the product
// reaches the test host, told apart by the name the connection's SNI
// carried; their certificate chains to the suite's own authority, which the
// runner gives the host side of every session as its trust store
// (sandbox.Config.Roots). A guest that validates a canary's leaf was spliced
// through, not terminated.

// terminating is the sandbox the rows want: two allowed names, bare, the
// judge as the host's resolver, and the host side in a network of its own,
// where the judge holds the one address both names resolve to (SPEC T8).
var terminating = Want{Allow: []string{"bound.escape.test", "other.escape.test"}, Resolver: judgeResolver, Isolated: true}

// authority is the suite's certificate authority, made once per process.
var authority struct {
	once sync.Once
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	err  error
}

func roots() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	authority.once.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			authority.err = err
			return
		}
		now := time.Now()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "escape canary authority"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err == nil {
			authority.cert, err = x509.ParseCertificate(der)
		}
		authority.key, authority.pem, authority.err = key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
	})
	return authority.cert, authority.key, authority.err
}

// Roots writes the authority's certificate, in PEM, under dir and returns
// the file's path: the trust store the runner gives every session's host
// side, as an operator's SSL_CERT_FILE would hold it.
func Roots(dir string) (string, error) {
	if _, _, err := roots(); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "roots.pem")
	return path, os.WriteFile(path, authority.pem, 0o644)
}

// certificate makes a TLS server configuration whose certificate the
// authority signed for the names given, DNS names or IP addresses; with none
// it is a certificate nothing verifies.
func certificate(names ...string) (*tls.Config, error) {
	ca, caKey, err := roots()
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, nil
}

// twoNames serves a canary for each allowed name on one listener at port
// 443 where the product reaches the test host, the first accepting ECH
// under the second's name when ech is set, runs the judge's resolver
// answering both names with that address, and hands the canaries to judge.
func twoNames(ech bool, judge func(s Session, bound, other *canary) (bool, string, error)) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		ln, _, err := bind(ctx, s, "tcp4", hostAddr+":443")
		if err != nil {
			return false, "", err
		}
		host, _, _ := net.SplitHostPort(ln.Addr().String())
		_, pc, err := bind(ctx, s, "udp4", net.JoinHostPort(judgeResolver, "53"))
		if err != nil {
			ln.Close()
			return false, "", err
		}
		ns := serveNamesOn(pc, rebind{a: []string{host}, names: []string{s.Allow[0] + ".", s.Allow[1] + "."}})
		defer ns.stop()
		bound, other := &canary{name: s.Allow[0]}, &canary{name: s.Allow[1]}
		var keys []tls.EncryptedClientHelloKey
		if ech {
			if bound.ech, keys, err = echKeys(other.name); err != nil {
				ln.Close()
				return false, "", err
			}
		}
		stop, err := serveCanaries(ln, keys, nil, bound, other)
		if err != nil {
			return false, "", err
		}
		defer stop()
		return judge(s, bound, other)
	}
}

// terminatedProbe is a program in the guest opening TLS to the bound name
// twice, as programs do: trusting what its environment names (nil roots:
// the standard library reads SSL_CERT_FILE) and trusting the canary's own
// authority alone (args[5], PEM in base64). On a terminated connection the
// first validates a leaf for the name and the second meets a leaf the
// canary's authority never signed; on a spliced one the second validates.
// Each that validates asks for /terminated, so that the canary saw it.
func terminatedProbe(args []string) Result {
	t, bad := parseTargets(args)
	if bad.Status != "" {
		return bad
	}
	if len(t.extra) != 1 {
		return Result{Status: "error", Detail: "want the canary authority's certificate"}
	}
	ca, err := base64.StdEncoding.DecodeString(t.extra[0])
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return Result{Status: "error", Detail: "the canary authority's certificate is not PEM"}
	}
	env, envSaid, envErr := handshake(t.bound, t.addrs[t.bound], nil)
	canary, canarySaid, canaryErr := handshake(t.bound, t.addrs[t.bound], pool)
	var verify *tls.CertificateVerificationError
	status := "untrusted" // the guest validates the leaf with neither
	switch {
	case canary:
		status = "spliced"
	case env && errors.As(canaryErr, &verify):
		status = "terminated"
	case env: // the second connection met no leaf at all
		return dialFailed(canaryErr)
	case !errors.As(envErr, &verify):
		return dialFailed(envErr)
	}
	file := os.Getenv("SSL_CERT_FILE")
	if file == "" {
		file = "unset"
	}
	return Result{Status: status, Detail: fmt.Sprintf("env roots: %s; canary roots: %s; SSL_CERT_FILE=%s", envSaid, canarySaid, file)}
}

// handshake opens TLS to addr as name under roots and says whether it
// validated, with the leaf it met or the error; a validated connection
// carries one request for /terminated.
func handshake(name, addr string, roots *x509.CertPool) (bool, string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		return false, err.Error(), err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	leaf := c.ConnectionState().PeerCertificates[0]
	fmt.Fprintf(c, "GET /terminated HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", name)
	line, _ := bufio.NewReader(c).ReadString('\n')
	return true, fmt.Sprintf("validated a leaf for %v issued by %q, got %q", leaf.DNSNames, leaf.Issuer.CommonName, strings.TrimSpace(line)), nil
}

// terminationJudge expects the guest to have validated the bound name with
// the roots its environment names and not with the canary's authority, and
// the bound canary to have served the request that came on that connection,
// in the open and under its own name: the product terminated the connection
// and reached the upstream as itself. A leaf of the canary's authority in
// the guest was spliced through; a leaf the guest could validate with
// neither is one the product set no trust for.
func terminationJudge(s Session, bound, other *canary) (bool, string, error) {
	if _, _, err := roots(); err != nil {
		return false, "", err
	}
	r, err := run(s, bound, other, base64.StdEncoding.EncodeToString(authority.pem))
	if err != nil {
		return false, "", err
	}
	if r.Status != "terminated" {
		return false, fmt.Sprintf("the connection to %s was not terminated by the host with a leaf the guest trusts (guest says %s: %s)", bound.name, r.Status, r.Detail), nil
	}
	rs := bound.requests()
	for _, q := range rs {
		if !q.wellFormed(bound.name) {
			return false, fmt.Sprintf("%s served %s %s with SNI %s and Host %s (guest says %s: %s)", bound.name, q.proto, q.method, q.sni, q.host, r.Status, r.Detail), nil
		}
	}
	if len(other.requests()) > 0 {
		return false, fmt.Sprintf("%s (the connection named %s; guest says %s: %s)", other.served(), bound.name, r.Status, r.Detail), nil
	}
	if len(rs) == 0 {
		return false, "", fmt.Errorf("%s saw nothing, though the guest validated a connection to it (guest says %s: %s)", bound.name, r.Status, r.Detail)
	}
	return true, fmt.Sprintf("%s (guest says %s: %s)", bound.served(), r.Status, r.Detail), nil
}
