// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I14 judges run the product's update client on the host against a
// channel and an upstream the judge serves itself, on the test host's own
// loopback (SPEC T8), signed with a key the judge made, in the format of
// ADR-004. Each judge first serves a valid manifest and the artifact it pins,
// and errors unless the client installs it: a client that installs nothing
// proves nothing. Then it serves one hostile variant, and the invariant holds
// only if nothing from the variant was installed. The guest plays no part;
// the probe is idle.

// payloadType is the DSSE payload type of channel.json.
const payloadType = "application/vnd.workcell.channel+json"

// pinName is the pin every manifest carries and the client is told to install.
const pinName = "provider"

const day = 24 * 60 * 60

// pin is one artifact in a manifest.
type pin struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Released int64  `json:"released"`
}

// manifest is the payload of channel.json. Pad is a field no client knows,
// for the variant that is too large.
type manifest struct {
	Serial    int64                     `json:"serial"`
	Expires   int64                     `json:"expires"`
	Pins      map[string]map[string]pin `json:"pins"`
	Previous  map[string]map[string]pin `json:"previous"`
	Withdrawn []string                  `json:"withdrawn"`
	Pad       string                    `json:"pad,omitempty"`
}

// envelope is channel.json itself: a DSSE envelope over the manifest.
type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

// pae is the DSSE pre-authentication encoding the signature covers.
func pae(payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

// keyID is the hex SHA-256 of the public key, as ADR-004 derives it.
func keyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// sign wraps m in an envelope with one signature by key.
func sign(m manifest, key ed25519.PrivateKey) (envelope, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return envelope{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	return envelope{PayloadType: payloadType, Payload: payload,
		Signatures: []signature{{KeyID: keyID(pub), Sig: ed25519.Sign(key, pae(payload))}}}, nil
}

// pins is a manifest's pin table holding one artifact for pinName on the
// host's own architecture: the version, where it is, and its digest.
func pins(version, url string, artifact []byte, released int64) map[string]map[string]pin {
	sum := sha256.Sum256(artifact)
	return map[string]map[string]pin{pinName: {runtime.GOARCH: {Version: version, URL: url, SHA256: hex.EncodeToString(sum[:]), Released: released}}}
}

// artifact is a provider binary as far as the judge cares: bytes that name
// their label, long enough that a download can stop short of them.
func artifact(label string) []byte {
	return bytes.Repeat([]byte("escape artifact "+label+"\n"), 256)
}

// authority makes a certificate authority and a certificate it signed for the
// loopback address, for the judge's servers. The client gets the authority.
func authority() (caPEM []byte, cfg *tls.Config, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "escape channel authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, nil
}

// upstream is one server on the test host's loopback, HTTPS under cfg or
// plain HTTP without one, that answers each path as the judge set it and
// records every path asked for.
type upstream struct {
	url   string
	mu    sync.Mutex
	paths map[string]http.HandlerFunc
	seen  []string
	stop  func()
}

func serve(cfg *tls.Config) (*upstream, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("upstream listener: %w", err)
	}
	u := &upstream{paths: map[string]http.HandlerFunc{}, url: "http://" + ln.Addr().String()}
	srv := &http.Server{
		ReadTimeout:  3 * time.Second,
		ErrorLog:     log.New(io.Discard, "", 0),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, // HTTP/1.1, so that a body can stop short
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.mu.Lock()
			u.seen = append(u.seen, r.URL.Path)
			h := u.paths[r.URL.Path]
			u.mu.Unlock()
			if h == nil {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}),
	}
	var wg sync.WaitGroup
	if cfg != nil {
		u.url = "https://" + ln.Addr().String()
		srv.TLSConfig = cfg
		wg.Go(func() { srv.ServeTLS(ln, "", "") })
	} else {
		wg.Go(func() { srv.Serve(ln) })
	}
	u.stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		srv.Close()
		wg.Wait()
	}
	return u, nil
}

func (u *upstream) set(path string, h http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.paths[path] = h
}

func (u *upstream) requests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.seen)
}

// whole serves b; cut promises all of b and sends half, then hangs up;
// moved sends the client on to url.
func whole(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.Write(b) }
}

func cut(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(b))
		rw.Write(b[:len(b)/2])
		rw.Flush()
		conn.Close()
	}
}

func moved(url string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, url, http.StatusFound) }
}

// idleProbe is the probe of a test the guest plays no part in.
func idleProbe([]string) Result {
	return Result{Status: "idle", Detail: "the update client runs on the host"}
}

// updateJudge serves a valid channel and has the client install from it; then
// it serves the hostile variant named and passes only if nothing from it was
// installed: the artifact it pins, or any bytes but the honest one.
func updateJudge(variant string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		caPEM, cfg, err := authority()
		if err != nil {
			return false, "", err
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return false, "", err
		}
		src, err := serve(cfg) // the channel and the upstream it pins
		if err != nil {
			return false, "", err
		}
		defer src.stop()
		other, err := serve(cfg) // a listener no manifest names
		if err != nil {
			return false, "", err
		}
		defer other.stop()
		plain, err := serve(nil) // one that is not HTTPS
		if err != nil {
			return false, "", err
		}
		defer plain.stop()
		now := time.Now().Unix()
		good := artifact("honest")
		m := manifest{Serial: now - 120, Expires: now - 120 + 13*day, Pins: pins("1.0.0", src.url+"/honest", good, now-7*day),
			Previous: map[string]map[string]pin{}, Withdrawn: []string{}}
		if err := publish(src, m, key, nil); err != nil {
			return false, "", err
		}
		src.set("/honest", whole(good))
		u := sandbox.UpdateConfig{Channel: src.url + "/channel.json", CA: caPEM, Key: pub, Name: pinName, Version: "1.0.0"}
		got, err := s.Update(ctx, u)
		if err != nil {
			return false, "", fmt.Errorf("the client did not install from a valid manifest: %w", err)
		}
		if !bytes.Equal(got, good) {
			return false, "", fmt.Errorf("the client installed %d bytes from a valid manifest, not the %d-byte artifact it pins (%d requests served)", len(got), len(good), len(src.requests()))
		}
		// The variant: a later manifest pinning a new artifact, which must be refused.
		bad := artifact(variant)
		h := manifest{Serial: now - 60, Expires: now - 60 + 13*day, Pins: pins("1.0.1", src.url+"/"+variant, bad, now-day),
			Previous: m.Pins, Withdrawn: []string{}}
		src.set("/"+variant, whole(bad))
		signer, tamper := key, func(*envelope) {}
		switch variant {
		case "wrong-key":
			_, signer, err = ed25519.GenerateKey(rand.Reader)
		case "corrupt-signature":
			tamper = func(e *envelope) { e.Signatures[0].Sig[0] ^= 1 }
		case "expired":
			h.Expires = now - 3600
		case "lower-serial":
			h.Serial, h.Expires = m.Serial-day, m.Serial+12*day
		case "serial-ahead":
			h.Serial, h.Expires = now+25*3600, now+25*3600+13*day
		case "oversized":
			h.Pad = strings.Repeat("x", 64<<10)
		case "digest-mismatch":
			src.set("/"+variant, whole(artifact("tampered")))
		case "truncated":
			src.set("/"+variant, cut(bad))
		case "redirected":
			other.set("/"+variant, whole(bad))
			src.set("/"+variant, moved(other.url+"/"+variant))
		case "plain-http":
			plain.set("/"+variant, whole(bad))
			h.Pins = pins("1.0.1", plain.url+"/"+variant, bad, now-day)
		default:
			return false, "", errors.New("unknown variant " + variant)
		}
		if err == nil {
			err = publish(src, h, signer, tamper)
		}
		if err != nil {
			return false, "", err
		}
		u.Version = "1.0.1"
		got, err = s.Update(ctx, u)
		switch {
		case err != nil:
			return false, "", err
		case bytes.Equal(got, bad):
			return false, "the client installed the artifact the " + variant + " manifest pins", nil
		case len(got) > 0 && !bytes.Equal(got, good):
			return false, fmt.Sprintf("the client installed %d bytes that are neither artifact, from the %s manifest", len(got), variant), nil
		}
		for _, l := range []*upstream{other, plain} {
			if rs := l.requests(); len(rs) > 0 {
				return false, fmt.Sprintf("the client fetched %v from a server the valid manifest never named", rs), nil
			}
		}
		return true, fmt.Sprintf("nothing installed from the %s manifest; the honest install stands (%d bytes); the channel served %v", variant, len(got), src.requests()), nil
	}
}

// publish signs m with key, lets tamper edit the envelope, and serves it as
// the channel's channel.json.
func publish(src *upstream, m manifest, key ed25519.PrivateKey, tamper func(*envelope)) error {
	env, err := sign(m, key)
	if err != nil {
		return err
	}
	if tamper != nil {
		tamper(&env)
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	src.set("/channel.json", whole(b))
	return nil
}
