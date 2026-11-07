// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I14 judges run the product's update client on the host against a
// channel and an upstream the judge serves on the test host's own loopback
// (SPEC T8), signed with a key the judge made, in the format of ADR-004:
// updateJudge through `workcell update`, dailyJudge through the check a
// session start makes by itself. The invariant holds only if nothing from a
// hostile manifest is installed. The guest plays no part; the probe is idle.

// payloadType is the DSSE payload type of channel.json.
const payloadType = "application/vnd.workcell.channel+json"

// pinName is the pin every manifest carries: claude's row, which the adapter maps to its agent.
const pinName = "claude-code"

const day = 24 * 60 * 60

// pin is one artifact in a manifest.
type pin struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Released int64  `json:"released"`
}

// manifest is the payload of channel.json.
type manifest struct {
	Serial    int64                     `json:"serial"`
	Expires   int64                     `json:"expires"`
	Pins      map[string]map[string]pin `json:"pins"`
	Previous  map[string]map[string]pin `json:"previous"`
	Withdrawn []string                  `json:"withdrawn"`
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

// artifact is a provider binary as far as the judge cares: bytes naming their label, long enough to cut short.
func artifact(label string) []byte {
	return bytes.Repeat([]byte("escape artifact "+label+"\n"), 256)
}

// upstream is one server on the test host's loopback, HTTPS under cfg or
// plain HTTP without one, answering each path as set and recording every path asked for.
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
		ReadTimeout: 3 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0),
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
	u.stop = func() { srv.Close() }
	if cfg == nil {
		go srv.Serve(ln)
		return u, nil
	}
	u.url, srv.TLSConfig = "https://"+ln.Addr().String(), cfg
	go srv.ServeTLS(ln, "", "")
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

// whole serves b; cut promises all of b, sends half and hangs up; moved
// sends the client on to url.
func whole(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.Write(b) }
}

func cut(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Write(b[:len(b)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
}

func moved(url string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, url, http.StatusFound) }
}

// idleProbe is the probe of a test the guest plays no part in.
func idleProbe([]string) Result {
	return Result{Status: "idle", Detail: "this test runs on the host"}
}

// channel is a judge's channel: an HTTPS server under the suite's authority
// serving channel.json and the artifacts it pins, a listener beside it that
// is not HTTPS, the one key the client trusts, and the honest manifest
// published first, m, pinning 1.0.0 as the artifact good.
type channel struct {
	src, plain *upstream
	key        ed25519.PrivateKey
	now        int64
	good       []byte
	m          manifest
}

func openChannel() (*channel, error) {
	cfg, err := certificate("127.0.0.1") // the judge's servers, under the suite's authority, which the client gets
	if err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	src, err := serve(cfg)
	if err != nil {
		return nil, err
	}
	plain, err := serve(nil)
	if err != nil {
		src.stop()
		return nil, err
	}
	c := &channel{src: src, plain: plain, key: key, now: time.Now().Unix(), good: artifact("honest")}
	c.m = c.manifest(c.now-120, "1.0.0", src.url+"/honest", c.good)
	c.m.Previous = map[string]map[string]pin{} // the first manifest: nothing before it
	src.set("/honest", whole(c.good))
	return c, publish(src, c.m, key, nil)
}

func (c *channel) stop() {
	c.src.stop()
	c.plain.stop()
}

// manifest is a manifest of the serial given, valid for 13 days, pinning
// version at url as the artifact art, with the honest pins as previous.
func (c *channel) manifest(serial int64, version, url string, art []byte) manifest {
	return manifest{Serial: serial, Expires: serial + 13*day, Pins: pins(version, url, art, c.now-7*day), Previous: c.m.Pins, Withdrawn: []string{}}
}

// config is the [update] table a client gets: the channel, the suite's
// authority and the key, with version as `--to`.
func (c *channel) config(version string) sandbox.UpdateConfig {
	return sandbox.UpdateConfig{Channel: c.src.url + "/channel.json", CA: authority.pem, Key: c.key.Public().(ed25519.PublicKey), Name: pinName, Version: version}
}

// hostile publishes the variant named in place of the honest manifest: a
// later one pinning 1.0.1 as a new artifact, which it returns, that the
// client must refuse.
func (c *channel) hostile(variant string) ([]byte, error) {
	bad := artifact(variant)
	h := c.manifest(c.now-60, "1.0.1", c.src.url+"/"+variant, bad)
	c.src.set("/"+variant, whole(bad))
	signer, tamper := c.key, func(*envelope) {}
	var err error
	switch variant {
	case "wrong-key":
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case "corrupt-signature":
		tamper = func(e *envelope) { e.Signatures[0].Sig[0] ^= 1 }
	case "expired":
		h.Expires = c.now - 3600
	case "lower-serial":
		h.Serial, h.Expires = c.m.Serial-day, c.m.Serial+12*day
	case "serial-ahead":
		h.Serial, h.Expires = c.now+25*3600, c.now+25*3600+13*day
	case "digest-mismatch":
		c.src.set("/"+variant, whole(artifact("tampered")))
	case "truncated":
		c.src.set("/"+variant, cut(bad))
	case "redirected": // sent off the pinned HTTPS URL to a listener that is not
		c.plain.set("/moved", whole(bad))
		c.src.set("/"+variant, moved(c.plain.url+"/moved"))
	case "plain-http":
		c.plain.set("/"+variant, whole(bad))
		h.Pins = pins("1.0.1", c.plain.url+"/"+variant, bad, c.now-7*day)
	default:
		return nil, errors.New("unknown variant " + variant)
	}
	if err == nil {
		err = publish(c.src, h, signer, tamper)
	}
	return bad, err
}

// updateJudge serves a valid channel and has the client install from it; then
// it serves the hostile variant named, and after that a valid successor. The
// invariant holds only if nothing from the variant was installed, neither the
// artifact it pins nor any bytes but the honest one, and the successor is:
// a client that installs once and never fetches again proves nothing.
func updateJudge(variant string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		ch, err := openChannel()
		if err != nil {
			return false, "", err
		}
		defer ch.stop()
		u := ch.config("1.0.0")
		got, err := s.Update(ctx, u)
		if err != nil {
			return false, "", fmt.Errorf("the client did not install from a valid manifest: %w", err)
		}
		if !bytes.Equal(got, ch.good) {
			return false, "", fmt.Errorf("the client installed %d bytes from a valid manifest, not the %d-byte artifact it pins (%d requests served)", len(got), len(ch.good), len(ch.src.requests()))
		}
		bad, err := ch.hostile(variant)
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
		case len(got) > 0 && !bytes.Equal(got, ch.good):
			return false, fmt.Sprintf("the client installed %d bytes that are neither artifact, from the %s manifest", len(got), variant), nil
		}
		if rs := ch.plain.requests(); len(rs) > 0 {
			return false, fmt.Sprintf("the client fetched %v without TLS", rs), nil
		}
		// A valid successor pinning the same version: a client that refused the
		// variant must still install from it.
		next := artifact("successor")
		ch.src.set("/successor", whole(next))
		if err := publish(ch.src, ch.manifest(ch.now-30, "1.0.1", ch.src.url+"/successor", next), ch.key, nil); err != nil {
			return false, "", err
		}
		got, err = s.Update(ctx, u)
		if err != nil || !bytes.Equal(got, next) {
			return false, "", fmt.Errorf("after the %s manifest the client did not install from a valid successor (%d bytes, err %v)", variant, len(got), err)
		}
		return true, fmt.Sprintf("nothing installed from the %s manifest, then the successor was; the channel served %v", variant, ch.src.requests()), nil
	}
}

// dailyJudge is I14 at the installer's second entry: the channel check a
// session start makes by itself, once a day, and the install the next start
// makes from what it kept, in a session of its own carrying the [update]
// table. Under a hostile variant the channel serves only that manifest,
// pinning 1.0.1: the first start must ask for channel.json (a client that
// never checks proves nothing), and after a second nothing may be installed
// nor the pinned artifact fetched. Under "once" it serves the honest
// manifest: after three starts the layer must hold the honest artifact,
// exactly the digest pinned, and channel.json was asked for once.
func dailyJudge(variant string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		ch, err := openChannel()
		if err != nil {
			return false, "", err
		}
		defer ch.stop()
		starts, bad := 3, []byte(nil)
		if variant != "once" {
			if bad, err = ch.hostile(variant); err != nil {
				return false, "", err
			}
			starts = 2
		}
		u := ch.config("")
		d, err := s.Another(&u)
		if err != nil {
			return false, "", err
		}
		for i := range starts {
			if _, err := d.Run(); err != nil {
				return false, "", fmt.Errorf("session start %d: %w", i+1, err)
			}
			if i == 0 && !slices.Contains(ch.src.requests(), "/channel.json") {
				return false, "", errors.New("the first session start of the day never asked the channel for channel.json, so nothing is proven")
			}
		}
		got, err := d.Installed(ctx, pinName)
		if err != nil {
			return false, "", err
		}
		rs := ch.src.requests()
		say := fmt.Sprintf("; over %d starts the channel served %v", starts, rs)
		if variant == "once" {
			n := strings.Count(strings.Join(rs, " "), "/channel.json")
			switch {
			case !bytes.Equal(got, ch.good):
				return false, fmt.Sprintf("after %d starts the layer installed holds %d bytes, not the honest artifact the manifest pins%s", starts, len(got), say), nil
			case n != 1:
				return false, fmt.Sprintf("channel.json was asked for %d times in one day, not once%s", n, say), nil
			}
			return true, "the day's one check installed the honest artifact at the next start" + say, nil
		}
		switch {
		case bytes.Equal(got, bad):
			return false, "a session start installed the artifact the " + variant + " manifest pins" + say, nil
		case len(got) > 0:
			return false, fmt.Sprintf("a session start installed %d bytes from the %s manifest%s", len(got), variant, say), nil
		case slices.Contains(rs, "/"+variant):
			return false, "a session start fetched the artifact the " + variant + " manifest pins" + say, nil
		}
		return true, "nothing installed or fetched from the " + variant + " manifest" + say, nil
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
