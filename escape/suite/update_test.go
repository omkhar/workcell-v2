// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// careful is a client that makes every check ADR-004 lists, so that each
// judge is shown to have a pass; idle is one that installs nothing, so that
// each judge is shown to error rather than pass on it.
type careful struct {
	noObserve
	serial    int64
	installed []byte
}

type noObserve struct{}

func (noObserve) Audit(context.Context) (string, []string, error) {
	return "", nil, sandbox.ErrNotImplemented
}
func (noObserve) Verify(context.Context) error                { return sandbox.ErrNotImplemented }
func (noObserve) Helper(context.Context, string) (int, error) { return 0, sandbox.ErrNotImplemented }
func (noObserve) Channel(context.Context) (sandbox.Channel, error) {
	return sandbox.Channel{}, sandbox.ErrNotImplemented
}

type idle struct{ noObserve }

func (idle) Update(context.Context, sandbox.UpdateConfig) ([]byte, error) { return nil, nil }

func (c *careful) Update(ctx context.Context, u sandbox.UpdateConfig) ([]byte, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(u.CA)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	get := func(url string, limit int64) ([]byte, error) {
		if !strings.HasPrefix(url, "https://") {
			return nil, errors.New("not https")
		}
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err == nil && (resp.StatusCode != 200 || int64(len(b)) > limit || (resp.ContentLength >= 0 && int64(len(b)) != resp.ContentLength)) {
			err = errors.New("bad response")
		}
		return b, err
	}
	b, err := get(u.Channel, 64<<10)
	var env envelope
	var m manifest
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		err = dec.Decode(&env)
	}
	if err == nil && (env.PayloadType != payloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != keyID(u.Key) ||
		!ed25519.Verify(u.Key, pae(env.Payload), env.Signatures[0].Sig)) {
		err = errors.New("bad signature")
	}
	if err == nil {
		err = json.Unmarshal(env.Payload, &m)
	}
	now := time.Now().Unix()
	if err == nil && (m.Serial < c.serial || m.Serial > now+day || m.Expires > m.Serial+14*day || m.Expires <= now) {
		err = errors.New("bad serial or expiry")
	}
	if err != nil {
		return c.installed, nil // a refusal: the install stands
	}
	c.serial = m.Serial
	p := m.Pins[u.Name][runtime.GOARCH]
	if p.Version != u.Version || len(p.SHA256) != 64 || strings.ToLower(p.SHA256) != p.SHA256 {
		return c.installed, nil
	}
	art, err := get(p.URL, 1<<20)
	if sum := sha256.Sum256(art); err == nil && hex.EncodeToString(sum[:]) == p.SHA256 {
		c.installed = art
	}
	return c.installed, nil
}

func TestUpdateJudgesOnClients(t *testing.T) {
	variants := []string{"wrong-key", "corrupt-signature", "expired", "lower-serial", "serial-ahead", "oversized", "digest-mismatch", "truncated", "redirected", "plain-http"}
	for _, v := range variants {
		pass, detail, err := updateJudge(v)(context.Background(), Session{Observe: &careful{}})
		if err != nil || !pass {
			t.Errorf("%s: a careful client = pass %v, %q, err %v; want a pass", v, pass, detail, err)
		}
		pass, detail, err = updateJudge(v)(context.Background(), Session{Observe: idle{}})
		if err == nil || pass {
			t.Errorf("%s: a client that installs nothing = pass %v, %q, err %v; want an error", v, pass, detail, err)
		}
	}
	if _, _, err := updateJudge("no-such")(context.Background(), Session{Observe: &careful{}}); err == nil {
		t.Error("an unknown variant judged without error")
	}
}
