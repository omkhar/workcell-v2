// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: credbroker/server.go

package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	rateLimit  = 300
	rateWindow = time.Minute
)

// Grant is one [[secret]] row: the secret Name, read from Source, may be sent
// only in Header to Host.
type Grant struct {
	Name, Source, Host, Header string
}

// Ledger receives one JSON line per lookup and makes it durable on Sync. A
// value is released only after its record is durable, so a writer that cannot
// sync is not a ledger.
type Ledger interface {
	io.Writer
	Sync() error
}

type pair struct{ host, header string }

// tokens is what a grant whose source is a sign-in flow holds: the tokens
// its endpoint issued last, none before a sign-in. They live here alone,
// and a replaced one is zeroed.
type tokens struct{ access, refresh []byte }

// Broker releases a secret only for the (host, header) pair of its grant, and
// only after the ledger holds a durable record of the release.
type Broker struct {
	grants map[pair]Grant
	tokens map[pair]*tokens // the grants whose source is a sign-in flow
	now    func() time.Time

	mu          sync.Mutex
	log         Ledger
	windowStart time.Time
	count       int
	// Denials have their own window so they can neither spend the grant
	// quota beyond their own lookups nor fill the ledger.
	rejectStart time.Time
	rejected    int
	logFailed   error
}

// NewBroker builds a broker from the session's [[secret]] rows. Each field
// of a row is required, and no two rows share a (host, header) pair.
func NewBroker(grants []Grant, log Ledger) (*Broker, error) {
	if log == nil {
		return nil, errors.New("secret ledger is required")
	}
	table := make(map[pair]Grant, len(grants))
	held := map[pair]*tokens{}
	for _, g := range grants {
		if g.Name == "" || g.Source == "" || g.Host == "" || g.Header == "" {
			return nil, fmt.Errorf("secret %q needs a name, source, host and header", g.Name)
		}
		p := pair{g.Host, g.Header}
		if _, dup := table[p]; dup {
			return nil, fmt.Errorf("secret %q: host %s header %s is granted twice", g.Name, g.Host, g.Header)
		}
		table[p] = g
		if strings.HasPrefix(g.Source, "signin:") {
			held[p] = &tokens{}
		}
	}
	return &Broker{grants: table, tokens: held, now: time.Now, log: log}, nil
}

// Lookup returns the value granted for header on host: its source read now,
// or the access token its sign-in flow holds. A denial is recorded while
// the denial window allows; a grant is always recorded, and withheld when
// its record is not durable. The caller owns the value and wipes it with
// Zero.
func (b *Broker) Lookup(ctx context.Context, host, header string) ([]byte, error) {
	return b.release(ctx, host, header, false)
}

// Refresh returns the refresh token the sign-in flow granted for header on
// host holds, for the token endpoint alone, recorded as Lookup records a
// release. The caller owns the value and wipes it with Zero.
func (b *Broker) Refresh(ctx context.Context, host, header string) ([]byte, error) {
	return b.release(ctx, host, header, true)
}

func (b *Broker) release(ctx context.Context, host, header string, refresh bool) ([]byte, error) {
	// A lookup over the request bound keeps every ledger line readable.
	if len(host)+len(header) > maxLineBytes {
		return nil, b.deny(pair{}, resultMalformed)
	}
	p := pair{host, header}
	if !b.allow(&b.windowStart, &b.count) {
		return nil, b.deny(p, resultRateLimited)
	}
	g, ok := b.grants[p]
	t := b.tokens[p]
	if !ok || refresh && t == nil {
		return nil, b.deny(p, resultNotGranted)
	}
	var value []byte
	result := resultGranted
	if t != nil {
		if value = b.held(t, refresh); value == nil {
			return nil, b.deny(p, resultNotSignedIn)
		}
		if refresh {
			result = resultRefreshGranted
		}
	} else if v, err := Resolve(ctx, g.Source); err != nil {
		return nil, fmt.Errorf("secret %s: %w", g.Name, err)
	} else {
		value = v
	}
	// The record is the ledger of every release: a value whose record is not
	// durable is withheld, so the ledger never under-reports what left.
	if err := b.record(p, g.Name, result); err != nil {
		Zero(value)
		return nil, err
	}
	return value, nil
}

// held returns a copy of the access or the refresh token t holds, nil for none.
func (b *Broker) held(t *tokens, refresh bool) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := t.access
	if refresh {
		v = t.refresh
	}
	if len(v) == 0 {
		return nil
	}
	return bytes.Clone(v)
}

// Issue takes the tokens the sign-in flow granted for header on host was
// issued, which the broker owns from here: each replaces the one held, which
// is zeroed, and an empty one leaves the one held in place. The sign-in, or
// the refresh when tokens were held, is recorded; one whose record is not
// durable is refused, and from then on nothing is released.
func (b *Broker) Issue(host, header string, access, refresh []byte) error {
	p := pair{host, header}
	g, ok := b.grants[p]
	t := b.tokens[p]
	if !ok || t == nil {
		Zero(access)
		Zero(refresh)
		return b.deny(p, resultNotGranted)
	}
	b.mu.Lock()
	result := resultRefreshed
	if t.access == nil && t.refresh == nil {
		result = resultSignedIn
	}
	if len(access) > 0 {
		Zero(t.access)
		t.access = access
	}
	if len(refresh) > 0 {
		Zero(t.refresh)
		t.refresh = refresh
	}
	b.mu.Unlock()
	return b.record(p, g.Name, result)
}

// Tokens returns copies of the access and the refresh token the sign-in
// flow granted for header on host holds, nil for one it does not. Nothing
// is released: the caller hides them, and wipes the copies with Zero.
func (b *Broker) Tokens(host, header string) (access, refresh []byte) {
	t := b.tokens[pair{host, header}]
	if t == nil {
		return nil, nil
	}
	return b.held(t, false), b.held(t, true)
}

func (b *Broker) deny(p pair, result string) error {
	if b.allow(&b.rejectStart, &b.rejected) {
		_ = b.record(p, "", result)
	}
	return fmt.Errorf("secret broker: %s", result)
}

// allow is a fixed window: at most rateLimit calls per rateWindow.
func (b *Broker) allow(start *time.Time, count *int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.Sub(*start) >= rateWindow {
		*start, *count = now, 0
	}
	if *count >= rateLimit {
		return false
	}
	*count++
	return true
}

// record appends one line and makes it durable before it returns, so a
// caller can withhold a value whose record did not reach the ledger.
func (b *Broker) record(p pair, name, result string) error {
	line, _ := json.Marshal(ledgerRecord{
		Time:       b.now().UTC().Format(time.RFC3339Nano),
		Host:       p.host,
		Header:     p.header,
		Credential: name,
		Result:     result,
	})
	line = append(line, '\n')
	b.mu.Lock()
	defer b.mu.Unlock()
	// A failed write or sync may have left a partial record; nothing is
	// appended after it, so the ledger never carries a release it cannot
	// account for, and nothing is granted from then on.
	if b.logFailed != nil {
		return b.logFailed
	}
	n, err := b.log.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = b.log.Sync()
	}
	if err != nil {
		b.logFailed = fmt.Errorf("secret ledger failed; no further grants: %w", err)
		return b.logFailed
	}
	return nil
}
