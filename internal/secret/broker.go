// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: credbroker/server.go

package secret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Broker releases a secret only for the (host, header) pair of its grant, and
// only after the ledger holds a durable record of the release.
type Broker struct {
	grants map[pair]Grant
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
	for _, g := range grants {
		if g.Name == "" || g.Source == "" || g.Host == "" || g.Header == "" {
			return nil, fmt.Errorf("secret %q needs a name, source, host and header", g.Name)
		}
		p := pair{g.Host, g.Header}
		if _, dup := table[p]; dup {
			return nil, fmt.Errorf("secret %q: host %s header %s is granted twice", g.Name, g.Host, g.Header)
		}
		table[p] = g
	}
	return &Broker{grants: table, now: time.Now, log: log}, nil
}

// Lookup returns the value granted for header on host. A denial is recorded
// while the denial window allows; a grant is always recorded, and withheld
// when its record is not durable. The caller owns the value and wipes it
// with Zero.
func (b *Broker) Lookup(ctx context.Context, host, header string) ([]byte, error) {
	// A lookup over the request bound keeps every ledger line readable.
	if len(host)+len(header) > maxLineBytes {
		return nil, b.deny(pair{}, resultMalformed)
	}
	p := pair{host, header}
	if !b.allow(&b.windowStart, &b.count) {
		return nil, b.deny(p, resultRateLimited)
	}
	g, ok := b.grants[p]
	if !ok {
		return nil, b.deny(p, resultNotGranted)
	}
	value, err := Resolve(ctx, g.Source)
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", g.Name, err)
	}
	// The record is the ledger of every release: a value whose record is not
	// durable is withheld, so the ledger never under-reports what left.
	if err := b.record(p, g.Name, resultGranted); err != nil {
		Zero(value)
		return nil, err
	}
	return value, nil
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
