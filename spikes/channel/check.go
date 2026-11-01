// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package channel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errTooBig = errors.New("manifest larger than the cap")

// Checker is the client side of B9. Dir holds three small files: the time of
// the last check, the last serial seen, and the last manifest that verified.
type Checker struct {
	URL     string
	Client  *http.Client
	Dir     string
	Keys    []Key
	Timeout time.Duration
}

func (c *Checker) readUint(name string) uint64 {
	b, _ := os.ReadFile(filepath.Join(c.Dir, name))
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (c *Checker) write(name string, b []byte) error {
	tmp := filepath.Join(c.Dir, name+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.Dir, name))
}

// Start never blocks on the network. It returns the stored manifest if it still
// verifies at now (nil otherwise: the caller keeps what it has installed), and,
// at most once a day, starts a background check whose outcome arrives on done.
// When no check is due, done is nil.
func (c *Checker) Start(now time.Time) (m *Manifest, done <-chan error) {
	serial := c.readUint("serial")
	if raw, err := os.ReadFile(filepath.Join(c.Dir, "manifest")); err == nil {
		m, _ = Verify(raw, c.Keys, now, serial)
	}
	if last := c.readUint("checked"); now.Before(time.Unix(int64(last), 0).Add(24*time.Hour)) && last != 0 {
		return m, nil
	}
	// Stamp first: a hung or failing server costs one attempt a day, not one per start.
	if err := c.write("checked", []byte(strconv.FormatInt(now.Unix(), 10))); err != nil {
		return m, nil
	}
	ch := make(chan error, 1)
	go func() { ch <- c.check(now, serial) }()
	return m, ch
}

func (c *Checker) check(now time.Time, serial uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxManifestBytes {
		return errTooBig
	}
	m, err := Verify(raw, c.Keys, now, serial)
	if err != nil {
		return err
	}
	// The new manifest is applied at the next start (B9). Serial last, so a crash
	// in between leaves a manifest the next start still accepts.
	if err := c.write("manifest", raw); err != nil {
		return err
	}
	return c.write("serial", []byte(strconv.FormatUint(m.Serial, 10)))
}
