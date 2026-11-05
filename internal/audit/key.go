// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const keyName = "audit.key"

// LoadKey returns the host's signing key from dir, making it on first use: the hex of a 32 byte
// seed, in a file only the user can read. The key signs the seal beside each session's log and
// is never written to a log. Two first uses at once end with the one key that was linked first.
func LoadKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, keyName)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := makeKey(dir, path); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("audit: %s must be a regular file only its owner can use", path)
	}
	text := make([]byte, 2*ed25519.SeedSize+2)
	n, _ := f.Read(text)
	seed, err := hex.DecodeString(string(text[:n]))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("audit: %s does not hold a key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// makeKey writes a new key to a private temporary file and links it to path, which fails if a key
// is there, so a reader never sees half a key.
func makeKey(dir, path string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, keyName+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(hex.EncodeToString(seed))
	if err = errors.Join(err, tmp.Sync(), tmp.Close()); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}
