// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package audit is the one record of a session (I9): every connection attempt, every use of a
// secret and every step of the session's life, one JSON object per line in audit.log in the
// session directory. Each line is bound to the ones before it by a SHA-256 chain, and after each
// line the head of the chain is signed with a key that is not in the file, into audit.seal, so
// that Verify finds a line that was changed, dropped, repeated, moved or cut off. The guest never
// touches either file, and none of its bytes is copied into a record whole: a field is clipped
// to a host name's length and JSON escapes it, so it cannot make a second line.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// LogName and SealName are the two files of a session's record.
	LogName  = "audit.log"
	SealName = "audit.seal"

	// SoftLimit is where connection records stop (I10): the guest can attempt connections for as
	// long as the session lives. Records that must not be lost go on until HardLimit.
	SoftLimit = 8 << 20
	HardLimit = 16 << 20

	maxField = 253 // the longest DNS name
)

// The events a record can be of.
const (
	Connect      = "connect" // Result: Allowed, or the reason the attempt was refused
	Allowed      = "allowed"
	Secret       = "secret" // Name, Host, Header and Result of one lookup; never the value
	SessionStart = "session_start"
	SessionEnd   = "session_end"
	LogFull      = "log_full" // the last connection record the log has room for
)

// ErrFull is what a record that does not fit gets back.
var ErrFull = errors.New("audit: the log is full")

// ErrClosed is what a record gets back once the log is closed or has failed to write.
var ErrClosed = errors.New("audit: the log is closed")

// Record is one line. The log sets Time; the caller sets the rest.
type Record struct {
	Time   string `json:"time"`
	Event  string `json:"event"`
	Host   string `json:"host,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Name   string `json:"name,omitempty"`
	Header string `json:"header,omitempty"`
	Result string `json:"result,omitempty"`
}

// Log appends records to one session's audit.log and keeps audit.seal current. A nil *Log takes
// no connection records and fails every durable one, so a secret is never released without it.
type Log struct {
	mu         sync.Mutex
	log, seal  *os.File
	key        ed25519.PrivateKey
	now        func() time.Time
	head       [sha256.Size]byte
	n          uint64
	size       int64
	soft, hard int64
	full       bool
	failed     error
}

// Create makes the session's log and seal in dir, which must hold neither, signed with key.
func Create(dir string, key ed25519.PrivateKey, now func() time.Time) (*Log, error) {
	log, err := os.OpenFile(filepath.Join(dir, LogName), os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	seal, err := os.OpenFile(filepath.Join(dir, SealName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		log.Close()
		return nil, err
	}
	l := &Log{log: log, seal: seal, key: key, now: now, soft: SoftLimit, hard: HardLimit}
	if err := l.sign(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Note appends r without waiting for the disk, and stops at SoftLimit with one log_full record.
func (l *Log) Note(r Record) error {
	if l == nil {
		return ErrClosed
	}
	return l.append(r, false)
}

// Record appends r and returns once it is on the disk, or says why not. A caller that must not act
// without a record, such as the broker releasing a secret, acts only on a nil result.
func (l *Log) Record(r Record) error {
	if l == nil {
		return ErrClosed
	}
	return l.append(r, true)
}

func (l *Log) append(r Record, durable bool) error {
	r.Time = l.now().UTC().Format(time.RFC3339Nano)
	for _, f := range []*string{&r.Event, &r.Host, &r.Name, &r.Header, &r.Result} {
		*f = clip(*f)
	}
	line, _ := json.Marshal(r)
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed != nil {
		return l.failed
	}
	limit := l.hard
	if !durable {
		limit = l.soft
	}
	if l.size+int64(len(line)) > limit {
		if l.full {
			return ErrFull
		}
		l.full = true
		marker, _ := json.Marshal(Record{Time: r.Time, Event: LogFull})
		if err := l.write(append(marker, '\n'), true); err != nil {
			return err
		}
		return ErrFull
	}
	return l.write(line, durable)
}

// write adds one whole line to the log and the seal. A failure ends the log: nothing is appended
// after a line that may be partial, so the file never holds a record it cannot account for.
func (l *Log) write(line []byte, durable bool) error {
	_, err := l.log.Write(line)
	if err == nil {
		l.size += int64(len(line))
		l.n++
		l.head = next(l.head, line[:len(line)-1])
		err = l.sign()
	}
	if err == nil && durable {
		err = errors.Join(l.log.Sync(), l.seal.Sync())
	}
	if err != nil {
		l.failed = fmt.Errorf("audit log failed; no further records: %w", err)
		return l.failed
	}
	return nil
}

// sign writes the seal: the number of lines and the head of the chain, signed. It has one length
// whatever the count, so each seal replaces the last in place.
func (l *Log) sign() error {
	text := fmt.Sprintf("%020d %x %x\n", l.n, l.head, ed25519.Sign(l.key, sealed(l.n, l.head)))
	_, err := l.seal.WriteAt([]byte(text), 0)
	return err
}

// Close ends the log; every record after it fails.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed == nil {
		l.failed = ErrClosed
	}
	return errors.Join(l.log.Close(), l.seal.Close())
}

// next is the head of the chain after line: it holds every line before, in order.
func next(head [sha256.Size]byte, line []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write(head[:])
	h.Write(line)
	return [sha256.Size]byte(h.Sum(nil))
}

func sealed(n uint64, head [sha256.Size]byte) []byte {
	return append(binary.BigEndian.AppendUint64([]byte("workcell-audit-seal-v1"), n), head[:]...)
}

func clip(s string) string {
	if len(s) > maxField {
		return s[:maxField]
	}
	return s
}

// Verify reads the log in dir and says whether it is exactly what the log that holds key wrote:
// every line a record, and their number and chain the ones the seal signs. The error says only
// that it is not, and where a line is no record. pub is the public half of the key.
func Verify(dir string, pub ed25519.PublicKey) error {
	f, err := os.Open(filepath.Join(dir, LogName))
	if err != nil {
		return err
	}
	defer f.Close()
	var n uint64
	var head [sha256.Size]byte
	if err := eachLine(f, func(line []byte) error {
		n++
		if _, ok := ParseLine(string(line)); !ok {
			return fmt.Errorf("audit: line %d is not a record", n)
		}
		head = next(head, line)
		return nil
	}); err != nil {
		return err
	}
	text, err := os.ReadFile(filepath.Join(dir, SealName))
	if err != nil {
		return err
	}
	var sealN uint64
	var headHex, sigHex string
	if _, err := fmt.Sscanf(string(text), "%d %s %s", &sealN, &headHex, &sigHex); err != nil {
		return errors.New("audit: the seal is unreadable")
	}
	h, herr := hex.DecodeString(headHex)
	sig, serr := hex.DecodeString(sigHex)
	if herr != nil || serr != nil || len(h) != sha256.Size {
		return errors.New("audit: the seal is unreadable")
	}
	want := [sha256.Size]byte(h)
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, sealed(sealN, want), sig) {
		return errors.New("audit: the seal is not signed with this host's key")
	}
	if sealN != n || want != head {
		return fmt.Errorf("audit: the log holds %d records that do not match the signed seal of %d: it was changed", n, sealN)
	}
	return nil
}

// ParseLine is the strict reader of one line (no newline): one Record and nothing after it.
func ParseLine(line string) (Record, bool) {
	var r Record
	if len(line) > maxLine {
		return r, false
	}
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.InputOffset() != int64(len(line)) {
		return r, false
	}
	_, err := time.Parse(time.RFC3339Nano, r.Time)
	return r, err == nil && r.Event != ""
}

var plainHost = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)

// SafeHost lower-cases a logged host, and gives (invalid) for one outside the DNS name characters:
// a host is guest-chosen bytes (an SNI), and a reader must be able to copy what it prints.
func SafeHost(host string) string {
	if host = strings.ToLower(host); host != "" && !plainHost.MatchString(host) {
		return "(invalid)"
	}
	return host
}
