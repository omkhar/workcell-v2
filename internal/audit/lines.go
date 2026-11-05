// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: auditlog/read.go

package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// maxLine bounds one physical line, newline excluded. A record holds at most five fields of 253
// bytes, and JSON escaping grows a byte to at most 6.
const maxLine = 16 << 10

// MaxBytes bounds the log one operation reads: both limits of the writer, and the marker.
const MaxBytes = HardLimit + 2*maxLine

var errUnterminated = errors.New("audit: the last line has no newline: the log was cut inside a record")

// splitLF splits at "\n" and nothing else, so a "\r" or a space stays in the line and in its digest,
// and a last line with no newline is an error rather than a record.
func splitLF(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return 0, nil, errUnterminated
	}
	return 0, nil, nil
}

// eachLine streams r to fn, one line at a time and without its newline. It refuses a line over
// maxLine and a stream over MaxBytes. fn must not keep the slice.
func eachLine(r io.Reader, fn func(line []byte) error) error {
	limited := &io.LimitedReader{R: r, N: MaxBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 4<<10), maxLine+1) // a line of maxLine bytes plus its newline
	sc.Split(splitLF)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if limited.N <= 0 {
		return fmt.Errorf("audit: the log exceeds %d bytes", MaxBytes)
	}
	return nil
}
