// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package wire frames messages on the host-guest channel. The guest is hostile (A1), so
// every frame has a hard size limit, checked before anything is allocated, and a hard
// time limit, enforced by the stream's own deadlines (I12).
//
// A frame is a 6-byte header, then the payload:
//
//	byte 0     version, always Version
//	byte 1     type, which the caller interprets
//	bytes 2-5  payload length, big-endian, at most MaxPayload
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// Version is the only protocol version this package reads or writes.
	Version = 1
	// MaxPayload is the hard limit on the payload of one frame, in bytes.
	MaxPayload = 64 << 10
	headerLen  = 6
)

var (
	// ErrVersion means a frame carried a version other than Version.
	ErrVersion = errors.New("wire: unsupported version")
	// ErrTooLarge means a frame declared a payload longer than MaxPayload.
	ErrTooLarge = errors.New("wire: frame too large")
)

// Stream is the channel to the guest. net.Conn and a pollable *os.File satisfy it.
type Stream interface {
	io.ReadWriter
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Frame is one message.
type Frame struct {
	Type    uint8
	Payload []byte
}

// Conn reads and writes frames on a Stream. One goroutine may read while another writes.
// After any error a direction is unusable: every later call in it returns the same error,
// so the stream is never resynchronised on bytes the guest chose.
type Conn struct {
	s          Stream
	limit      time.Duration
	rerr, werr error
}

// New returns a Conn on s in which every frame must be read or written within limit.
func New(s Stream, limit time.Duration) *Conn {
	if limit <= 0 {
		panic("wire: the time limit must be positive")
	}
	return &Conn{s: s, limit: limit}
}

// ReadFrame returns the next frame. It waits without limit for a frame to begin, so an idle
// peer is not an error; once the first byte arrives the whole frame must follow within the
// limit. It returns io.EOF only if the stream ends cleanly between frames.
func (c *Conn) ReadFrame() (Frame, error) {
	if c.rerr != nil {
		return Frame{}, c.rerr
	}
	f, err := c.readFrame()
	if err != nil {
		c.rerr = err
	}
	return f, err
}

func (c *Conn) readFrame() (Frame, error) {
	var h [headerLen]byte
	if err := c.s.SetReadDeadline(time.Time{}); err != nil {
		return Frame{}, fmt.Errorf("wire: clear read deadline: %w", err)
	}
	if _, err := io.ReadFull(c.s, h[:1]); err != nil {
		if err == io.EOF {
			return Frame{}, io.EOF
		}
		return Frame{}, fmt.Errorf("wire: read header: %w", err)
	}
	if h[0] != Version {
		return Frame{}, fmt.Errorf("%w: got %d, want %d", ErrVersion, h[0], Version)
	}
	if err := c.s.SetReadDeadline(time.Now().Add(c.limit)); err != nil {
		return Frame{}, fmt.Errorf("wire: set read deadline: %w", err)
	}
	if _, err := io.ReadFull(c.s, h[1:]); err != nil {
		return Frame{}, fmt.Errorf("wire: read header: %w", unexpected(err))
	}
	n := binary.BigEndian.Uint32(h[2:])
	if n > MaxPayload {
		return Frame{}, fmt.Errorf("%w: %d bytes declared, limit %d", ErrTooLarge, n, MaxPayload)
	}
	f := Frame{Type: h[1], Payload: make([]byte, n)}
	if _, err := io.ReadFull(c.s, f.Payload); err != nil {
		return Frame{}, fmt.Errorf("wire: read %d-byte payload: %w", n, unexpected(err))
	}
	return f, nil
}

// unexpected reports the end of the stream inside a frame as a truncation.
func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// WriteFrame writes f within the limit, in one Write. A payload over MaxPayload is
// refused before anything is written, and leaves the Conn usable.
func (c *Conn) WriteFrame(f Frame) error {
	if c.werr != nil {
		return c.werr
	}
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("%w: %d bytes to write, limit %d", ErrTooLarge, len(f.Payload), MaxPayload)
	}
	b := make([]byte, headerLen+len(f.Payload))
	b[0], b[1] = Version, f.Type
	binary.BigEndian.PutUint32(b[2:], uint32(len(f.Payload)))
	copy(b[headerLen:], f.Payload)
	err := c.s.SetWriteDeadline(time.Now().Add(c.limit))
	if err != nil {
		err = fmt.Errorf("wire: set write deadline: %w", err)
	} else if n, werr := c.s.Write(b); werr != nil {
		err = fmt.Errorf("wire: write frame: %w", werr)
	} else if n != len(b) {
		err = fmt.Errorf("wire: write frame: %w", io.ErrShortWrite)
	}
	c.werr = err
	return err
}
