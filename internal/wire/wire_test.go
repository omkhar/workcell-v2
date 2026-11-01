// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// mem is a Stream over fixed input that ends with io.EOF; it needs no deadlines.
type mem struct {
	*bytes.Reader
	bytes.Buffer
}

func (m *mem) Read(p []byte) (int, error)       { return m.Reader.Read(p) }
func (m *mem) Write(p []byte) (int, error)      { return m.Buffer.Write(p) }
func (m *mem) SetReadDeadline(time.Time) error  { return nil }
func (m *mem) SetWriteDeadline(time.Time) error { return nil }

func newMem(b []byte) *mem { return &mem{Reader: bytes.NewReader(b)} }

// frame builds the raw bytes of a frame with any version and declared length.
func frame(version, typ byte, length uint32, body string) []byte {
	return append([]byte{version, typ, byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}, body...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestReadFrame(t *testing.T) {
	flood := bytes.Repeat(frame(1, 7, 0, ""), 5000)
	big := string(bytes.Repeat([]byte{'x'}, MaxPayload))
	tests := []struct {
		name  string
		in    []byte
		want  int // frames decoded before the error
		err   error
		check func(t *testing.T, fs []Frame)
	}{
		{"empty stream", nil, 0, io.EOF, nil},
		{"one frame", frame(1, 3, 2, "hi"), 1, io.EOF, func(t *testing.T, fs []Frame) {
			if fs[0].Type != 3 || string(fs[0].Payload) != "hi" {
				t.Errorf("got %+v", fs[0])
			}
		}},
		{"unknown type handed up", frame(1, 0xff, 1, "z"), 1, io.EOF, func(t *testing.T, fs []Frame) {
			if fs[0].Type != 0xff || string(fs[0].Payload) != "z" {
				t.Errorf("got %+v", fs[0])
			}
		}},
		{"type zero handed up", frame(1, 0, 0, ""), 1, io.EOF, nil},
		{"zero-length flood", flood, 5000, io.EOF, nil},
		{"exactly MaxPayload", frame(1, 1, MaxPayload, big), 1, io.EOF, nil},
		{"MaxPayload plus one", frame(1, 1, MaxPayload+1, "x"), 0, ErrTooLarge, nil},
		{"length 0xFFFFFFFF", frame(1, 1, 0xffffffff, "abc"), 0, ErrTooLarge, nil},
		{"length 2^31, negative as signed", frame(1, 1, 1<<31, "abc"), 0, ErrTooLarge, nil},
		{"length 2^63 as 8 bytes", []byte{1, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 'a'}, 0, ErrTooLarge, nil},
		{"length one short of body", frame(1, 1, 2, "abc"), 1, ErrVersion, nil},
		{"length one long of body", frame(1, 1, 4, "abc"), 0, io.ErrUnexpectedEOF, nil},
		{"truncated header", []byte{1, 1, 0}, 0, io.ErrUnexpectedEOF, nil},
		{"version only", []byte{1}, 0, io.ErrUnexpectedEOF, nil},
		{"version 0", frame(0, 1, 0, ""), 0, ErrVersion, nil},
		{"version 2", frame(2, 1, 0, ""), 0, ErrVersion, nil},
		{"version 255", frame(255, 1, 0, ""), 0, ErrVersion, nil},
		{"mixed versions", cat(frame(1, 1, 1, "a"), frame(2, 1, 1, "b"), frame(1, 1, 1, "c")), 1, ErrVersion, nil},
		{"no resync after a bad frame", cat(frame(1, 1, 1<<20, ""), frame(1, 1, 0, "")), 0, ErrTooLarge, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(newMem(tt.in), time.Second)
			var fs []Frame
			var err error
			for {
				var f Frame
				if f, err = c.ReadFrame(); err != nil {
					break
				}
				fs = append(fs, f)
			}
			if len(fs) != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("got %d frames and %v, want %d and %v", len(fs), err, tt.want, tt.err)
			}
			if _, again := c.ReadFrame(); again != err {
				t.Errorf("after %v the next read returned %v", err, again)
			}
			if tt.check != nil {
				tt.check(t, fs)
			}
		})
	}
}

func TestWriteFrame(t *testing.T) {
	tests := []struct {
		name string
		f    Frame
		want []byte
		err  error
	}{
		{"empty", Frame{Type: 9}, frame(1, 9, 0, ""), nil},
		{"payload", Frame{Type: 2, Payload: []byte("abc")}, frame(1, 2, 3, "abc"), nil},
		{"too large", Frame{Type: 2, Payload: make([]byte, MaxPayload+1)}, nil, ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMem(nil)
			c := New(m, time.Second)
			if err := c.WriteFrame(tt.f); !errors.Is(err, tt.err) {
				t.Fatalf("got %v, want %v", err, tt.err)
			}
			if !bytes.Equal(m.Buffer.Bytes(), tt.want) {
				t.Errorf("wrote % x, want % x", m.Buffer.Bytes(), tt.want)
			}
			if err := c.WriteFrame(Frame{Type: 1}); err != nil {
				t.Errorf("the next write failed: %v", err)
			}
			got, err := New(newMem(m.Buffer.Bytes()), time.Second).ReadFrame()
			if want := len(tt.f.Payload); tt.err == nil && (err != nil || got.Type != tt.f.Type || len(got.Payload) != want) {
				t.Errorf("read back %+v, %v", got, err)
			}
		})
	}
}

// TestTimeLimits runs a hostile peer on the far end of a pipe and checks that every
// operation ends, with the stated error, well before the test times out.
func TestTimeLimits(t *testing.T) {
	const limit = 50 * time.Millisecond
	drip := func(b []byte, gap time.Duration) func(net.Conn) {
		return func(p net.Conn) {
			for i := range b {
				if _, err := p.Write(b[i : i+1]); err != nil {
					return
				}
				time.Sleep(gap)
			}
		}
	}
	tests := []struct {
		name  string
		peer  func(net.Conn) // runs on the far end; the pipe stays open until the test ends
		write bool           // test WriteFrame rather than ReadFrame
		err   error
	}{
		{"header then no body", drip(frame(1, 1, 10, ""), 0), false, os.ErrDeadlineExceeded},
		{"truncated header held open", drip([]byte{1, 1, 0}, 0), false, os.ErrDeadlineExceeded},
		{"huge length then idle", drip(frame(1, 1, 0xffffffff, "ab"), 0), false, ErrTooLarge},
		{"slow drip", drip(frame(1, 1, 0, ""), limit/3), false, os.ErrDeadlineExceeded},
		{"reset mid-frame", func(p net.Conn) { drip(frame(1, 1, 5, "ab"), 0)(p); p.Close() }, false, io.ErrUnexpectedEOF},
		{"idle peer then close", func(p net.Conn) { time.Sleep(3 * limit); p.Close() }, false, io.EOF},
		{"peer refuses to read", func(net.Conn) {}, true, os.ErrDeadlineExceeded},
		{"peer reads part then stops", func(p net.Conn) { io.ReadFull(p, make([]byte, 3)) }, true, os.ErrDeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			near, far := net.Pipe()
			defer near.Close()
			defer far.Close()
			go tt.peer(far)
			c := New(near, limit)
			op := func() error { _, err := c.ReadFrame(); return err }
			if tt.write {
				op = func() error { return c.WriteFrame(Frame{Type: 1, Payload: []byte("payload")}) }
			}
			start := time.Now()
			err := op()
			if !errors.Is(err, tt.err) {
				t.Fatalf("got %v, want %v", err, tt.err)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("took %v", d)
			}
			if again := op(); again != err {
				t.Errorf("after %v the next call returned %v", err, again)
			}
		})
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(frame(1, 3, 2, "hi"))
	f.Add(cat(frame(1, 0, 0, ""), frame(1, 255, 1, "x"), frame(2, 1, 0, "")))
	f.Add(frame(1, 1, 0xffffffff, "abc"))
	f.Add([]byte{1, 1, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		c := New(newMem(in), time.Second)
		var again []byte
		var err error
		for {
			var fr Frame
			if fr, err = c.ReadFrame(); err != nil {
				break
			}
			if len(fr.Payload) > MaxPayload {
				t.Fatalf("payload of %d bytes", len(fr.Payload))
			}
			again = append(again, frame(Version, fr.Type, uint32(len(fr.Payload)), string(fr.Payload))...)
		}
		if !bytes.HasPrefix(in, again) {
			t.Fatalf("decoded frames do not re-encode to a prefix of the input")
		}
		if err == io.EOF && len(again) != len(in) {
			t.Fatalf("clean EOF after %d of %d bytes", len(again), len(in))
		}
		if _, e := c.ReadFrame(); e != err {
			t.Fatalf("after %v the next read returned %v", err, e)
		}
	})
}
