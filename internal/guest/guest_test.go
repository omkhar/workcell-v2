// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package guest

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestExec(t *testing.T) {
	full := Exec{Argv: []string{"sh", "-c", "exit 7"}, Env: []string{"PATH=/bin"}, Dir: "/w", PTY: true, Rows: 24, Cols: 80}
	tests := []struct {
		name string
		in   []byte
		want Exec
		ok   bool
	}{
		{"round trip", EncodeExec(full), full, true},
		{"argv only", []byte(`{"argv":["ls"]}`), Exec{Argv: []string{"ls"}}, true},
		{"empty argv", []byte(`{"argv":[]}`), Exec{}, false},
		{"no argv", []byte(`{"pty":true}`), Exec{}, false},
		{"not json", []byte(`argv`), Exec{}, false},
		{"empty", nil, Exec{}, false},
		{"rows too big", []byte(`{"argv":["ls"],"rows":65536}`), Exec{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeExec(tc.in)
			if (err == nil) != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DecodeExec(%s) = %+v, %v; want %+v, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestResize(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want Resize
		ok   bool
	}{
		{"round trip", EncodeResize(Resize{Rows: 30, Cols: 100}), Resize{Rows: 30, Cols: 100}, true},
		{"max", []byte{0xff, 0xff, 0xff, 0xff}, Resize{Rows: 65535, Cols: 65535}, true},
		{"zero", []byte{0, 0, 0, 0}, Resize{}, true},
		{"short", []byte{0, 24, 0}, Resize{}, false},
		{"long", []byte{0, 24, 0, 80, 0}, Resize{}, false},
		{"empty", nil, Resize{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeResize(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("DecodeResize(%x) = %+v, %v; want %+v, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestSignal(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
		ok   bool
	}{
		{"term", EncodeSignal(15), 15, true},
		{"one", []byte{1}, 1, true},
		{"sixty-four", []byte{64}, 64, true},
		{"zero", []byte{0}, 0, false},
		{"sixty-five", []byte{65}, 0, false},
		{"two bytes", []byte{15, 0}, 0, false},
		{"empty", nil, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSignal(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("DecodeSignal(%x) = %d, %v; want %d, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestExit(t *testing.T) {
	long := strings.Repeat("e", MaxErr+1)
	tests := []struct {
		name string
		in   []byte
		want Exit
		ok   bool
	}{
		{"code 7", EncodeExit(Exit{Code: 7}), Exit{Code: 7}, true},
		{"code 0", EncodeExit(Exit{}), Exit{}, true},
		{"code 255", []byte{0, 255}, Exit{Code: 255}, true},
		{"signal 15", EncodeExit(Exit{Signal: 15}), Exit{Signal: 15}, true},
		{"signal wins over code", EncodeExit(Exit{Code: 1, Signal: 9}), Exit{Signal: 9}, true},
		{"error", EncodeExit(Exit{Err: "no such file"}), Exit{Err: "no such file"}, true},
		{"error wins", EncodeExit(Exit{Code: 1, Signal: 9, Err: "x"}), Exit{Err: "x"}, true},
		{"error truncated to MaxErr", EncodeExit(Exit{Err: long}), Exit{Err: long[:MaxErr]}, true},
		{"error with control bytes kept", []byte{2, 0x1b, '[', 'm', 0}, Exit{Err: "\x1b[m\x00"}, true},
		{"empty", nil, Exit{}, false},
		{"one byte", []byte{0}, Exit{}, false},
		{"code with a tail", []byte{0, 7, 0}, Exit{}, false},
		{"signal 0", []byte{1, 0}, Exit{}, false},
		{"signal 65", []byte{1, 65}, Exit{}, false},
		{"signal with a tail", []byte{1, 15, 0}, Exit{}, false},
		{"error too long", append([]byte{2}, long...), Exit{}, false},
		{"unknown kind", []byte{3, 0}, Exit{}, false},
		{"kind 255", []byte{255, 0}, Exit{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeExit(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("DecodeExit(%.8x) = %+v, %v; want %+v, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestAck(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
		ok   bool
	}{
		{"zero, the end of a pipe", EncodeAck(0), 0, true},
		{"one byte", EncodeAck(1), 1, true},
		{"a full frame", EncodeAck(MaxStdin), MaxStdin, true},
		{"one over", EncodeAck(MaxStdin + 1), 0, false},
		{"huge", []byte{0xff, 0xff, 0xff, 0xff}, 0, false},
		{"empty", nil, 0, false},
		{"three bytes", []byte{0, 0, 1}, 0, false},
		{"five bytes", []byte{0, 0, 0, 1, 0}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeAck(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Errorf("DecodeAck(%x) = %d, %v; want %d, ok=%t", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

// FuzzDecode runs every decoder on arbitrary bytes. What decodes must be in bounds and
// encode back to the same bytes, so the guest has exactly one way to say each thing.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 7})
	f.Add([]byte{1, 15})
	f.Add([]byte("\x02fork/exec /nope: no such file or directory"))
	f.Add([]byte{0, 24, 0, 80})
	f.Add([]byte{0, 1, 0, 0})
	f.Add([]byte(`{"argv":["sh"],"pty":true,"rows":24,"cols":80}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		if e, err := DecodeExit(in); err == nil {
			if e.Code < 0 || e.Code > 255 || e.Signal < 0 || e.Signal > 64 || len(e.Err) > MaxErr {
				t.Fatalf("exit out of bounds: %+v", e)
			}
			if again := EncodeExit(e); !bytes.Equal(again, in) {
				t.Fatalf("exit %x re-encodes to %x", in, again)
			}
		}
		if r, err := DecodeResize(in); err == nil && !bytes.Equal(EncodeResize(r), in) {
			t.Fatalf("resize %x re-encodes differently", in)
		}
		if s, err := DecodeSignal(in); err == nil && (s < 1 || s > 64 || !bytes.Equal(EncodeSignal(s), in)) {
			t.Fatalf("signal %x decodes to %d", in, s)
		}
		if n, err := DecodeAck(in); err == nil && (n < 0 || n > MaxStdin || !bytes.Equal(EncodeAck(n), in)) {
			t.Fatalf("ack %x decodes to %d", in, n)
		}
		if e, err := DecodeExec(in); err == nil {
			if len(e.Argv) == 0 {
				t.Fatalf("exec without argv from %q", in)
			}
			if _, err := DecodeExec(EncodeExec(e)); err != nil {
				t.Fatalf("exec from %q does not round-trip: %v", in, err)
			}
		}
	})
}
