// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package guest is the vocabulary of the host-guest channel: the frame types and payloads
// with which the host drives cmd/workcell-init and the init answers. The framing itself is
// internal/wire. The guest is hostile (A1), so what the host decodes from it, the Exit
// payload, is checked byte by byte and can never be longer than one wire frame (I12);
// output frames are bytes the host passes on, never parses.
package guest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Port is the vsock port the init dials on the host.
const Port = 5000

// Frame types. The host sends the first four; the init sends the rest.
const (
	TypeExec   uint8 = 1 // an Exec: run one command. The init runs one at a time
	TypeStdin  uint8 = 2 // bytes for the command's stdin; an empty payload closes it (pipes only)
	TypeResize uint8 = 3 // a Resize of the command's PTY
	TypeSignal uint8 = 4 // one byte, a Linux signal number, for the command's process group
	TypeStdout uint8 = 5 // bytes the command wrote. With a PTY everything it wrote comes here
	TypeStderr uint8 = 6 // bytes the command wrote to stderr, without a PTY
	TypeExit   uint8 = 7 // an Exit: how the command ended
)

// MaxErr bounds Exit.Err on the wire.
const MaxErr = 256

// Exec asks the init to run one command. Argv[0] is looked up in the PATH of Env when it
// holds no slash. With PTY the command gets a controlling terminal of Rows by Cols and
// its output arrives as TypeStdout; otherwise it gets three pipes.
type Exec struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
	PTY  bool     `json:"pty,omitempty"`
	Rows uint16   `json:"rows,omitempty"`
	Cols uint16   `json:"cols,omitempty"`
}

// Resize is a new window size for the command's PTY.
type Resize struct{ Rows, Cols uint16 }

// Exit says how a command ended. Exactly one of the three holds: Err is set when the
// command never ran, Signal when a signal ended it, else Code is its exit status.
// Err is text the guest chose: print it quoted.
type Exit struct {
	Code   int
	Signal int
	Err    string
}

const (
	exitCode   = 0
	exitSignal = 1
	exitErr    = 2
)

// EncodeExec is the payload of a TypeExec frame.
func EncodeExec(e Exec) []byte {
	b, _ := json.Marshal(e) // strings, bools and integers cannot fail to marshal
	return b
}

// DecodeExec reads an Exec and requires a command.
func DecodeExec(b []byte) (Exec, error) {
	var e Exec
	if err := json.Unmarshal(b, &e); err != nil {
		return Exec{}, fmt.Errorf("exec request: %w", err)
	}
	if len(e.Argv) == 0 {
		return Exec{}, errors.New("exec request: empty argv")
	}
	return e, nil
}

// EncodeResize is the payload of a TypeResize frame: rows then cols, big-endian.
func EncodeResize(r Resize) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, r.Rows), r.Cols)
}

// DecodeResize reads a Resize.
func DecodeResize(b []byte) (Resize, error) {
	if len(b) != 4 {
		return Resize{}, fmt.Errorf("resize: %d bytes, want 4", len(b))
	}
	return Resize{Rows: binary.BigEndian.Uint16(b), Cols: binary.BigEndian.Uint16(b[2:])}, nil
}

// EncodeSignal is the payload of a TypeSignal frame.
func EncodeSignal(sig int) []byte { return []byte{byte(sig)} }

// DecodeSignal reads a signal number, 1 to 64.
func DecodeSignal(b []byte) (int, error) {
	if len(b) != 1 || b[0] == 0 || b[0] > 64 {
		return 0, fmt.Errorf("signal: payload %x is not one byte from 1 to 64", b)
	}
	return int(b[0]), nil
}

// EncodeExit is the payload of a TypeExit frame: a kind byte, then the exit status, the
// signal number, or up to MaxErr bytes of Err.
func EncodeExit(e Exit) []byte {
	switch {
	case e.Err != "":
		return append([]byte{exitErr}, e.Err[:min(len(e.Err), MaxErr)]...)
	case e.Signal != 0:
		return []byte{exitSignal, byte(e.Signal)}
	default:
		return []byte{exitCode, byte(e.Code)}
	}
}

// DecodeExit reads an Exit. It accepts exactly what EncodeExit writes.
func DecodeExit(b []byte) (Exit, error) {
	bad := fmt.Errorf("exit: payload %.8x is not an exit status", b)
	if len(b) < 2 {
		return Exit{}, bad
	}
	switch b[0] {
	case exitCode:
		if len(b) == 2 {
			return Exit{Code: int(b[1])}, nil
		}
	case exitSignal:
		if len(b) == 2 && b[1] >= 1 && b[1] <= 64 {
			return Exit{Signal: int(b[1])}, nil
		}
	case exitErr:
		if len(b) <= 1+MaxErr {
			return Exit{Err: string(b[1:])}, nil
		}
	}
	return Exit{}, bad
}
