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

// StdinWindow is how many Stdin frames the host may have sent that the init has not yet
// acknowledged. The init queues twice as many, so for a host that keeps to the window
// its queue never fills and nothing is dropped. A Stdin frame holds at most MaxStdin bytes.
const (
	StdinWindow = 32
	MaxStdin    = 64 << 10
)

// Frame types. The host sends the first four; the init sends the rest.
const (
	TypeExec   uint8 = 1 // an Exec: run one command. The init runs one at a time
	TypeStdin  uint8 = 2 // bytes for the command's stdin; an empty payload closes it (pipes only)
	TypeResize uint8 = 3 // a Resize of the command's PTY
	TypeSignal uint8 = 4 // one byte, a Linux signal number, for the command's process group
	TypeStdout uint8 = 5 // bytes the command wrote. With a PTY everything it wrote comes here
	TypeStderr uint8 = 6 // bytes the command wrote to stderr, without a PTY
	TypeExit   uint8 = 7 // an Exit: how the command ended
	TypeAck    uint8 = 8 // four bytes, big-endian: how many bytes of one Stdin frame the init has written to the command
)

// A Pull brings the work tree back. The host sends TypePull, with no payload, while no command
// runs; the init answers with what /workspace holds: one TypeEntry frame per entry, every
// directory before what it holds, then an empty TypeEntry; then the bytes of each regular
// file, in that order and exactly Size each, in TypeData frames; then TypeExit, with Code 0,
// or Err when the walk failed. The host judges every entry before it writes anything (I8),
// so one entry is bounded here and the whole tree there.
const (
	TypePull  uint8 = 9
	TypeEntry uint8 = 10
	TypeData  uint8 = 11
)

// The kinds of an Entry. A socket, FIFO or device is never sent.
const (
	KindDir uint8 = 1 + iota
	KindFile
	KindLink
)

// Bounds on a work tree the host takes.
const (
	MaxPath    = 4096     // bytes of one path or link target
	MaxEntries = 1 << 20  // entries in one tree
	MaxNames   = 64 << 20 // bytes of every path and target together
)

// Entry is one member of a work tree: its path relative to the workspace, with / between the
// components; for a file, whether it is executable and how many bytes follow in the data;
// for a link, its target as it is. Nothing in it is trusted: the host judges the path.
type Entry struct {
	Kind   uint8
	Exec   bool
	Size   int64
	Path   string
	Target string
}

// MaxErr bounds Exit.Err on the wire.
const MaxErr = 256

// Exec asks the init to run one command. Argv[0] is looked up in the PATH of Env when it
// holds no slash. With PTY the command gets a controlling terminal of Rows by Cols and
// its output arrives as TypeStdout; otherwise it gets three pipes. CA, when set, is the
// session's CA certificate in PEM, at most MaxCA bytes, which the init puts in the guest's
// trust stores (WriteTrust) before the command runs; Env then names them (TrustEnv).
type Exec struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env,omitempty"`
	Dir  string   `json:"dir,omitempty"`
	PTY  bool     `json:"pty,omitempty"`
	Rows uint16   `json:"rows,omitempty"`
	Cols uint16   `json:"cols,omitempty"`
	CA   []byte   `json:"ca,omitempty"`
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
	if len(e.CA) > MaxCA {
		return Exec{}, fmt.Errorf("exec request: %d bytes of CA, limit %d", len(e.CA), MaxCA)
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

// EncodeEntry is the payload of a TypeEntry frame: the kind, the executable bit, the size
// in 8 bytes, then the path and the target, each with its length in 2 bytes before it.
func EncodeEntry(e Entry) []byte {
	b := []byte{e.Kind, 0}
	if e.Exec {
		b[1] = 1
	}
	b = binary.BigEndian.AppendUint64(b, uint64(e.Size))
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Path)))
	b = append(b, e.Path...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Target)))
	return append(b, e.Target...)
}

// DecodeEntry reads an Entry. It accepts exactly what EncodeEntry writes of an entry with a
// known kind, a path of 1 to MaxPath bytes, a size and an executable bit for a file alone,
// and a target of at most MaxPath bytes for a link alone.
func DecodeEntry(b []byte) (Entry, error) {
	bad := fmt.Errorf("entry: payload %.16x is not a tree entry", b)
	if len(b) < 12 {
		return Entry{}, bad
	}
	e := Entry{Kind: b[0], Exec: b[1] == 1, Size: int64(binary.BigEndian.Uint64(b[2:]))}
	n := int(binary.BigEndian.Uint16(b[10:]))
	if n == 0 || n > MaxPath || len(b) < 14+n {
		return Entry{}, bad
	}
	e.Path = string(b[12 : 12+n])
	t := int(binary.BigEndian.Uint16(b[12+n:]))
	if t > MaxPath || len(b) != 14+n+t || b[1] > 1 || e.Size < 0 {
		return Entry{}, bad
	}
	e.Target = string(b[14+n:])
	switch {
	case e.Kind == KindFile && t == 0, e.Kind == KindLink && !e.Exec && e.Size == 0, e.Kind == KindDir && !e.Exec && e.Size == 0 && t == 0:
		return e, nil
	}
	return Entry{}, bad
}

// EncodeAck is the payload of a TypeAck frame: the length of the Stdin frame that was written.
func EncodeAck(n int) []byte { return binary.BigEndian.AppendUint32(nil, uint32(n)) }

// DecodeAck reads the length of an acknowledged Stdin frame: four bytes, at most MaxStdin.
func DecodeAck(b []byte) (int, error) {
	if len(b) != 4 || binary.BigEndian.Uint32(b) > MaxStdin {
		return 0, fmt.Errorf("ack: payload %.8x is not a length up to %d", b, MaxStdin)
	}
	return int(binary.BigEndian.Uint32(b)), nil
}
