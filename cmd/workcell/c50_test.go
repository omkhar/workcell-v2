// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"testing"
	"time"
)

// TestRunEndsWithAStoppedReader reproduces C50 (S-1002, sweep 2; I9, I7; C3's sibling), fixed by S-F33: the stdout reader takes nothing (`workcell run -- cmd | sleep 1000`), the command writes more than the pipe holds and exits. The seat drops the client and the Exit reaches done; session's done arm, end, must return at once. Before the fix it waited on a client parked in os.Stdout.Write, which theirs.Close() cannot wake.
func TestRunEndsWithAStoppedReader(t *testing.T) {
	saved, s := must(unix.Dup(unix.Stdout)), &seat{window: make(chan struct{}, guest.StdinWindow), in: make(chan wire.Frame, 4)}
	r, w, err := os.Pipe()                       // fd 1 becomes this pipe, whose reader is alive and reads nothing
	must(0, unix.Dup2(int(w.Fd()), unix.Stdout)) // a failed Pipe fails here too: a nil file has no descriptor
	back := func() { unix.Dup2(saved, unix.Stdout); unix.Close(saved); w.Close(); r.Close() }
	fail := func(why string, a ...any) { back(); t.Fatalf(why, a...) } // a report needs fd 1 back, and os.Stdout's lock: EPIPE frees the parked writer
	host, g := net.Pipe()
	ours, theirs := net.Pipe()
	s.sit(ours)
	done, ended, gc := make(chan result, 1), make(chan result, 1), wire.New(g, time.Minute)
	go client(theirs, func() {}, false)
	go output(wire.New(host, frameLimit), s, done)
	exit, out := guest.EncodeExit(guest.Exit{Code: 3}), make([]byte, guest.MaxStdin)
	for sent := 0; sent <= 1<<20 && err == nil; sent += len(out) { // 1 MiB of output, well past what any pipe holds, then the Exit
		err = gc.WriteFrame(map[bool]wire.Frame{false: {Type: guest.TypeStdout, Payload: out}, true: {Type: guest.TypeExit, Payload: exit}}[sent >= 1<<20])
	}
	var got result
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		fail("guest side: %v; the Exit never reached done within 10 s", err)
	}
	go func() { ended <- end(theirs, got) }() // session's done arm
	select {
	case got = <-ended:
	case <-time.After(5 * time.Second):
		fail("C50: run did not end after Exit: end(theirs, got) still waits on the stopped stdout reader 5 s after done delivered the Exit")
	}
	if back(); err != nil || got.code != 3 {
		t.Fatalf("guest side: %v; end returned %+v, want code 3", err, got)
	}
}
