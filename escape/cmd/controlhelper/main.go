// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Controlhelper is one host helper of the control sandbox (SPEC T2). It is
// what a plain container has: a process that enforces nothing.
//
//	controlhelper proxy|resolver|broker
//	controlhelper supervisor <unix socket path>
//
// As the supervisor it is the host end of a naive channel: one connection at
// a time, a frame of a big-endian length, a type byte and a body, read whole
// with no cap and no deadline, and answered when the type is 1 (hello).
package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	if os.Args[1] != "supervisor" {
		select {} // a helper that does nothing, forever
	}
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	os.Remove(os.Args[2])
	ln, err := net.Listen("unix", os.Args[2])
	if err != nil {
		os.Exit(1)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(1)
		}
		serve(c)
	}
}

func serve(c net.Conn) {
	defer c.Close()
	var head [4]byte
	for {
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		frame := make([]byte, binary.BigEndian.Uint32(head[:]))
		if _, err := io.ReadFull(c, frame); err != nil {
			return
		}
		if frame[0] == 1 { // hello: answer with type 2
			c.Write(Frame(2, []byte("hi")))
		}
	}
}

// Frame encodes one frame of the control channel.
func Frame(kind byte, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(1+len(body)))
	return append(append(b, kind), body...)
}
