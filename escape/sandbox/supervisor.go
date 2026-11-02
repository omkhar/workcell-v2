// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"encoding/binary"
	"io"
	"net"
)

// ControlSupervisor is a helper of the control sandbox (SPEC T2): the host
// end of a naive channel on the unix socket at path, served one connection
// at a time, a frame of a big-endian length, a type byte and a body read
// whole with no cap and no deadline, and answered when the type is 1 (hello).
func ControlSupervisor(path string) error {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		serveControl(c)
	}
}

func serveControl(c net.Conn) {
	defer c.Close()
	var head [4]byte
	for {
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(head[:]))
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		if body[0] == 1 { // hello: answer with type 2
			c.Write(frame(2, []byte("hi")))
		}
	}
}

// frame encodes one frame of the control channel.
func frame(kind byte, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(1+len(body)))
	return append(append(b, kind), body...)
}
