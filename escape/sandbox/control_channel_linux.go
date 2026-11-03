// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// naiveHost is the host end of the control sandbox's channel for one run,
// the deliberately weak counterpart of the product's (SPEC T2, I12): it
// accepts every connection, reads each frame whole with no cap and no clock,
// relays Stdout and Stderr raw, prints an Exit's error text as it came, and
// believes any Exit frame over the command's own status. A decoder that
// trips over a short payload takes the host down, as a crash would, and the
// run then reports as a crashed Go process does: exit 2 and "panic:".
type naiveHost struct {
	stdout, stderr io.Writer
	cancel         context.CancelFunc // ends the run when the host end dies
	mu             sync.Mutex
	exit           *int   // the last Exit frame's status
	crash          string // the panic, if one
	conns          []net.Conn
	wg             sync.WaitGroup
}

// accept serves every connection ln yields until stop is called.
func (h *naiveHost) accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h.add(c)
	}
}

func (h *naiveHost) add(c net.Conn) {
	h.mu.Lock()
	h.conns = append(h.conns, c)
	h.mu.Unlock()
	h.wg.Go(func() { h.serve(c) })
}

// stop ends the accept loop, then waits as a naive host does for every
// connection to close, which the command's death brings; or until ctx ends,
// when it closes them itself.
func (h *naiveHost) stop(ctx context.Context, ln *net.UnixListener) {
	ln.SetDeadline(time.Now())
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		h.mu.Lock()
		for _, c := range h.conns {
			c.Close()
		}
		h.mu.Unlock()
		<-done
	}
	ln.SetDeadline(time.Time{})
}

// serve reads frames until the connection ends: a 6-byte header of version,
// type and big-endian length, then the payload, however long, however slow.
func (h *naiveHost) serve(c net.Conn) {
	defer c.Close()
	defer func() {
		if p := recover(); p != nil {
			h.mu.Lock()
			if h.crash == "" {
				h.crash = fmt.Sprint(p)
			}
			h.mu.Unlock()
			h.cancel()
		}
	}()
	var head [6]byte
	for {
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return
		}
		var body bytes.Buffer
		if _, err := io.CopyN(&body, c, int64(binary.BigEndian.Uint32(head[2:]))); err != nil {
			return
		}
		b := body.Bytes()
		switch head[1] {
		case 5:
			h.stdout.Write(b)
		case 6:
			h.stderr.Write(b)
		case 7:
			h.exited(b)
		case 8:
			_ = binary.BigEndian.Uint32(b) // the stdin window moves by this much
		}
	}
}

// exited takes an Exit payload at its word: a JSON object when it looks like
// one, else a tag byte and the value, a code, a signal or an error text.
func (h *naiveHost) exited(b []byte) {
	code := 0
	if b[0] == '{' {
		var v struct {
			Code   *int    `json:"code"`
			Signal *int    `json:"signal"`
			Error  *string `json:"error"`
		}
		json.Unmarshal(b, &v)
		switch {
		case v.Error != nil:
			fmt.Fprintf(h.stderr, "control: %s\n", *v.Error)
			code = 126
		case v.Signal != nil:
			code = 128 + *v.Signal
		case v.Code != nil:
			code = *v.Code
		}
	} else {
		switch b[0] {
		case 0:
			code = int(binary.BigEndian.Uint32(b[1:]))
		case 1:
			code = 128 + int(b[1])
		case 2:
			fmt.Fprintf(h.stderr, "control: %s\n", b[1:])
			code = 126
		}
	}
	h.mu.Lock()
	h.exit = &code
	h.mu.Unlock()
}

// result applies what the channel said to the command's own exit status.
func (h *naiveHost) result(out Output) Output {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.exit != nil {
		out.Exit = *h.exit
	}
	if h.crash != "" {
		out.Exit = 2
		out.Stderr = append(out.Stderr, "panic: "+h.crash+"\n\ngoroutine 1 [running]:\n"...)
	}
	return out
}
