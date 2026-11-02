// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// The I12 probe is root in the guest with the host end of the channel in
// reach, as guest init has it. It sends the one well-formed frame the
// adapter named and reads the answer; then its kind of hostile traffic, on
// connections it keeps open; then the well-formed frame again on a fresh
// connection, while the hostile ones still stand. The judge holds the host
// end to answering both and to being alive after.

const (
	channelWait  = 3 * time.Second        // for an answer to the well-formed frame
	dripInterval = 150 * time.Millisecond // between bytes of the slow drip
	dripFor      = 3 * time.Second        // how long the drip lasts
	bigFrame     = 1 << 22                // bytes streamed as one declared frame
	zeroFrames   = 1024                   // zero-length frames in the flood
	rawBytes     = 4096                   // random bytes sent as frames
	chewTime     = 500 * time.Millisecond // for the host to take the hostile traffic
	sendWait     = 2 * time.Second        // a write to a host that stopped reading gives up
)

// channelProbe sends the hostile traffic of kind args[0] to the channel at
// args[1], around the well-formed frame args[2] (hex), which the host answers
// with args[3] (hex), and says whether the host still answered after.
func channelProbe(args []string) Result {
	if len(args) != 4 {
		return Result{Status: "error", Detail: "want kind, address, hello and reply"}
	}
	kind, addr := args[0], args[1]
	hello, err := hex.DecodeString(args[2])
	reply, err2 := hex.DecodeString(args[3])
	if err != nil || err2 != nil || len(hello) == 0 {
		return Result{Status: "error", Detail: "hello and reply must be hex, hello not empty"}
	}
	if err := sayHello(addr, hello, reply); err != nil {
		return Result{Status: "error", Detail: "no answer to the well-formed frame before anything hostile: " + err.Error()}
	}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	// send opens a connection, writes b on it with a deadline, and keeps it
	// open: a host that reads whole frames with no cap or clock stays stuck.
	send := func(b []byte) {
		c, err := dialChannel(addr)
		if err != nil {
			return
		}
		held = append(held, c)
		c.SetWriteDeadline(time.Now().Add(sendWait))
		c.Write(b)
	}
	switch kind {
	case "hello":
	case "malformed":
		send(make([]byte, 4*zeroFrames)) // zero-length frames
		send([]byte{0, 0, 0, 1})         // a one-byte frame with no byte
		off := binary.BigEndian.AppendUint32(nil, uint32(len(hello)-4+1))
		send(append(off, hello[4:]...)) // the hello, length off by one
		odd := append([]byte{}, hello...)
		odd[len(odd)-1] ^= 0xff // the hello with its last byte flipped: an unknown type or a bad body
		send(odd)
		raw := make([]byte, rawBytes)
		rand.Read(raw)
		send(raw)
		send(append([]byte{0xff, 0xff}, hello...)) // a version or type the host never issued
	case "oversized":
		send([]byte{0xff, 0xff, 0xff, 0xff})                         // 4 GiB declared, then silence
		send([]byte{0x7f, 0xff, 0xff, 0xff})                         // 2 GiB declared
		send([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // a 64-bit length
		big := binary.BigEndian.AppendUint32(nil, bigFrame)
		send(append(big, make([]byte, bigFrame)...)) // a frame the host must refuse to buffer
	case "slow-drip":
		c, err := dialChannel(addr)
		if err != nil {
			return Result{Status: "error", Detail: "drip: " + err.Error()}
		}
		held = append(held, c)
		go func() {
			for i := 0; time.Duration(i)*dripInterval < dripFor; i++ {
				c.SetWriteDeadline(time.Now().Add(sendWait))
				if _, err := c.Write(hello[i%len(hello) : i%len(hello)+1]); err != nil {
					return
				}
				time.Sleep(dripInterval)
			}
		}()
	default:
		return Result{Status: "error", Detail: "unknown kind " + kind}
	}
	time.Sleep(chewTime)
	if err := sayHello(addr, hello, reply); err != nil {
		return Result{Status: "unanswered", Detail: fmt.Sprintf("%d hostile connections open; the well-formed frame then got: %s", len(held), err)}
	}
	return Result{Status: "served", Detail: fmt.Sprintf("%d hostile connections open; the well-formed frame was still answered", len(held))}
}

// sayHello sends the well-formed frame on a fresh connection and expects the
// reply to begin as told, within channelWait.
func sayHello(addr string, hello, reply []byte) error {
	c, err := dialChannel(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(channelWait))
	if _, err := c.Write(hello); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(c, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(got) != string(reply) {
		return fmt.Errorf("reply %x, want %x", got, reply)
	}
	return nil
}

// dialChannel connects to a channel address: unix:<path>, tcp:<host:port> or
// vsock:<cid>:<port>.
func dialChannel(addr string) (net.Conn, error) {
	kind, rest, ok := strings.Cut(addr, ":")
	if !ok {
		return nil, errors.New("channel address " + addr + ": want kind:address")
	}
	switch kind {
	case "unix", "tcp":
		return net.DialTimeout(kind, rest, channelWait)
	case "vsock":
		return dialVsock(rest)
	}
	return nil, errors.New("channel address " + addr + ": unknown kind")
}

// channelJudge sends the probe of kind at the channel and holds the host end
// to its promise: it answered the well-formed frame before (else nothing is
// proven), it answers it after, the supervisor still runs, and a plain run
// still completes.
func channelJudge(kind string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		ch, err := s.Channel(ctx)
		if err != nil {
			return false, "", err
		}
		pid, err := s.Helper(ctx, "supervisor")
		if err != nil {
			return false, "", err
		}
		if pid <= 1 || pid == os.Getpid() {
			return false, "", fmt.Errorf("the adapter names pid %d as the supervisor", pid)
		}
		if alive, err := helperAlive(pid); err != nil || !alive {
			return false, "", fmt.Errorf("the supervisor (pid %d) is not running before the probe (%v)", pid, err)
		}
		args := []string{kind, ch.Addr, hex.EncodeToString(ch.Hello), hex.EncodeToString(ch.Reply)}
		r, err := s.Run(args...)
		if err != nil {
			return false, "", err
		}
		say := fmt.Sprintf(" (guest says %s: %s)", r.Status, r.Detail)
		if alive, err := helperAlive(pid); err != nil {
			return false, "", err
		} else if !alive {
			return false, fmt.Sprintf("the supervisor (pid %d) died on %s traffic%s", pid, kind, say), nil
		}
		if r.Status != "served" {
			return false, "the host end stopped answering the well-formed frame under " + kind + " traffic" + say, nil
		}
		args[0] = "hello"
		if r2, err := s.Run(args...); err != nil || r2.Status != "served" {
			return false, fmt.Sprintf("a plain run after the %s traffic did not complete: %v%s", kind, err, say), nil
		}
		return true, fmt.Sprintf("the supervisor (pid %d) survived %s traffic and still answers%s", pid, kind, say), nil
	}
}
