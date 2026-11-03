// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"
)

// SPEC I12. Root in the guest reaches the host end of the channel two ways:
// as a duplicate of the connection the init holds (pidfd_getfd on pid 1), on
// which a forged frame is indistinguishable from the init's own, and as fresh
// connections to the same host port. The host answers no guest frame, so the
// evidence is all on the host side: what `workcell run` returned for the
// hostile run, its exit status, its stderr and how long it took, and whether
// a plain run afterwards still works. A host end holds I12 only if the run
// ends within hangBound, the host process did not crash, it wrote no control
// bytes to its stderr, and it reported the command's own status or a clean
// refusal of the session, never a status the forged frame named.
//
// Frames: a 6-byte header of version 1, a type and a big-endian length of at
// most 65536, then the payload. Guest-to-host types are Stdout 5, Stderr 6,
// Exit 7 and Ack 8. An Exit payload is a tagged value, a code, a signal or an
// error text; its encoding is tried two ways, a tag byte and a JSON object,
// so that one of them reaches the host's decoder.
const (
	typeStdout = 5
	typeExit   = 7
	typeAck    = 8
	tagCode    = 0 // Exit payload: a code
	tagText    = 2 // Exit payload: an error text
	forgedCode = 7 // the status every forged Exit names; the command's own is 0

	maxExitText  = 256              // bytes of error text an Exit may carry
	hangBound    = 15 * time.Second // a hostile run must end within this
	shortLinger  = 2 * time.Second  // the probe stays alive after a frame the host may ignore
	longLinger   = 40 * time.Second // the probe holds the channel hostage past hangBound
	sendWait     = 2 * time.Second  // a write to a host that stopped reading gives up
	dripInterval = time.Second      // between bytes of the slow drip
	stormSize    = 32               // fresh connections in the storm
	stormHold    = time.Second      // how long each is held open
	channelBound = 45 * time.Second // Test.Bound: several boots, one of which may hang
	rawCleanExit = 125              // the CLI's status for a session it could not keep
	rawNoStart   = 126              // the CLI's status when the guest could not start the command
	sanitised    = " \t\n"          // control bytes a host may write to its stderr
)

// frame encodes one channel frame.
func frame(kind byte, payload []byte) []byte {
	h := []byte{1, kind}
	h = binary.BigEndian.AppendUint32(h, uint32(len(payload)))
	return append(h, payload...)
}

// exitTag and exitJSON are a forged Exit payload naming code, in each encoding.
func exitTag(code uint32) []byte { return binary.BigEndian.AppendUint32([]byte{tagCode}, code) }
func exitJSON(code int) []byte   { b, _ := json.Marshal(map[string]int{"code": code}); return b }
func textTag(text []byte) []byte { return append([]byte{tagText}, text...) }
func textJSON(text []byte) []byte {
	b, _ := json.Marshal(map[string]string{"error": string(text)})
	return b
}

// hostileText is an error text of n bytes that would retitle, clear and
// recolour a terminal and plant a fake result line, were it printed raw.
func hostileText(n int) []byte {
	b := []byte("\x1b]0;owned\x07\x1b[2J\x1b[H\r\x1b[1;31mFAKE: pass\x1b[0m\n\x07\x08\x08\x00\x7f\x1b[?1049h\nescape: workcell: I12: pass\n")
	for len(b) < n {
		b = append(b, "\x1b[A"...)
	}
	return b[:n]
}

// channelProbe takes the init's channel to the host at args[1] and sends the
// hostile traffic of kind args[0], then stays alive so that the host's answer
// to the frame, and not the command's end, is what ends the run. The storm
// kind uses fresh connections instead; plain sends nothing.
func channelProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want kind and channel address"}
	}
	kind, addr := args[0], args[1]
	switch kind {
	case "plain":
		return Result{Status: "ran", Detail: "nothing hostile sent"}
	case "storm":
		return storm(addr)
	}
	ch, err := stealChannel(addr)
	if err != nil {
		return Result{Status: "error", Detail: "take the init's channel: " + err.Error()}
	}
	defer ch.close()
	var b []byte
	linger := shortLinger
	switch kind {
	case "exit-empty":
		b = frame(typeExit, nil)
	case "ack-short":
		b = frame(typeAck, []byte{1})
	case "unknown-type":
		b = frame(200, []byte("?"))
	case "version-2-tag":
		b = frame(typeExit, exitTag(forgedCode))
		b[0] = 2
	case "version-2-json":
		b = frame(typeExit, exitJSON(forgedCode))
		b[0] = 2
	case "exit-text-tag":
		b = frame(typeExit, textTag(hostileText(maxExitText-1)))
	case "exit-text-json":
		n := maxExitText
		for b = textJSON(hostileText(n)); len(b) > maxExitText; b = textJSON(hostileText(n)) {
			n -= 8 // JSON spells a control byte in six
		}
		b = frame(typeExit, b)
	case "giant-header":
		b = frame(typeStdout, nil)
		binary.BigEndian.PutUint32(b[2:], 0xffffffff) // then silence
		linger = longLinger
	case "slow-drip":
		return drip(ch, frame(typeStdout, []byte("drip")))
	default:
		return Result{Status: "error", Detail: "unknown kind " + kind}
	}
	if err := ch.write(b, sendWait); err != nil {
		return Result{Status: "unsent", Detail: kind + ": " + err.Error()}
	}
	time.Sleep(linger)
	return Result{Status: "sent", Detail: fmt.Sprintf("%s: %d bytes on the init's channel, still running %s later", kind, len(b), linger)}
}

// drip writes the frame one byte per dripInterval, over and over, for
// longLinger or until the host stops taking bytes.
func drip(ch *rawConn, f []byte) Result {
	sent := 0
	for by := time.Now().Add(longLinger); time.Now().Before(by); sent++ {
		if err := ch.write(f[sent%len(f):sent%len(f)+1], sendWait); err != nil {
			return Result{Status: "cut", Detail: fmt.Sprintf("the host stopped taking the drip after %d bytes: %s", sent, err)}
		}
		time.Sleep(dripInterval)
	}
	return Result{Status: "sent", Detail: fmt.Sprintf("%d bytes dripped over %s", sent, longLinger)}
}

// storm opens stormSize fresh connections to the host end at once, sends a
// forged Exit on each, in both encodings, holds them open, and counts.
func storm(addr string) Result {
	var mu sync.Mutex
	var wg sync.WaitGroup
	opened, sent := 0, 0
	var last error
	for i := range stormSize {
		wg.Go(func() {
			c, err := dialChannel(addr)
			if err != nil {
				mu.Lock()
				last = err
				mu.Unlock()
				return
			}
			defer c.close()
			payload := exitTag(forgedCode)
			if i%2 == 1 {
				payload = exitJSON(forgedCode)
			}
			err = c.write(frame(typeExit, payload), sendWait)
			mu.Lock()
			opened++
			if err == nil {
				sent++
			}
			mu.Unlock()
			time.Sleep(stormHold)
		})
	}
	wg.Wait()
	detail := fmt.Sprintf("%d of %d connections opened, %d forged Exit frames sent", opened, stormSize, sent)
	if last != nil {
		detail += "; last error: " + last.Error()
	}
	return Result{Status: "stormed", Detail: detail}
}

// allowed is the exit status each kind lets a sound host report: 0, the
// command's own, when the host ignored the frame or the connections; 125, a
// clean refusal of the session; 126, the error path a forged error text
// reaches. Never the forged code, and never a crash.
var allowed = map[string][]int{
	"exit-empty":     {0, rawCleanExit},
	"ack-short":      {0, rawCleanExit},
	"unknown-type":   {0, rawCleanExit},
	"version-2-tag":  {0, rawCleanExit},
	"version-2-json": {0, rawCleanExit},
	"exit-text-tag":  {0, rawCleanExit, rawNoStart},
	"exit-text-json": {0, rawCleanExit, rawNoStart},
	"giant-header":   {rawCleanExit},
	"slow-drip":      {rawCleanExit},
	"storm":          {0, rawCleanExit},
}

// channelRun runs kind against the session's channel and holds the host end
// to what every kind demands. It returns the run's exit status, or the reason
// the host end fell short, "" when it did not.
func channelRun(ctx context.Context, s Session, addr, kind string) (int, string, error) {
	rctx, cancel := context.WithTimeout(ctx, hangBound)
	defer cancel()
	start := time.Now()
	out, err := s.Exec(rctx, kind, addr)
	took := time.Since(start).Round(100 * ms)
	if err != nil {
		if rctx.Err() != nil && ctx.Err() == nil {
			return 0, fmt.Sprintf("%s: the run did not end within %s", kind, hangBound), nil
		}
		return 0, "", err
	}
	say := fmt.Sprintf("%s: exit %d after %s", kind, out.Exit, took)
	line := firstLine(out.Stderr)
	switch {
	case out.Exit == 2 || bytes.Contains(out.Stderr, []byte("panic:")) || bytes.Contains(out.Stderr, []byte("fatal error:")):
		return out.Exit, fmt.Sprintf("%s: the host process crashed: %s", say, line), nil
	case control(out.Stderr) > 0:
		return out.Exit, fmt.Sprintf("%s: the host wrote %d control bytes to its stderr: %q", say, control(out.Stderr), line), nil
	case !slices.Contains(allowed[kind], out.Exit):
		return out.Exit, fmt.Sprintf("%s, want one of %v: %s", say, allowed[kind], line), nil
	}
	return out.Exit, "", nil
}

// control counts the bytes of b that would steer a terminal rather than show.
func control(b []byte) int {
	n := 0
	for _, c := range b {
		if c < 0x20 && !bytes.ContainsRune([]byte(sanitised), rune(c)) || c == 0x7f {
			n++
		}
	}
	return n
}

func firstLine(b []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(b), []byte("\n"))
	return clean(string(line), 120, isPrint, '?')
}

// channelJudge runs each kind in turn, each in its own session boot, and
// then a plain run, which must still work: the hostile run's VM, sockets
// and files must be gone. The first kind the host end fails under decides.
func channelJudge(kinds ...string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		ch, err := s.Channel(ctx)
		if err != nil {
			return false, "", err
		}
		var exits []string
		for _, kind := range kinds {
			exit, why, err := channelRun(ctx, s, ch.Addr, kind)
			if err != nil || why != "" {
				return false, why, err
			}
			exits = append(exits, fmt.Sprintf("%s: exit %d", kind, exit))
		}
		if why, err := plainAfter(s, ch.Addr, kinds[len(kinds)-1]); err != nil || why != "" {
			return false, why, err
		}
		return true, fmt.Sprintf("the host end held: %v; a plain run after still works", exits), nil
	}
}

// escapesJudge sends the forged error text in each encoding; one of them
// must reach the host's error path (exit 126), else nothing was tested, and
// whichever did must have left the host's stderr free of control bytes.
func escapesJudge(ctx context.Context, s Session) (bool, string, error) {
	ch, err := s.Channel(ctx)
	if err != nil {
		return false, "", err
	}
	kinds := []string{"exit-text-tag", "exit-text-json"}
	var exits []int
	for _, kind := range kinds {
		exit, why, err := channelRun(ctx, s, ch.Addr, kind)
		if err != nil || why != "" {
			return false, why, err
		}
		exits = append(exits, exit)
	}
	if !slices.Contains(exits, rawNoStart) {
		return false, "", fmt.Errorf("no forged error text reached the host's error path (exits %v for %v): the probe's Exit encodings need fixing", exits, kinds)
	}
	if why, err := plainAfter(s, ch.Addr, "the forged error texts"); err != nil || why != "" {
		return false, why, err
	}
	return true, fmt.Sprintf("the host reported the forged error text (exits %v) with no control byte on its stderr; a plain run after still works", exits), nil
}

func plainAfter(s Session, addr, after string) (string, error) {
	r, err := s.Run("plain", addr)
	if err != nil {
		return fmt.Sprintf("a plain run after %s did not complete: %v", after, err), nil
	}
	if r.Status != "ran" {
		return fmt.Sprintf("a plain run after %s says %s: %s", after, r.Status, r.Detail), nil
	}
	return "", nil
}
