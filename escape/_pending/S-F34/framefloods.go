// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// The reproducing test of C51 (S-1002, sweep 2), parked under S4: it fails on the product until S-F34 lands. Hosted CI on 11a6fff: the host spent 6.8 CPU
// seconds in 3.5 s of wall time, allowed 4.5, while the guest wrote 469646 empty Stdout frames in 3 s. The fix unit puts frameFloodKind's body back as the
// "frame-flood" case of channelProbe's switch in channel.go, after slow-drip; frameFlood beside drip there; and the row after device-cpu-flood in tests.go's All.
package suite

import (
	"bytes"
	"fmt"
	"time"
)

// frameFloodKind is channelProbe's frame-flood case, on the init's channel ch: empty Stdout frames, as many as the host takes in args[1] s, the guest's CPU at
// its cap meanwhile (cpuProbe): the decoder's load (I10).
func frameFloodKind(ch *rawConn, args []string) Result {
	v, r := ints(args[1:2], 1, "seconds")
	if r.Status != "" {
		return r
	}
	go cpuProbe(args[1:2])
	batch, sent := bytes.Repeat(frame(typeStdout, nil), 10922), 0 // about 64 KiB a write: a blocking write of more would outlast the deadline
	for by := time.Now().Add(time.Duration(v[0]) * time.Second); time.Now().Before(by) || sent%6 != 0 && time.Since(by) < sendWait; {
		n, _ := ch.write(batch[sent%6:], max(time.Until(by), sendWait)) // the rest of a frame the deadline cut comes first: the init's own frames follow it
		sent += n
	}
	return Result{Status: "tried", Detail: fmt.Sprintf("the host took %d empty Stdout frames (%d MiB) on the init's channel in %d s", sent/6, sent>>20, v[0])}
}

// frameFlood is channelProbe's frame-flood kind under the arguments cpuJudge passes: the seconds, then the channel address.
func frameFlood(args []string) Result { return channelProbe(append([]string{"frame-flood"}, args...)) }

// And the supervisor's own decoder: root writes the smallest valid frames on the init's channel as fast as the host takes them, each read in several calls.
var channelCPUFlood = Test{ID: "I10", Name: "channel-cpu-flood", Probe: frameFlood, Host: cpuJudge(Session.Channel), Want: capped}
