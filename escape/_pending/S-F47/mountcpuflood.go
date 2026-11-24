// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// The reproducing test of C64 (S-1002, sweep 3), parked under S4: it fails on the product until S-F47 lands. Hosted CI on 774549b judged it a fail: the supervisor spent more host CPU than
// the guest's one vCPU and the judge's slack allow while the guest flooded the file service of a `--mount` session with FUSE INTERRUPT requests. The fix unit puts fuseFlood back beside
// frameFlood in escape/suite/channel.go, whose comment then names both, and the row, with its comment line, directly after channel-cpu-flood in escape/suite/tests.go's All. The
// "fuse-flood" kind of channelProbe, interrupt and its unit test, and Session.Files (sandbox.Observe) stay live meanwhile: nothing runs them without the row.
package suite

// fuseFlood is channelProbe's fuse-flood kind under the arguments cpuJudge passes: the seconds, then the file service's address.
func fuseFlood(args []string) Result { return channelProbe(append([]string{"fuse-flood"}, args...)) }

// And the file service of a `--mount` session, on the init's connection to it, which the row above does not cover: root writes FUSE INTERRUPT requests, which the host answers with nothing, as fast as it takes them.
var mountCPUFlood = Test{ID: "I10", Name: "mount-cpu-flood", Probe: fuseFlood, Host: cpuJudge(Session.Files), Want: cappedLive}
