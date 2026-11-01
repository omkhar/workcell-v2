# Benchmarks

This file records measured numbers for the targets P1 to P7 of `loop/SPEC.md` section 1. Each number names the run it came from.

## Hosted CI gate (U-002b)

Source: hosted CI on pull request #5 of omkhar/workcell-v2, commit 7169c67, run on 2026-11-01.

| Check | Started (UTC) | Finished (UTC) | Seconds | Conclusion |
|---|---|---|---|---|
| gate | 15:16:44 | 15:17:18 | 34 | success |
| gate-macos | 15:16:44 | 15:17:41 | 57 | success |
| guard | 15:16:44 | 15:16:48 | 4 | success |
| merge | 15:17:43 | 15:17:47 | 4 | success |

The workflow's KVM step passed `test -w /dev/kvm` and printed `crw-rw-rw- 1 root kvm 10, 232 Nov  1 15:16 /dev/kvm`, so `/dev/kvm` is world-writable on the runner.
Inside the gate job, `loop/gate.sh` ran from 15:16:55Z to 15:17:15Z and reported `GATE PASS in 19s` against a 900 s budget; it noted that no invariant is enforced yet, so no VM suite ran.
The runner was the ubuntu-24.04 image version 20261025.353.1 (Ubuntu 24.04.5 LTS), GitHub-hosted on Azure in westus, runner 2.338.2; the Go toolchain was go1.27.0 linux/amd64, taken from `go.mod`.
