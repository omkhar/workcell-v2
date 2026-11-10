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

## v1 baseline (U-003)

Source: `loop/baseline/ci.tsv`, made by `baseline-ci.sh` from the public GitHub Actions API of the v1 repository, committed 2026-11-01.

| Workflow | Runs | Median (min) | p90 (min) | Failure rate | Cancel rate |
|---|---|---|---|---|---|
| Bench | 1 | 1 | 1 | 0% | 0% |
| CI | 20 | 18 | 24 | 0% | 20% |
| CI insights | 1 | 0 | 0 | 0% | 0% |
| CodeQL | 21 | 2 | 2 | 0% | 10% |
| Docs | 19 | 3 | 6 | 0% | 16% |
| Fuzz | 1 | 28 | 28 | 100% | 0% |
| Hosted controls | 21 | 0 | 0 | 0% | 0% |
| Mutation | 1 | 6 | 6 | 0% | 0% |
| Pin Hygiene | 1 | 1 | 1 | 100% | 0% |
| Scorecard | 22 | 0 | 0 | 0% | 0% |
| Security | 20 | 0 | 3 | 0% | 0% |
| Upstream refresh | 11 | 3 | 6 | 0% | 0% |

The `CI` row is the v1 row comparable to P5. Rows with a single run (Bench, CI insights, Fuzz, Mutation, Pin Hygiene) are one sample each.

## macOS suite (H-703)

Source: the escape suite on a real Mac (Apple M2 Max, darwin/arm64, macOS 27.2, Virtualization.framework), a clone of `main` at commit 7731bd90, run 2026-11-09.

The macOS host enforces nine invariants (`escape/enforced-macos.txt`). `GATE_MACOS=1 loop/gate.sh` ran them and reported `GATE PASS in 386s` (69 checks, 0 failed, 0 errors). A full `escape -sandbox workcell` run, with no enforced-list filter, recorded every invariant's outcome on this host:

| Invariant | macOS outcome | Note |
|---|---|---|
| I1 workspace isolation | pass (fs), n/a (mount) | dotdot, symlink, bind-mount, open-by-handle, link-rename pass; `--mount` and loop-device cases are Linux-only |
| I2 egress block | pass | 12/12 |
| I3 resolver | pass | 13/13 |
| I4 host/LAN/metadata block, rebind | pass | 15/15 |
| I5 credential binding | pass | 15/15; no placeholder or sign-in token reached the guest |
| I6 TLS, SNI, ECH | pass | 5/5 |
| I7 cross-session residue, read-only layers | pass | 2/2 |
| I8 safe return path | pass | 7/7 |
| I9 audit integrity | pass | 9/9; `verify` rejects every tampered log |
| I10 resource caps | pass (mem), n/a (other) | memory-flood pass; fork, disk, descriptor, log and cpu floods read Linux-only host counters |
| I11 fail-closed on helper death | pass | 4/4 |
| I12 host-guest channel | pass | 10/10 |
| I13 repo policy | pass | 10/10 |
| I14 update, channel | pass (daily), n/a (layer) | daily-wrong-key and daily-expired pass; layer-image cases need `debugfs` (Linux) |

Of the fourteen, the nine the macOS host enforces (I2, I3, I4, I6, I7, I8, I11, I12 and P1) are green; I1, I5, I9 and I13 also pass here though they are not in the enforced set; I10's non-memory floods and I14's layer-image checks need Linux host counters or `debugfs` and are covered by the KVM nightly track, not this host. B6 pin-smoke is not run here: it needs the real upstream agent fixtures, absent in this environment, and the run confirmed the fake API saw no real key.

P1 warm start, measured on the Mac: n=20, p50 251 ms, min 245 ms, max 267 ms (`GATE_MACOS=1` run); the unfiltered run measured p50 253 ms. P2 to P7 are recorded by U-906 from the KVM nightly.
