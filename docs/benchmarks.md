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

The nine checks the macOS host enforces (eight of the fourteen invariants, I2, I3, I4, I6, I7, I8, I11 and I12, and P1) are green; I1, I5, I9 and I13 also pass here though they are not in the enforced set; I10's non-memory floods and I14's layer-image checks need Linux host counters or `debugfs` and are covered by the KVM nightly track, not this host. B6 pin-smoke is not run here: it needs the real upstream agent fixtures, absent in this environment, and the run confirmed the fake API saw no real key.

P1 warm start, measured on the Mac: n=20, p50 251 ms, min 245 ms, max 267 ms (`GATE_MACOS=1` run); the unfiltered run measured p50 253 ms. P2 to P7 are recorded by U-906 from the KVM nightly.

## P1 to P7 (U-906)

Every number in this section is from a public hosted run or a hosted check, and this record is dated 2026-11-12.

| Target | Number | Verdict | Run |
|---|---|---|---|
| P1 warm start | hosted p50 242 ms (budget 2500 ms); Mac p50 251 ms (budget 1000 ms) | met | ci.yml `gate`, PR #174; H-703 |
| P2 install to first session | 2.0 s (target 60 s) | met | nightly.yml `upstream`, 2026-11-12 |
| P3 no host dependency beyond the hypervisor | not measured on a wiped image | not missed | see below |
| P4 every invariant on a real VM | 138 of 138 checks pass | met | ci.yml `gate`, PR #174 |
| P5 pull-request feedback | p50 269 s (target 600 s) | met | last 10 merged PRs, checks API |
| P6 launch hosts | macOS arm64, Linux amd64 and Linux arm64 pass | met | `gate`, H-703, H-704, `gate-arm64` |
| P7 upstream release to users | cannot be met before cutover | not measurable | bump.yml and nightly.yml, see below |

### P1 warm session start

Hosted: ci.yml job `gate` on pull request #174, commit b095307, 2026-11-12 05:16Z, runner ubuntu-24.04 image 20261101.360.1 with /dev/kvm, go1.27.0 linux/amd64. The log line is `escape: workcell: P1 warm-start: pass bench start n=20 p50=242ms min=238ms max=248ms`. The suite enforces a hosted budget of 2500 ms.
Developer machine: H-703 above (n=20, p50 251 ms, min 245 ms, max 267 ms, Apple M2 Max, 2026-11-09).
Verdict: met on both. H-703 and H-704 are the human gates behind the Mac number.

### P2 install to first running session

Source: nightly.yml job `upstream`, scheduled run 2026-11-12 04:50Z on main commit 78ea7e8, ubuntu-24.04 runner with /dev/kvm. `go test -count=1 -v -run TestInstallToFirstSession ./spikes/install` printed `P2 install 0.1`, `P2 guest files 1.6`, `P2 first session 0.4`, `P2 install to first session 2.0 s (target 60)` and `--- PASS: TestInstallToFirstSession (13.35s)`.
The test runs scripts/install.sh against a local server with a fresh HOME and TMPDIR, fetches the pinned Firecracker and kernel by digest, builds the guest image from pins/debian.json, then runs `workcell run -- true`. The runner is a hosted image, not a wiped machine, and the test builds the binary with the runner's Go toolchain before timing starts.
Verdict: met (2.0 s).

### P3 no host dependency beyond the OS hypervisor

No hosted job runs `workcell doctor` and prints its output, so P3 has no direct measurement on a clean image. This is not a run on a wiped image.
What `doctor` checks: `cmd/workcell/run_vm.go` has three rows, the hypervisor, the image (the pinned artifacts) and free disk (4 GiB), and exits 1 on any failure.
What the hosted subtest proves: the `doctor` subtest in `internal/vmm/firecracker/run_test.go` runs `workcell doctor` under KVM twice and asserts the exit code and the output lines (it does not only log them). With an empty data directory it requires exit 1 and the lines `ok   hypervisor`, `FAIL image: `, `     fix: ` and `ok   disk (`. With the populated data directory it requires exit 0 and `ok   hypervisor`, `ok   image` and `ok   disk (`. That package passed in the hosted `gate` of pull request #174 (`ok internal/vmm/firecracker 33.299s`); the gate runs `go test -race -count=1` without -v, so the logged doctor output is not in the log.
Related evidence: the P2 run above reached a first session from a fresh HOME with only /dev/kvm and the artifacts the install path fetches by digest.
Verdict: not missed. Nothing shows a dependency beyond the hypervisor, but a run on a wiped image has not been made.

### P4 every invariant on a real VM, on every change

Source: ci.yml job `gate` on pull request #174, commit b095307, 2026-11-12. With GATE_REQUIRE_VM=1 and /dev/kvm present, `go run ./escape/cmd/escape -sandbox workcell -only <escape/enforced.txt>` ran 138 checks: passed 138, failed 0, not_implemented 0, errors 0. `GATE PASS in 229s` against the 900 s budget.
Checks passed per invariant: I1 12, I2 13, I3 13, I4 14, I5 16, I6 5, I7 2, I8 7, I9 9, I10 7, I11 4, I12 10, I13 10, I14 12, B6 3, P1 1. escape/enforced.txt lists all 16 entries (I1 to I14, P1, B6).
macOS: the H-703 section above (nine enforced: I2 I3 I4 I6 I7 I8 I11 I12 P1). The `gate-macos` job on #174 printed `GATE PASS in 140s`; the hosted macos-15 runner has no nested virtualisation, so it runs unit tests only.
Verdict: met.

### P5 pull-request feedback

Each of the last 10 merged pull requests counts by the slower of `gate` and `gate-macos` (seconds from started to completed of the check run; a pull request with two runs counts the newer). Source: the checks API on 2026-11-12.

| PR | head | gate s | gate-macos s | slower s |
|---|---|---|---|---|
| #173 | eb5fae4 | 269 | 148 | 269 |
| #172 | c443f8b | 307 | 172 | 307 |
| #171 | c403a2d | 235 | 229 | 235 |
| #169 | 6cb4abf | 312 | 184 | 312 |
| #168 | e015cfc | 274 | 183 | 274 |
| #167 | b1c161e | 267 | 234 | 267 |
| #166 | fad11ab | 310 | 178 | 310 |
| #165 | b9fb0d7 | 237 | 170 | 237 |
| #164 | 824b180 | 269 | 178 | 269 |
| #162 | de228ea | 238 | 185 | 238 |

Sorted: 235 237 238 267 269 269 274 307 310 312. The p50 is 269 s (4 min 29 s) and the maximum is 312 s. The comparable v1 row (`CI`, above) has a median of 18 min. Verdict: met.

### P6 launch hosts

Linux amd64: the `gate` job above (P4). macOS arm64: H-703 (2026-11-09, Mac gate green, 69 of 69 checks) and H-704 (decided 2026-11-09), which narrowed P6 to this wording because the maintainer's M2 Max cannot nest virtual machines.
Linux arm64: ci.yml job `gate-arm64` (ubuntu-24.04-arm) runs loop/gate.sh, which builds, vets and runs `go test -race -count=1` on every non-spike package; the VM suite is deferred there because the runner has no /dev/kvm. It passed on pull request #174 in 66 s and on each of the ten pull requests in the P5 table (66 to 76 s each).
Verdict: met.

### P7 upstream release to users

P7 cannot be met before cutover, because nothing merges a bump in this repository (SPEC section 10). In its place stand the dry runs and the lag report.
Dry run that B-826b read: bump.yml job `plan`, scheduled run 2026-11-08 05:27Z on main commit d875117, `go run ./cmd/bump -dry-run`. It printed `dry-run: nothing is posted or written`, then one row per pin: claude-code guest 2.1.318, newest 2.1.319, eligible; codex guest, none, source-error; copilot-cli guest v1.0.105, newest v1.0.106, eligible; debian trusted trixie-20261027-slim, none, source-error; then `would open pull request: guest`. Its channel job signed and verified a manifest (serial 1794115747) with a key made in the job.
Newest dry run: bump.yml job `plan`, scheduled run 2026-11-11 05:27Z on main commit 62b29e3: claude-code guest 2.1.318 none (cool-off); codex guest, none, v0.167.0 eligible; copilot-cli guest v1.0.105, v1.0.107 eligible; debian trusted trixie-20261027-slim, trixie-20261104-slim eligible; then `would open pull request: guest` and `would open pull request: trusted`.
Lag per pin: nightly.yml job `upstream`, scheduled run 2026-11-12 04:50Z on main commit 78ea7e8. The log prints no header; the columns are pin, class, pinned, newest eligible, newest, lag, verdict.

| Pin | Class | Pinned | Newest eligible | Newest | Lag | Verdict |
|---|---|---|---|---|---|---|
| claude-code | guest | 2.1.318 | 2.1.322 | 2.1.322 | 4h0m0s | eligible |
| codex | guest | - | v0.167.0 | v0.167.2 | 945h0m0s | eligible, `P7 missed: codex` |
| copilot-cli | guest | v1.0.105 | v1.0.108 | v1.0.109 | 99h0m0s | eligible, `P7 missed: copilot-cli` |
| debian | trusted | trixie-20261027-slim | trixie-20261104-slim | trixie-20261104-slim | 29h0m0s | eligible |

The `issue` job updated the standing issue `nightly: P7 missed` (#163) as B12 says. codex has no pinned version yet, so its lag counts from the release.
Verdict: not measurable before cutover. The dry runs show the bump path would open the pull requests, and the nightly report measures the lag that H-905 and the first real bump will close.
