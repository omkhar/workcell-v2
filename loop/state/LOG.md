# Loop log

Append only. Newest at the bottom. Each entry is one heading and at most seven more lines, none of which starts with `#`.
`guard` refuses a pull request that changes or removes a line of this file, or that adds any heading but `## <UTC time> <unit>`
followed by START, PASS, FAIL, BLOCKED or SPLIT, unless the maintainer signed it.

| Heading | Written by | Meaning |
|---------|------------|---------|
| `## <UTC time> <unit> START mode=cloud` | the loop | A run has claimed the unit. It is not a result |
| `## <UTC time> <unit> PASS mode=<cloud or mac> model=<model> tries=<n>` | the loop | The unit is `[x]`, or `[S]` if it waits for `adopt.sh` |
| `## <UTC time> <unit> FAIL ...` | the loop | One more try is used up. After three, the next run marks the unit `[!]` |
| `## <UTC time> <unit> FAIL ... abandoned run` | the loop | A later run found this one dead. It uses up a try only if the unit's result before it was an abandoned run too |
| `## <UTC time> <unit> BLOCKED ...` | the loop | The unit is `[!]` and waits for the maintainer. `BLOCKED.md` says why, or says `needs the maintainer, see the run's transcript` |
| `## <UTC time> <unit> SPLIT ...` | the loop | The unit was split in `PLAN.md` |
| `## <UTC time> - RESUME` | the maintainer only | Start counting failures afresh |

Write the time as `2026-10-31T10:15Z`. The loop halts when the last six results are all FAIL or BLOCKED. To clear
that halt, fix the cause, append a RESUME line here, and land it with `land.sh`. Then close the `loop-halt` issue.

## 2026-11-01T15:16Z U-002b START mode=cloud

## 2026-11-01T15:21Z U-002b PASS mode=cloud model=haiku tries=0
Hosted gate on PR #5 (commit 7169c67): gate 34 s, gate.sh 19 s, /dev/kvm world-writable; recorded in docs/benchmarks.md (new file, 18 lines).
Learned: the shipped ci.yml works on ubuntu-24.04 with KVM; the gate.sh VM suite is still deferred because nothing is enforced yet.
Next: U-003 adds the v1 baseline to the same file; guard and merge checks take about 4 s each.

## 2026-11-01T15:24Z U-003 START mode=cloud

## 2026-11-01T15:26Z U-003 PASS mode=cloud model=haiku tries=0
Summarised loop/baseline/ci.tsv into a new section of docs/benchmarks.md (+21 lines): per-workflow runs, median, p90, failure rate and cancel rate for 12 v1 workflows.
Learned: the v1 CI workflow, the row comparable to P5, had a median of 18 min and a 20% cancel rate over 20 runs; five workflows have one sample only.
Next: the first unit is U-004, the escape harness (flow escape, model fable); the local gate takes about 2 s with nothing enforced.

## 2026-11-01T15:28Z U-004 START mode=cloud

## 2026-11-01T15:43Z U-004 PASS mode=cloud model=fable tries=0
Added escape/ (790 lines, stdlib only): sandbox.Sandbox interface with control (Linux namespaces, host network kept) and workcell (stub) adapters, a static CGO_ENABLED=0 payload, the runner escape/cmd/escape with -sandbox, -list, -only and a JSON report, and suite.All as the one place a test is declared.
Exit codes: 1 unless every selected test passed (not-implemented and probe errors are not passes), 2 when -only names an invariant with no test, so an enforced ID never passes vacuously.
Review found one R2 finding (a probe that never ran could count as an I4 pass); fixed in the one fix round. Hosted gate on PR #7 was green on the harness commit before the fix.
Learned: this session has no docker daemon and no /dev/kvm, but user namespaces work, so the control adapter runs here as uid 0 and through a user namespace. T2 evidence: the seed test I4 host-loopback-tcp4 fails on control.
Next: U-005 must absorb that I4 seed test rather than add a second loopback test, and point the canary at the host address as seen from a real guest, where 127.0.0.1 is the guest's own loopback. Linux-only probes go in _linux.go files with a stub for other systems, because the suite compiles on darwin.

## 2026-11-01T15:45Z U-005 START mode=cloud
