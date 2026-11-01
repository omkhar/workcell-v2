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
