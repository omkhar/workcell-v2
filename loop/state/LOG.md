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

## 2026-11-01T16:17Z U-005 PASS mode=cloud model=fable tries=0
Added nine escape tests to suite.All (+534/-18 lines, stdlib only): I2 raw-ip-odd-port-tcp4, ipv4-mapped-ipv6-tcp, udp4-datagram, quic-initial (QUIC v1 Initial with the token as DCID) and icmp-echo; I4 host-loopback-tcp4 (seed, now dials the host's own address), lan-rfc1918-tcp4, link-local-tcp4 and metadata-tcp4. All nine FAIL on control as root and as an unprivileged user, 0 errors (T2).
The three non-loopback I4 canaries add a /32 to lo for the test (netlink, with a sudo -n ip fallback on EPERM for the unprivileged hosted runner) and remove it after; the runner now cancels on SIGINT/SIGTERM so the address never leaks. Every target is an address the test itself bound (T8, S12).
Review: four R2 findings (unprivileged runner, 127.0.0.1 is the guest's own loopback on a real VM, no true IPv6 packet, leaked /32 on interrupt); three fixed in the one fix round. The IPv6 test is parked, not written: this kernel has no IPv6, so it could not be shown to fail on control.
Learned: Go dials an IPv4-mapped address as AF_INET, so the mapped test covers parsing only; the ICMP probe needs CAP_NET_RAW or an unprivileged SOCK_DGRAM echo socket; the sudo ip path has not run for real yet, the hosted gate is its first run once I4 is enforced.
Next: U-006 (I3) through U-010b each add tests the same way; the unit ran over the 400-line wish because the netlink and ICMP packet code cannot be split from the tests that need it. Add I2 and I4 to enforced.txt only when U-303 and U-305 make them pass. A hosted run of the control suite as the runner account is still unproven: no gate step runs control.

## 2026-11-01T16:19Z U-006 START mode=cloud

## 2026-11-01T16:41Z U-006 PASS mode=cloud model=fable tries=0
Added six I3 escape tests to suite.All (+563/-5 lines, stdlib only): direct-resolver-udp4, direct-resolver-tcp4, dot-tcp4, doh-post-tcp4, doh-get-tcp4 and tunnel-txt-udp4, each with a literal hostAddr:port that the judge's own listener chose; a host-side capture (UDP, framed TCP, in-memory self-signed TLS shared by DoT and DoH) parses the bytes with a bounded parseDNSQuery that has a table test and FuzzParseDNSQuery (T5, 20 s clean).
All six FAIL on control as root and as uid 65534, 0 errors; the whole control suite is 15 fail, 0 errors (T2). Hosted gate, gate-macos and guard were green on the pre-fix commit; local gate 4 s.
Review: two R2 findings, both fixed in the one round: tunnelled judged a partial leak (3 of 4 chunks) as a pass, now any chunk of the token counts; the UDP, TCP and HTTPS captures did not join their goroutines before the judge read, now stop() closes then waits like udpCanary. Four lines parked.
Learned: no _linux/_other split was needed, the DNS codec and TLS helpers are portable; the DoH client uses an explicit Transport with Proxy nil so no environment proxy or system resolver can redirect a probe; the session has no nft privileges, so the dropped-chunk case is a unit test, not a control run.
Next: U-007 (I1, I7, I10) needs a deliberately weak control variant for each flood and residue test; the control adapter keeps the host network namespace, so nothing here proves the resolver path (see PARKED), which is U-304's job with a test-controlled upstream.

## 2026-11-01T17:14Z U-007 BLOCKED mode=cloud model=fable tries=0
Redteam wrote ten tests (+850 lines net under escape/): I1 dotdot-traversal, planted-symlink, device-node and bind-mount against a judge-made export directory with a secret beside it; I7 cross-session-residue (a second session reads what the first wrote to /tmp, /var/tmp, /dev/shm, /root, /run and its export); I10 fork-, memory-, disk-, descriptor- and log-flood, each bounded by the probe and judged against a cap the test fixes (1 CPU, 256 MiB memory, 64 MiB disk). All ten FAIL on control as root, 0 errors, 18.7 s; as uid 65534 nine fail and device-node passes, because CAP_MKNOD is honoured only in the init user namespace.
Harness shape that made it work: Start(ctx, Config{Payload, Workspace, CPUs, MemoryMiB, DiskMiB}) exports a judge-made directory into the guest; suite.Session{Run, Workspace, Guest, Another} replaces the bare Run so a judge can open a second session; Output.Total counts the bytes the host took in beyond the 4096 it keeps. Control applies no cap and exports the directory at its host path.
Blocked by SPEC section 7, not by the tests: the test-code budget is 1.5 x product + 2000 lines, product code is 32 lines, so everything under escape/ may hold 2048 lines; main holds 1860 and this unit brings 2729. Nothing in escape/ can go without losing a T2-proven test, and no cut of 188 lines inside the new files was found.
The code is committed on this run's work branch and not pushed (7a case 2). Rebuild it from this entry when the budget allows.
Next: U-008, U-009, U-010 and U-010b each add about 500 lines and cannot fit either; read the gate's budget line before spending a redteam on them. Only product code (U-202 is the first unit with no human gate before it) or a maintainer edit to the budget makes room. Code under spikes/ is outside the budget, so U-100 and U-101 can go on.
