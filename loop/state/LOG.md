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

## 2026-11-01T17:19Z U-008 BLOCKED mode=cloud model=fable tries=0
Not attempted: the local gate on main reports test code 1879 of 2048 lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under escape/. U-008 needs a canary secret in the harness Config plus about seven I5 and I6 tests; U-005 and U-006 cost 60 to 95 lines per test and U-007 brought 850, so it cannot fit.
No redteam was spent, as the U-007 entry advised. Nothing under escape/ can be deleted without losing a T2-proven test, so SPEC section 7 blocks the unit as it blocked U-007. BLOCKED.md says what unblocks it.
Next: U-009, U-010 and U-010b have the same problem and will be recorded the same way unless the maintainer edits the budget or reorders Phase 0 first. That makes five BLOCKED results after one PASS, not six, so the loop then reaches U-100 (spike, env:kvm, spikes/ is outside the budget). The claim was PR #12, closed by this run.

## 2026-11-01T17:24Z U-009 BLOCKED mode=cloud model=fable tries=0
Not attempted: the local gate on main reports test code 1879 of 2048 lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under escape/. U-009 needs about eight I8 and I13 tests (hostile hooks, filters, attributes, .git/config, submodule URLs, symlinks, ../ paths, case-collision names, a widening repo-local policy) at 60 to 95 lines each, plus a return-path hook in the harness, so it cannot fit.
No redteam was spent, as the U-007 entry advised. Nothing under escape/ can go without losing a T2-proven test, so SPEC section 7 blocks the unit as it blocked U-007 and U-008. BLOCKED.md says what unblocks it.
Next: U-010 and U-010b have the same problem and will be recorded the same way unless the maintainer edits the budget or reorders Phase 0 first. After them the loop reaches U-100 (spike, env:kvm, spikes/ is outside the budget). The claim was PR #14, closed by this run.

## 2026-11-01T17:31Z U-010 BLOCKED mode=cloud model=fable tries=0
Not attempted: the local gate on main reports test code 1879 of 2048 lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under escape/. U-010 needs three harness hooks (a host-side record reader for I9, a way to kill the proxy, resolver or broker for I11, and guest access to the host-guest channel for I12) plus about eight tests at 60 to 95 lines each, so it cannot fit.
No redteam was spent, as the U-007 entry advised. Nothing under escape/ can go without losing a T2-proven test (the largest non-test files are the runner at 158 lines and suite.go at 144), so SPEC section 7 blocks the unit as it blocked U-007 to U-009. BLOCKED.md says what unblocks it.
Next: U-010b has the same problem and will be recorded the same way. That makes five BLOCKED results after U-006 PASS, so the six-failures rule does not fire yet, but one FAIL on U-100 (spike, env:kvm, spikes/ is outside the budget) after that would halt the loop. The claim was PR #16, closed by this run; gate, gate-macos and guard were green on main plus the claim.

## 2026-11-01T17:34Z U-010b BLOCKED mode=cloud model=fable tries=0
Not attempted: the local gate on main reports test code 1879 of 2048 lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under escape/. U-010b needs a local fake channel server with a signing key, a fake upstream that serves an artifact, a harness hook that drives the client's update path against them, and six refusal tests (bad signature, expired manifest, lower serial, digest mismatch, truncated download, redirected URL), each with a weak control variant so that it FAILS there (T2). At 60 to 95 lines per test it cannot fit.
No redteam was spent, as the U-007 entry advised. Nothing under escape/ can go without losing a T2-proven test, so SPEC section 7 blocks the unit as it blocked U-007 to U-010. BLOCKED.md says what unblocks it.
Next: Phase 0 has no open unit left; the last six results are one PASS and five BLOCKED, so one more FAIL or BLOCKED halts the loop with six-failures. The next unit is U-100 (spike, model opus, env:kvm): code under spikes/ is outside the test budget, and its prototypes run on the pull request in hosted CI. The claim was PR #18, closed by this run.

## 2026-11-01T17:37Z U-100 START mode=cloud

## 2026-11-01T18:10Z U-100 PASS mode=cloud model=opus tries=0
Added spikes/libkrun (654 lines Go, notes.md 140 lines) and two direct dependencies (purego v0.11.2, x/sys v0.49.0). The test skips without /dev/kvm; on the hosted runner it downloads libkrun 1.19.7 (crates.io crate) and libkrunfw 5.6.2 by pinned digest, builds libkrun with cargo (LTO off, 58 s), loads it through purego in a child process, and boots a static Go guest: virtio-fs shared directory, vsock echo, exit code 7 propagated, Go guest as PID 1 also works.
Measured on PR #20, gate 131 s of 900: boot p50 699 ms (min 676, max 711, n=20), total p50 701 ms, teardown p50 20 ms; P1's hosted target is met with margin. Sizes: guest 3.46 MB static; host child 2.74 MB (nocgo) or 2.65 MB (cgo), both glibc-dynamic ELF; libkrun.so 5.4 MB; libkrunfw.so.5 21.8 MB.
Learned: A6's one static binary does not hold with libkrun on Linux (purego and cgo both need the ELF interpreter, plus two shared libraries beside it); libkrunfw bundles a GPL-2.0 kernel with a source-offer duty; libkrun's default TSI lets the guest reach host loopback, so a backend must disable the implicit vsock (I4); a NULL envp in krun_set_exec copies the host environment onto the guest cmdline (I5); without /dev/kvm krun_start_enter aborts the process instead of returning.
The ADR step of the spike flow is U-103a's job by the plan (ADR-001 compares all three spikes), so no ADR was written here. The proxy of this session refuses GitHub tag archives, so the crate was pinned instead; CI reached both inputs in under a second.
Next: U-101 (Firecracker and Cloud Hypervisor, model sonnet) can copy the test shape, timing definition and t.Logf keys from spikes/libkrun so that U-103a compares like with like; U-102 is env:macos and waits for a Mac run.

## 2026-11-01T18:13Z U-101 START mode=cloud

## 2026-11-01T18:53Z U-101 PASS mode=cloud model=sonnet tries=0
Added spikes/fcch (1424 lines Go, notes.md), stdlib plus x/sys only, no go.mod change: the test downloads Firecracker v1.17.0, Cloud Hypervisor v54.0, Firecracker's CI kernel 6.1.155 (kernel A) and Cloud Hypervisor's 7.2.8 release kernel (kernel B) by pinned digest, installs virtiofsd from the distribution with apt, builds a static Go guest as /init of a newc cpio written in Go, and boots fc (FC, A, raw block share), ch-blk (CH, A, raw block), ch-fs (CH, B, virtio-fs), 1 warm-up plus 20 timed boots each, plus one SIGKILL boot and two cross-kernel boots. Green on the first hosted push (PR #21, commit 26554d0): TestFCCH 89 s, gate 128 s of 900.
Measured (2 vCPU, 1024 MiB): boot_ms p50 fc 194, ch-blk 121, ch-fs 278; total_ms p50 197 / 121 / 280; teardown_ms p50 501 / 8 / 36; libkrun in the same run 543 / 545 (U-100's own run said 699 / 701, so runners differ and only numbers from one gate run compare). Every row is far under P1's hosted 2.5 s.
Learned: both VMMs are static-pie ELF with no interpreter and no NEEDED, driven by exec plus HTTP or flags, so with them A6 holds (one static Go binary plus one VMM binary fetched by digest); only virtiofsd is glibc-dynamic and nobody prebuilds it. Neither VMM carries a guest exit code (vsock is the channel) and both exit 0 on shutdown. The guest sees lo only, host loopback is unreachable (I4), the canary never reached the guest environment or cmdline (I5), orphans=0 after SIGKILL of the VMM (A9), but sockets and the share image stay in the boot directory (I7 cleanup is the supervisor's job). Firecracker has no virtio-fs and appends pci=off and virtio_mmio.device= to the cmdline itself. Neither VMM runs on macOS.
No ADR here, as with U-100: ADR-001 is U-103a's job once U-102 (env:macos) is done. The architect did not write a file; the builder on sonnet needed one CI push.
Next: the only unit left for the cloud is none until H-103, U-102 is env:macos, U-202 (deps:U-001, env:any, boundary) is open and is the first product code, which also widens the test-code budget that blocks U-007 to U-010b. Read the gate's budget line before any escape unit.

## 2026-11-01T18:57Z U-202 START mode=cloud

## 2026-11-01T19:11Z U-202 PASS mode=cloud model=opus tries=0
Added internal/wire (144 lines product, 215 lines test, stdlib only, no go.mod change): a 6-byte header (version, type, big-endian uint32 length), MaxPayload 64 KiB checked before any allocation, New(Stream, limit) where Stream needs SetReadDeadline and SetWriteDeadline, one per-frame deadline armed at the first byte and covering the rest of the header and the payload, the same for writes, ErrVersion and ErrTooLarge with the value seen, io.ErrUnexpectedEOF on truncation, os.ErrDeadlineExceeded on timeout; after an error that direction stays failed and never resynchronises on guest-chosen bytes. No logging (I10).
Tests: three table tests (19 read, 3 write, 8 net.Pipe time-limit cases at 50 ms) and FuzzReadFrame, whose oracle is re-encode to a prefix of the input, clean EOF only at a frame boundary, sticky error; 20 s and 30 s fuzz runs clean, -race -count=8 on the deadline cases clean. Local gate 5 s; hosted guard and gate-macos green on the unit commit.
Redteam wrote no escape test: I12's target does not exist yet and nothing can be shown to FAIL on control (T2); the control adapter already bounds and strictly parses the payload's stdio, which it measured with floods, lingering children and 100000 result lines. Its attack variants are one line in PARKED.md for U-010 and U-208. Review: no findings; one design note parked.
Learned: a raw blocking AF_VSOCK fd wrapped in os.File returns os.ErrNoDeadline, so the guest init (U-203) must open its channel non-blocking for deadlines to work; ReadFrame waits without limit for the first byte, the caller closes the stream to end an idle read. First product code: the test-code limit is now 2264 lines and the gate reports 2094 used, so about 170 lines remain under escape/ plus _test.go until more product lands; U-007 to U-010b stay blocked.
Next: the cloud has nothing until H-103 (U-102 is env:macos, U-200 and U-201 wait on H-103, U-302 waits on nothing but is listed after U-300 and U-301 which need U-204); check U-302 (deps:U-001, env:any) as the next takeable unit, and read the gate budget line first because it ports _legacy/egressproxy (S14).

## 2026-11-01T19:18Z U-302 SPLIT mode=cloud model=opus tries=0
Split into U-302a (allowlist.go and denylog.go with tests, drop injectionpolicy, inline the rootio no-follow read), U-302b (proxy.go with tests: blockedAddr, SNI peek, ECH refusal, FuzzPeekSNI) and U-302 (terminate.go with tests, the last part, deps on both). The scout measured _legacy/egressproxy at 929 product and 1220 test lines in eight files, five times the 400-line limit of PROMPT.md section 8, so no builder was spent.
Facts for the parts: every legacy file is stdlib-only except allowlist.go, which imports injectionpolicy for one endpoint check (ValidateEgressEndpoint, absent from this tree) and rootio for ReadFileNoFollow (_legacy/rootio/nofollow.go). No legacy test reads source as text. go.mod has two direct dependencies (purego, x/sys); x/net is not yet required and the scout saw no need for it.
Budget after the full port: about 1105 product lines, so the test limit becomes about 3658 and the 1220 ported test lines fit beside the 234 that exist; U-007 to U-010b may fit again once all three parts land, so read the gate budget line then.
Next: U-302a is the first takeable unit for the cloud (env:any, deps U-001). The claim was PR #23, closed by this run.

## 2026-11-01T19:22Z U-302a START mode=cloud

## 2026-11-01T19:36Z U-302a PASS mode=cloud model=opus tries=0
Added internal/proxy (325 lines product, 280 lines test, stdlib plus x/sys/unix, no go.mod change): allowlist.go (Allowlist, ParseAllowlist, LoadAllowlist, canonicalHost, Ports, tlsPort), denylog.go (denyLine, DenyAuditRecords, MaxDenyLogBytes) and readnofollow.go (readFileNoFollow, the descriptor-relative O_NOFOLLOW walk from _legacy/rootio/nofollow.go, 1 MiB cap). Every file says // Ported from v1: <path> below the SPDX and copyright lines.
The injectionpolicy call is replaced by a local dnsName check (labels 1 to 63 of a-z, 0-9 and inner hyphens, 253 bytes in all, after the IP-literal refusal) plus a port 0 refusal that the legacy test already demanded. denylog.go now also defines denyKey, maxLogHost (253), maxDenyKeys (4096), overflowHost and overflowCause, which legacy kept in proxy.go: U-302b must not define them again. FuzzDenyAuditRecords added (T5); 20 s runs clean twice, -race clean, GOOS=darwin vet clean.
Deferred to U-302b by the split: TestDenyAuditRecordsReadsProxyOutput and TestDenyAuditRecordsSeesRotatedHead, which need New and deny from proxy.go. Redteam wrote no escape test (nothing can FAIL on control until U-303 wires the proxy to a guest); its variants are one line in PARKED.md. Review: no findings; one less-code note parked. Local gate 6 s, guard green.
Budget: product 501 of 15000, test 2374 of 2751, so 377 test lines remain; U-302b brings about 500 legacy test lines (proxy_test.go) and gains about 1.5 lines of room per product line of proxy.go, so read the gate budget line first and drop or trim before writing. U-007 to U-010b stay blocked until more product lands.
Next: U-302b (deps U-001, U-302a; env:any; model opus) is the next takeable unit for the cloud.

## 2026-11-01T19:41Z U-302b START mode=cloud

## 2026-11-01T19:58Z U-302b PASS mode=cloud model=opus tries=0
Added internal/proxy/proxy.go (304 lines) and proxy_test.go (489 lines), stdlib only, go.mod unchanged; denylog_test.go gains the two tests U-302a deferred (TestDenyAuditRecordsReadsProxyOutput, TestDenyAuditRecordsSeesRotatedHead). Both new files say // Ported from v1: egressproxy/<name>.
proxy.go is legacy proxy.go minus what U-302a already holds (denyKey, maxLogHost, maxDenyKeys, overflowHost, overflowCause), minus the five terminate-only Proxy fields (terminate, ca, broker, transport, upstreamRoots) and the serveTerminated branch of handle, and minus the crypto/x509 and net/http imports those needed: every allowed TLS connection is spliced, as legacy does with no terminate rule. U-302 must add those fields, that branch and those imports back with terminate.go. blockedAddr, peekSNI (ECH refusal), route, connect, splice and deny are unchanged.
Tests: go test -race clean, FuzzPeekSNI 20 s clean (about 170 execs per second, each input does a net.Pipe TLS handshake), GOOS=darwin vet clean. Local gate 6 s; hosted gate, gate-macos and guard green on the unit commit. Redteam wrote no escape test (nothing can FAIL on control before U-303; its variants are one line in PARKED.md). Review: no findings; one less-code note parked.
Budget: product 805 of 15000, test 2914 of 3207, so 293 test lines remain. U-302 brings terminate.go (385 product lines, which raises the limit by about 577) and terminate_test.go (429 test lines), so it fits with about 440 lines to spare; read the gate budget line first all the same. U-007 to U-010b stay blocked until more product lands.
Next: U-302 (deps U-001, U-302a, U-302b; env:any; model opus) is the next takeable unit for the cloud. The claim was PR #26, which this run gave its final title.
