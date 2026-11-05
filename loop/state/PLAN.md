# Workcell v2: backlog

The loop's only mutable state, together with `LOG.md`, `BLOCKED.md`, `PARKED.md` and, in
Phase 10, `FINDINGS.md`. One unit per iteration.

## Line format

```
- [status] ID | flow:<flow> | model:<tier> | env:<env> | deps:<deps> | tries:<n> | [sign:you |] [wait:<file> |] title
      accept: the observable result that proves the unit is finished
- [H] ID | env:<env> | deps:<deps> | title
      accept: what is true once the maintainer has closed this gate
```

The first form is a unit. The second is a human gate: it has no flow, model or tries, and it reads `[x]` once it is closed.

| Field | Values |
|-------|--------|
| status | `[ ]` todo, `[x]` done, `[!]` blocked until the maintainer acts (`BLOCKED.md` says why), `[S]` proposed and waiting for `adopt.sh`, `[H]` a human gate. An open pull request is what "in progress" looks like |
| ID | one capital letter, a dash, digits, and at most one small letter: `U-204b`. The fix units of Phase 10 are `S-F1`, `S-F2` and so on |
| flow | `mech`, `doc`, `escape`, `build`, `boundary`, `spike`, `audit` (defined in `PROMPT.md` section 4) |
| model | the starting tier of the agent that writes: `haiku`, `sonnet`, `opus` or `fable`. `fable` is the top tier: Mythos where the account is verified for it, then Fable, then Opus |
| env | `any`: anywhere. `kvm`: needs a real VM or a hosted run. Hosted CI has both, so the cloud does it through its pull request (`PROMPT.md` section 5). `macos`: Apple Silicon, in the second macOS account, never in your own. A unit is done there by Claude, with you watching. A gate that runs code from the repository names the account in its own line, which only you can change |
| deps | IDs separated by commas. `-` means none. `above` means every unit and gate above this line |
| tries | failed attempts so far, 0 to 3. It drives escalation. At 3 the loop marks the unit `[!]` and moves on |
| sign:you | the unit needs a locked file. The loop writes it under `proposed/` and marks the unit `[S]`. You run `adopt.sh`. It shows you each file, installs what you accept, asks for each `[S]` unit whether it is done or must be done again, and hands over to `land.sh`, which signs |
| wait:<file> | the unit reads a scheduled run of that workflow. The loop skips the unit until such a run, created after the unit's dependencies were done, has finished. If it has had nothing to do but wait for 48 hours, it halts with the reason `no-schedule` |

A unit should land in under about 400 changed lines. If it cannot, the orchestrator splits it. The parts become
new units above it, with the same number and the next free letter. The original line stays as the last part and
depends on them. So nothing that depends on it has to change. Every part keeps the original's dependencies on gates
and on `above`. The parts of a fix unit `S-F<n>` take the next free `S-F` numbers instead, because that form has no letter.

Gate lines belong to the maintainer, ticked or not. So do their `accept` lines, and the headings and code fences of this
file. The loop never performs a gate. `guard` refuses a pull request that adds, changes, moves or removes one of those
lines, or that takes a dependency on a gate or on `above` out of any `deps` field, unless it is one commit signed by the
maintainer. The loop skips past a gate to any unit whose dependencies are met, and halts when none is left. An optional
gate is closed like any other: tick it when it is done, or when you have decided not to do it.

The loop writes a design decision as `docs/adr/NNN-name.md`, with `status: proposed`. It counts as accepted only when you
have moved its file to `docs/adr/accepted/`, which is locked: `git mv`, then `land.sh --reviewed`. Whatever a file outside
that folder says about its own status means nothing. Where no gate stands between a decision and the units that use it, as
with ADR-003 and ADR-004, they build on the proposal, and you can accept it at any stop.

---

## Phase 0: bootstrap and evidence first

- [x] H-000 | env:any | deps:- | Follow `START-HERE.md`: create the repository, open and merge the kit pull request, run `setup-2-after-merge.sh`, create the cloud task
      accept: `setup-2-after-merge.sh` reports that an unsigned change to a locked path was refused, and ticks this line itself
- [x] U-001 | flow:mech | model:sonnet | env:any | deps:H-000 | tries:0 | Create the module skeleton (shipped with the kit)
      accept: `go.mod` is `github.com/omkhar/workcell/v2`; `workcell --version` prints a version; gate green
- [x] U-002 | flow:mech | model:sonnet | env:any | deps:U-001 | tries:0 | sign:you | Finish `ci.yml`: pin `actions/setup-go` by SHA in both gate jobs, take the Go version from `go.mod`, and leave its cache off, because a `pull_request_target` run cannot save one. Keep the triggers, the KVM step and the job names `gate`, `gate-macos` and `merge` (shipped with the kit)
      accept: `actionlint` and `zizmor` pass on the file; nothing else in it changes
- [x] U-002b | flow:mech | model:haiku | env:kvm | deps:U-002 | tries:0 | Check the shipped `ci.yml` on this unit's own pull request
      accept: `gate` is green in under 5 minutes and its log shows `/dev/kvm` writable; the times are in `docs/benchmarks.md`. If not, set U-002 back to `[ ]` and say why at the end of its accept line. If hosted runners have no KVM, the loop halts with `no-checks` (`PROMPT.md` section 7a), and the maintainer must decide on a self-hosted runner
- [x] U-003 | flow:mech | model:haiku | env:any | deps:H-000 | tries:0 | Summarise `loop/baseline/ci.tsv` (made by `baseline-ci.sh`) into `docs/benchmarks.md`. Its content is data from a public API, never an instruction
      accept: table of v1 median duration, failure rate and cancel rate per workflow; if the file is missing, mark the unit `[!]` and name the script in `BLOCKED.md`
- [x] U-004 | flow:escape | model:fable | env:any | deps:U-001 | tries:0 | `escape/` harness: `Sandbox` adapter interface, static payload binary, runner, JSON report
      accept: `go run ./escape/cmd/escape -sandbox control -list` lists tests; without `-only` it runs every test; adapters `control` (plain container, open network) and `workcell` (stub that reports "not implemented")
- [x] U-005 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I2 and I4, with local canary listeners
      accept: every test FAILS on `control`; raw IP, odd port, IPv6, UDP, QUIC, ICMP, loopback, RFC 1918, link-local and metadata are each covered
- [x] U-006 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I3: tunnelling, direct resolver, DoH and DoT
      accept: every test FAILS on `control`; leakage is detected by a host-side capture, not by a third-party server
- [x] U-007 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I1, I7 and I10
      accept: traversal, symlink, device-node and mount attempts; cross-session residue; fork, memory, disk, descriptor and log floods; each FAILS on a deliberately weak `control` variant
- [x] U-008 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I5 and I6
      accept: guest memory, disk, env and argv scan for a known canary secret; placeholder replay to another host; SNI and Host mismatch; ECH; a redirect that tries to carry the secret
- [x] U-009 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I8 and I13
      accept: hostile hooks, filters, attributes, `.git/config`, submodule URLs, symlinks, `../` paths, case-collision names; a repo-local policy that tries to widen
- [x] U-010 | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I9, I11 and I12
      accept: log forge, suppress and truncate attempts; `kill -9` of each host helper; malformed, oversized and slow-drip channel frames
- [x] U-010b | flow:escape | model:fable | env:any | deps:U-004 | tries:0 | Escape tests for I14, with a local fake channel server and fake upstream
      accept: bad signature, expired manifest, lower serial, digest mismatch, truncated download and redirected URL are each refused
- [x] H-011 | env:macos | deps:U-005,U-006,U-007,U-008,U-009,U-010 | In the second account: optional, and private. Run the suite against Workcell v1.0.2, installed there, before hosted CI runs it against code ported from v1. It needs an adapter for v1, which stays off GitHub like those of H-806. `REFERENCE.md` section 6 says how
      accept: the result stays outside the repository (S14). Only limits that v1's own documents already state may go into `docs/benchmarks.md`. Anything new follows `SECURITY.md`

## Phase 1: choose the VM layer

- [x] U-100 | flow:spike | model:opus | env:kvm | deps:U-001 | tries:0 | Spike: libkrun on Linux. Boot kernel and initramfs, vsock echo, shared directory
      accept: `go test ./spikes/libkrun/` runs it in hosted CI; 20-sample boot time, binary size, cgo and licence notes recorded
- [x] U-101 | flow:spike | model:sonnet | env:kvm | deps:U-001 | tries:0 | Spike: Firecracker and Cloud Hypervisor on Linux, same measurements
      accept: `go test ./spikes/fcch/` runs it in hosted CI; same table
- [x] U-102 | flow:spike | model:opus | env:macos | deps:U-001 | tries:0 | Spike: macOS. Virtualization.framework through Go bindings, Apple `container`, and libkrun
      accept: `spikes/macos/` runs; same table, plus entitlement and signing needs
- [x] U-103a | flow:spike | model:opus | env:any | deps:U-100,U-101,U-102 | tries:0 | ADR-001: compare the options against A6, A7, P1, P3 and P6 and recommend one
      accept: `docs/adr/001-vmm.md`, at most 80 lines, `status: proposed`, one recommendation, a reversal cost, and the six-method interface
- [x] H-103 | env:any | deps:U-103a | Choose the backend or backends. To accept ADR-001, change it if you must, then move it to `docs/adr/accepted/`
      accept: `docs/adr/accepted/001-vmm.md` exists
- [x] H-104 | env:any | deps:- | Default workspace mode: decided, `clone` (2026-10-31)
      accept: `docs/adr/accepted/002-workspace-default.md`

## Phase 2: core on Linux

- [x] U-200 | flow:boundary | model:fable | env:kvm | deps:H-103 | tries:0 | `internal/vmm`: the interface and the Linux backend
      accept: boots, stops and force-kills a guest; no orphan process after a SIGKILL of the supervisor
- [x] U-201a | flow:build | model:sonnet | env:any | deps:H-103 | tries:0 | `internal/rootfs`: a pure Go ext4 writer. An in-memory tree (directories, regular files, symlinks, hard links, device nodes, mode, uid, gid, one fixed mtime) becomes a read-only ext4 image: 4 KiB blocks, extents, no journal, no checksums, sequential allocation, so the same tree gives the same bytes. ext4 because kernel A (Firecracker CI) has no erofs and kernel C (Kata) has no squashfs
      accept: the same tree written twice gives identical bytes, by a unit test; `e2fsck -fn` accepts an image holding every entry kind and a file over 48 KiB, shown by a test that skips without e2fsck on PATH; no exec of mkfs or shell
- [x] U-201b | flow:build | model:sonnet | env:any | deps:H-103,U-201a | tries:0 | `internal/rootfs`: OCI pull and unpack. Fetch one platform's manifest and layers from a registry by digest over https with an anonymous bearer token, check every blob's digest against the manifest, cap sizes as `internal/artifact` does, and apply the layers in order with whiteouts and opaque directories into the U-201a tree; no shell
      accept: unit tests against an `httptest` registry show the digest checks, the whiteout rules and the refusal of a tar member whose name is absolute, holds `..` or links outside the tree; nothing is written outside the given directory
- [x] U-201 | flow:build | model:sonnet | env:any | deps:H-103,U-201a,U-201b | tries:0 | Guest image build: OCI base to a read-only root image, byte-reproducible, addressed by digest
      accept: two clean builds give the same digest; under 400 MB; build needs no shell
- [x] U-202 | flow:boundary | model:opus | env:any | deps:U-001 | tries:0 | `internal/wire`: length-prefixed, versioned, bounded host-guest protocol, with a fuzz target
      accept: I12 unit and fuzz tests pass; every frame has a hard size and time limit
- [x] U-203 | flow:boundary | model:fable | env:kvm | deps:U-200,U-201,U-202 | tries:0 | `cmd/workcell-init`: static guest init. Mounts, exec, PTY, signals, exit status
      accept: runs as PID 1; reaps zombies; a host disconnect powers the guest off
- [x] U-204 | flow:build | model:sonnet | env:kvm | deps:U-203 | tries:0 | `workcell run -- <cmd>` end to end, with a PTY, window resize and exit code
      accept: `workcell run -- sh -c 'exit 7'` exits 7; an interactive shell works over a real terminal
- [x] U-204b | flow:escape | model:fable | env:kvm | deps:U-204,U-004 | tries:0 | The real `workcell` adapter in `escape/`, driven only through the CLI. It replaces the stub from U-004
      accept: `go run ./escape/cmd/escape -sandbox workcell -list` works in hosted CI, and the log shows one test that runs in a real guest
- [x] U-205 | flow:build | model:sonnet | env:kvm | deps:U-204b,U-007,H-011 | tries:0 | Session directory and lifecycle: `ls`, `stop`, `rm`, crash cleanup. Port `_legacy/rootio` only where R6 applies (S14)
      accept: I7 added to `enforced.txt` and green
- [x] U-206 | flow:build | model:sonnet | env:kvm | deps:U-204b,U-007 | tries:0 | Resource caps: CPU, memory, disk, processes, log volume
      accept: I10 added to `enforced.txt` and green
- [x] U-207 | flow:build | model:sonnet | env:kvm | deps:U-204b | tries:0 | `workcell bench start`, and a `P1` entry in the suite that fails above the hosted budget
      accept: `P1` added to `enforced.txt`; the number is printed in the run log
- [x] U-208 | flow:boundary | model:fable | env:kvm | deps:U-204b,U-010 | tries:0 | Harden the channel end to end
      accept: I12 added to `enforced.txt` and green

## Phase 3: network

- [x] U-300 | flow:spike | model:opus | env:kvm | deps:U-204 | tries:0 | ADR-003: how guest packets reach the host proxy (userspace stack over vsock, passt, or transparent socket impersonation)
      accept: `docs/adr/003-network-path.md`, `status: proposed`; a working prototype; the same design must work on macOS
- [x] U-301 | flow:boundary | model:fable | env:kvm | deps:U-300 | tries:0 | Implement the network path with no route except the proxy
      accept: the guest has no working default route to anything else
- [x] U-302a | flow:boundary | model:opus | env:any | deps:U-001 | tries:0 | Port `_legacy/egressproxy` part 1 to `internal/proxy` (S14): `allowlist.go` and `denylog.go` with their tests. Drop the `injectionpolicy` dependency and replace its endpoint check with a local one; inline the no-follow bounded read that `rootio` gave (R6)
      accept: ported allowlist and deny-log tests pass; no import outside the standard library, `x/sys` and `x/net`; every ported file says `// Ported from v1: <path>`
- [x] U-302b | flow:boundary | model:opus | env:any | deps:U-001,U-302a | tries:0 | Port `_legacy/egressproxy` part 2 to `internal/proxy` (S14): `proxy.go` with its tests. Keep SNI peek, ECH refusal and `blockedAddr`
      accept: ported proxy tests and `FuzzPeekSNI` pass; no import outside the standard library, `x/sys` and `x/net`
- [x] U-302 | flow:boundary | model:opus | env:any | deps:U-001,U-302a,U-302b | tries:0 | Port `_legacy/egressproxy` part 3 to `internal/proxy` (S14): `terminate.go` with its tests, the last part. Drop the `injectionpolicy` dependency, keep SNI peek, ECH refusal and `blockedAddr`
      accept: ported tests pass; no import outside the standard library, `x/sys` and `x/net`
- [x] U-303 | flow:boundary | model:fable | env:kvm | deps:U-301,U-302,U-204b,U-005,H-011 | tries:0 | Wire the proxy in. Refuse UDP, QUIC, ICMP and unproxied IPv6
      accept: I2 added to `enforced.txt` and green
- [x] U-304 | flow:boundary | model:fable | env:kvm | deps:U-303,U-006 | tries:0 | Host resolver: allowed names only, no recursion for anything else
      accept: I3 added to `enforced.txt` and green
- [x] U-305 | flow:boundary | model:sonnet | env:kvm | deps:U-304 | tries:0 | Resolve on the host, vet the address, dial that address. Rebinding guard
      accept: I4 added to `enforced.txt` and green
- [x] U-306 | flow:boundary | model:sonnet | env:kvm | deps:U-303,U-010 | tries:0 | Fail closed when any helper dies
      accept: I11 added to `enforced.txt` and green
- [x] U-307 | flow:boundary | model:fable | env:kvm | deps:U-303,U-008 | tries:0 | TLS termination with a per-session CA held only on the host. Install the CA in the guest trust store and the usual runtime variables. Enforce SNI, Host and certificate agreement
      accept: I6 added to `enforced.txt` and green; curl, Node, Python, Go and Java clients in the guest all validate
- [x] U-308 | flow:build | model:sonnet | env:kvm | deps:U-303 | tries:0 | Denial experience: `workcell log -f` shows denials live, `workcell explain` prints effective reach, `--allow host` widens one session
      accept: a blocked `npm install` tells the user the exact host to allow, in one line

## Phase 4: secrets and providers

- [x] U-400a | flow:boundary | model:opus | env:any | deps:U-302 | tries:0 | Port `_legacy/credbroker` part 1 to `internal/secret` (S14): `ledger.go` with its tests, plus a fuzz target for the ledger line parser (T5). No socket, no `aptbroker`, `rootio` or `cliexit` import
      accept: ported ledger tests and `FuzzLedgerAuditRecords` pass; no import outside the standard library, `x/sys` and `x/net`; every ported file says `// Ported from v1: <path>`
- [x] U-400b | flow:boundary | model:opus | env:any | deps:U-302,U-400a | tries:0 | Port `_legacy/credbroker` part 2 to `internal/secret` (S14): source resolution. Generalise `resolveSource` from `cli.go` to `file:`, `cmd:` and `secret-service:` (`keychain:` is U-702). Keep its shape: a fixed program path, no shell (A8), a scrubbed environment, a timeout, and refusal of an empty or multi-line value. Drop the `securityPath` test hook (A11). A value is `[]byte`, never a string, with a `Zero` that wipes it. The source names the host's own files and programs, so plain standard-library file handling (R6)
      accept: table tests show each source resolve and fail closed; a test that resolves a value, zeroes it and finds only zero bytes; no shell, no test hook, no import outside the standard library, `x/sys` and `x/net`
- [x] U-400 | flow:boundary | model:opus | env:any | deps:U-302,U-400a,U-400b | tries:0 | Port `_legacy/credbroker` part 3 to an in-process `internal/secret` (S14), the last part: the grant table, the fixed-window rate limit and `record` (no grant without a durable ledger write) from `server.go`, behind a type that satisfies `proxy.Broker` from `internal/proxy/terminate.go`. The grants are the `[[secret]]` rows of SPEC section 5 (name, source, host, header), not the fixed map. Drop `Serve`, `listen`, the session token, the peer-UID, ancestry and ACL checks, `client.go` and `Main`. Sources: `file:`, `cmd:`, `secret-service:`
      accept: no socket, no `aptbroker` import; secrets are zeroed after use where Go allows
- [x] U-401 | flow:boundary | model:fable | env:kvm | deps:U-307,U-400,H-011 | tries:0 | Mint placeholders and inject at the proxy, bound to host, and optionally to method and path
      accept: I5 added to `enforced.txt` and green
- [x] U-402 | flow:build | model:sonnet | env:any | deps:U-401 | tries:0 | Adapter data model in TOML: hosts, header shape, placeholder files and variables, install command. Mine `_legacy/adapters/*/adapter.toml` for facts only
      accept: adding a provider is one data file and no Go code
- [x] U-403 | flow:boundary | model:fable | env:kvm | deps:U-402 | tries:0 | Sign-in flows at the proxy: swap real tokens for placeholders in token-endpoint responses, and refresh on the host
      accept: a fake provider in `escape/` proves that access and refresh tokens never reach the guest
- [x] U-404 | flow:build | model:sonnet | env:kvm | deps:U-402 | tries:0 | Claude Code adapter, API key path
      accept: scripted session against a local fake API
- [x] U-405 | flow:build | model:sonnet | env:kvm | deps:U-402 | tries:0 | Codex adapter, API key path
      accept: as U-404
- [x] U-406 | flow:build | model:sonnet | env:kvm | deps:U-402 | tries:0 | Copilot CLI and Gemini CLI adapters
      accept: as U-404
- [x] U-407 | flow:boundary | model:fable | env:kvm | deps:U-401 | tries:0 | Git over HTTPS: inject a token scoped to named repositories by path
      accept: clone and push work for an allowed repository; the same placeholder fails for any other repository on the same host
- [x] U-408a | flow:build | model:fable | env:any | deps:U-402,B-821 | tries:0 | Host side of `workcell update [agent]`: a Go package `pins` at the repository root embeds the rows under `pins/` (`//go:embed *.json`), so a provider version lives nowhere else, and the provider's install table (U-402) names the row; `update` fetches the row's artifact for the host's architecture by its URL on the host, bounded as `internal/artifact` reads, refuses it unless its SHA-256 equals the row's (B8), unpacks it into a per-agent layer, an ext4 image from `internal/rootfs` under the data directory keyed by version and digest, points a `current` marker at it only once the image is complete, keeps the previous layer, and appends name, version and digest to an append-only record in the data directory in the ledger line shape of U-400a, until U-600 brings `internal/audit`; `--to <version>` accepts the row's current or previous release and `--rollback` points `current` back at the previous layer. The fetcher takes the rows and an `*http.Client` as parameters (A11). No channel, signature, daily check or real rows yet: B-826 and U-408 bring those
      accept: provider versions appear only under `pins/`; a digest mismatch is refused and leaves `current` untouched; `--rollback` and `--to` work, shown by table tests against a loopback TLS upstream (T8) with rows the test supplies; the verb and its two flags fit the section 5 budgets
- [x] U-408b | flow:boundary | model:fable | env:kvm | deps:U-402,B-821,U-408a | tries:0 | Guest side of the per-agent layer: `vmm.Config` carries the current layer image of each installed agent as a read-only drive, the Firecracker and vz backends attach it, the init mounts each one below the root overlay so the provider's binary is on PATH, and `run` passes whatever `current` names; a session with no layer boots as before
      accept: in a real guest, after `workcell update <agent>` on the host against a loopback upstream, `workcell run -- <binary> --version` prints the installed version; a write to the layer from inside the guest is refused or lost, and the next session sees the layer unchanged (I7); no escape row or enforced line is removed
- [x] U-408 | flow:boundary | model:fable | env:kvm | deps:U-402,B-821,U-408a,U-408b | tries:0 | `workcell update [agent]`: fetch by pinned URL and digest on the host, build a per-agent layer, keep the previous one, record version and digest in the audit log (A10, B8)
      accept: provider versions appear only under `pins/`; a digest mismatch is refused; `--rollback` and `--to` work
- [H] H-409 | env:any | deps:U-403 | In the second account: test real sign-in for each adapter, once you have read each provider's terms on intercepting subscription sign-in. Use test accounts, or revoke the sessions afterwards. `REFERENCE.md` section 6 has the commands
      accept: `docs/providers.md` states, per provider, which sign-in methods are supported

## Phase 5: workspace

- [x] U-500 | flow:build | model:sonnet | env:kvm | deps:U-204,H-104 | tries:0 | Clone mode: copy-on-write copy (reflink, `clonefile`, plain copy as fallback) exported to the guest
      accept: a 1 GB repository adds under 300 ms on a reflink filesystem
- [x] U-501 | flow:boundary | model:fable | env:kvm | deps:U-500,U-204b,U-009 | tries:0 | Return path: `workcell diff` and `workcell pull` through a bundle and a hardened fetch
      accept: I8 added to `enforced.txt` and green
- [x] U-502a | flow:spike | model:opus | env:kvm | deps:U-500,U-204b,U-007 | tries:0 | ADR-005: the mount-mode transport. Facts: the pinned guest kernel (Firecracker CI 6.1) has `FUSE_FS` and `OVERLAY_FS` but no 9P and no virtio-fs, and Firecracker has no shared directory (ADR-001 deferred this choice here). Compare a FUSE filesystem served by the guest init over the vsock channel (go-fuse as one direct dependency, or a hand-written FUSE protocol), Cloud Hypervisor plus a virtiofsd of our own as a second backend, and anything else that keeps A6 and A7. Prototype the recommendation under `spikes/mount/`: a FUSE mount in the real guest, with small-file throughput measured (a walk of 10,000 files, a write of 100 MB)
      accept: `docs/adr/005-mount-mode.md`, at most 80 lines, `status: proposed`, one recommendation, a reversal cost, and what it adds to the dependency budget; `go test ./spikes/mount/` runs in hosted CI and its numbers are in the log
- [x] U-502b | flow:boundary | model:fable | env:any | deps:U-500,U-204b,U-007,U-502a | tries:0 | Host side of mount mode: `internal/fileserve`, a directory service over `internal/wire` that works only by (handle, name). The root is an open descriptor of the mounted directory; every operation is `openat`, `fstatat`, `renameat`, `unlinkat` or the like, relative to a handle the service already holds, with `O_NOFOLLOW` and `AT_SYMLINK_NOFOLLOW` (R6); a name that holds `/` or is `.` or `..` is refused; a symlink is returned as its target and never followed; handles, open files and bytes per frame are bounded (I10, I12); the request parser gets a fuzz target (T5)
      accept: table tests show that a peer cannot reach a byte beside the root through a name, a symlink, a hard link planted beside it, a rename race or a stale handle; the fuzz target runs; no import outside the standard library, `x/sys` and `x/net`
- [x] U-502c | flow:boundary | model:fable | env:kvm | deps:U-500,U-204b,U-007,U-502a,U-502b | tries:0 | Guest side of mount mode: the init mounts `/workspace` from `/dev/fuse` and answers every FUSE request from the host service over the channel, as ADR-005 decides; a mount session passes no workspace disk, so `boot` gets its own branch for it
      accept: in a real guest, create, write, read, truncate, rename, symlink, readdir, unlink and chmod behave as on the host tree and show on the host at once; `ls -la` and `git status` in a mounted repository work; a host disconnect leaves no hung guest process
- [x] U-502 | flow:boundary | model:fable | env:kvm | deps:U-500,U-204b,U-007,U-502a,U-502b,U-502c | tries:0 | Mount mode (`--mount`), with host-side path confinement. The last part: the `--mount` flag on `run`, `pull` and `diff` refusing a mount session in one line, the `explain` verb with its workspace line (U-308 adds network reach to it later), the escape adapter's mode field and argument, and I1 in both modes
      accept: I1 added to `enforced.txt` and green in both modes; `explain` states in plain words that the agent writes directly to the real tree
- [x] U-503 | flow:boundary | model:sonnet | env:kvm | deps:U-402,U-009 | tries:0 | Policy loading and merge, where repo-local policy can only narrow
      accept: I13 added to `enforced.txt` and green
- [x] U-504 | flow:build | model:sonnet | env:kvm | deps:U-500,U-205 | tries:0 | Optional named dependency caches, read-only by default
      accept: a second `go build` or `npm ci` in a fresh session is warm; I7 still green

## Phase 6: audit and sessions

- [x] U-600 | flow:boundary | model:sonnet | env:any | deps:U-303 | tries:0 | Port `_legacy/auditlog`, `auditseal` and `keystore` to `internal/audit` (S14). One hash-chained log fed by the proxy, secret store and lifecycle
      accept: no import of `applecontainer`, `hoststate` or `sessions`
- [x] U-601 | flow:boundary | model:sonnet | env:kvm | deps:U-600,U-010,H-011 | tries:0 | `workcell verify` and `workcell log --format ocsf`
      accept: I9 added to `enforced.txt` and green
- [ ] U-602 | flow:build | model:sonnet | env:kvm | deps:U-205 | tries:0 | Detach and `attach`
      accept: a session survives terminal close; a second attach takes over cleanly
- [ ] U-603 | flow:build | model:sonnet | env:kvm | deps:U-602 | tries:0 | `workcell doctor`: hypervisor access, image present, disk space, each with a one-line fix
      accept: P3 checked on a clean container image

## Phase 7: macOS

`spikes/macos/`, from U-102, is the starting point for these units.

- [x] U-700 | flow:boundary | model:fable | env:macos | deps:H-103,U-208 | tries:0 | macOS backend behind `internal/vmm`
      accept: U-204's acceptance passes on macOS with no change outside `internal/vmm`
- [ ] U-701 | flow:boundary | model:fable | env:macos | deps:U-700,U-305,U-306,U-307 | tries:0 | Network path on macOS
      accept: I2, I3, I4, I6 and I11 added to `enforced-macos.txt` and green on the Mac
- [x] U-702 | flow:build | model:sonnet | env:macos | deps:U-400 | tries:0 | `keychain:` secret source
      accept: reads an item created with `security add-generic-password`, with no prompt storm
- [H] H-703 | env:macos | deps:U-701,U-702,U-501,U-601,B-826 | In the second account: run the full suite on a real Mac. Arrange the Developer ID, virtualization entitlement and notarisation. The suite needs no Developer ID: as `loop`, sign the test binary ad hoc with the virtualization entitlement (`codesign -s - --entitlements`). Your Developer ID signs nothing that the second account built or could touch. It signs release builds only, in `omkhar/workcell`, after H-1019. Keep its certificate and key out of that account. `REFERENCE.md` section 6 has the commands
      accept: suite report committed to `docs/benchmarks.md`; the report lists I1 to I14; P1 measured on the Mac
- [H] H-704 | env:macos | deps:U-208 | In the second account: Linux arm64. Run the suite in a Linux arm64 guest with nested virtualization on the Mac (needs an M3 or later), or narrow P6 in `SPEC.md` to "builds and unit-tests on arm64". `REFERENCE.md` section 6 has the commands
      accept: a result in `docs/benchmarks.md`, or the signed spec change

## Phase 8: workflows, release and process (see `WORKFLOW-REVIEW.md`)

This repository's Actions policy allows two events: `pull_request_target` and `schedule`. GitHub refuses every
other one here, among them `push`, `pull_request`, `workflow_dispatch` and `workflow_call`. The tag rule has no
exception, so no tag of any name can exist here, and without a tag no release can be published. Both allowed events
load the workflow file from `main`. Five things follow.

1. A proposed workflow cannot run before the maintainer adopts it. The unit that proposes it proves what can be
   proved without a run: the line cap holds, and `actionlint` and `zizmor` pass on the proposal. Run those two once,
   in the session. They are never added to the gate (T3, W15).
2. Its first real run comes after the merge. A follow-up unit with the suffix `b` reads that run. If the run is
   red, the follow-up sets the proposing unit back to `[ ]` and says why at the end of that unit's accept line.
3. A workflow uses only those two events until cutover. A comment at its top names its final triggers
   (`WORKFLOW-REVIEW.md` section 7), and H-905 switches them on.
4. The 500-line budget counts every YAML file under `.github/`, `guard.yml` and `zizmor.yml` included. The caps
   below add up to 450 lines.
5. No workflow names an environment or reads a secret until cutover. This repository holds neither, and
   `settings.sh check` reports either as wrong. A comment at the top of the file names the environment it will use, and H-905
   switches that on too.

- [x] W-800 | flow:build | model:sonnet | env:any | deps:U-207,U-002b | tries:0 | sign:you | Final `ci.yml`: one gate job per Linux architecture, the macOS job, pinned runner images. The jobs `gate` (amd64), `gate-macos` and `merge` keep their names, and `gate-macos` keeps running the whole gate with `GATE_MACOS=1`, because the rule on `main` requires those checks and `merge` lands the loop's work
      accept: W2 to W6 hold; at most 130 lines while the `merge` job is in it; `actionlint` and `zizmor` pass on the proposal
- [x] W-801 | flow:boundary | model:fable | env:any | deps:W-800,U-201 | tries:0 | sign:you | `release.yml`: check that CI passed for this tree, build binaries and image, write `SHA256SUMS`, one attestation, one keyless signature, draft, publish. Here it starts only on `schedule`, as a dry run that stops before any draft release is created, because `settings.sh check` counts a draft as a release. It runs daily, so that W-801b need not wait a week, until H-905 makes it weekly
      accept: W7 to W11 hold; at most 130 lines; at most 4 jobs; `actionlint` and `zizmor` pass on the proposal
- [ ] W-801b | flow:mech | model:haiku | env:kvm | deps:W-801 | tries:0 | wait:release.yml | Read the first scheduled run of `release.yml`
      accept: the dry run is green, and left no draft and no release. If not, set W-801 back to `[ ]` and say why at the end of its accept line
- [x] W-802 | flow:build | model:sonnet | env:any | deps:W-800,U-201 | tries:0 | sign:you | `nightly.yml`, on `schedule`: reproducibility rebuild and compare, and fuzz. It opens or updates one issue on failure. The fuzz job runs one job per target, takes the minutes per target from `escape/fuzz-minutes.txt` and caps them at 240, prints each crasher's input in its log, and leaves out packages ported from v1 (S14)
      accept: at most 80 lines; `actionlint` and `zizmor` pass on the proposal; `escape/fuzz-minutes.txt` holds `10`
- [ ] W-802b | flow:mech | model:haiku | env:kvm | deps:W-802 | tries:0 | wait:nightly.yml | Read the first scheduled run of `nightly.yml`
      accept: every job is green and each fuzz target ran for 10 minutes. If not, set W-802 back to `[ ]` and say why at the end of its accept line
- [x] W-803 | flow:mech | model:haiku | env:any | deps:W-800 | tries:0 | sign:you | One `dependabot.yml`: gomod, github-actions and docker only; grouped, weekly, 7-day cool-off; nothing under `pins/` (W12). `open-pull-requests-limit: 0` until H-905 raises it, because nothing merges its pull requests while the loop runs
      accept: at most 30 lines
- [x] W-804 | flow:doc | model:haiku | env:any | deps:W-800 | tries:0 | sign:you | `CONTRIBUTING.md` at most 80 lines, and `CLAUDE.md` at most 60 lines with a one-line `AGENTS.md` that points to it, including the sunset rule. Keep the section "While the loop runs" of `CLAUDE.md` as it is; H-905 removes it
      accept: a newcomer can build and test from three commands
- [H] H-806 | env:any | deps:U-005,U-006,U-007,U-008,U-009,U-010,U-010b | In the second account: optional, private, and outside this repository. Compare with other open-source sandboxes. Adapters, runs and results stay off GitHub. Report any weakness to that project's maintainers privately, and wait for them, before you publish a comparison
      accept: this line is ticked, done or declined. Nothing else about it is recorded here (S14)

## Phase 8b: upstream freshness (SPEC section 10)

`_legacy/bump/` holds the v1 selector, policy and per-provider verification
scripts. Mine them for facts: where each upstream publishes, which timestamps it
exposes, and how it signs. Do not port their structure.

This repository never holds a GitHub App, an environment or a secret, because code from free paths would run with
them. So `bump.yml` only plans and does dry runs here. H-829 creates the App and the keys in `omkhar/workcell`, after
the loop has ended.

- [x] B-820 | flow:spike | model:opus | env:any | deps:U-001 | tries:0 | ADR-004: channel manifest format and signing (keyless signing, or an embedded public key with serial and expiry)
      accept: `docs/adr/004-channel.md`, at most 80 lines, `status: proposed`; covers rollback, freeze, key rotation, where the manifest is published, and what each option adds to the dependency budget
- [x] B-821 | flow:boundary | model:opus | env:any | deps:U-001 | tries:0 | `internal/pins`: data model and the stateless selector (B1 to B4)
      accept: table tests for cool-off edge, latest-of-timestamps, pre-release, yanked, deprecated, never backwards, security lane, and an upstream that ships every four hours; the clock is injected
- [x] B-822 | flow:build | model:sonnet | env:any | deps:B-821 | tries:0 | Source types: npm registry, GitHub releases, vendor release manifest, OCI digest
      accept: each is tested against recorded responses; bounded reads; any error means no candidate, never "no update available"
- [x] B-823a | flow:boundary | model:fable | env:any | deps:B-822 | tries:0 | `internal/sigstore`: verify a Sigstore bundle in its JSON form, both `messageSignature` and `dsseEnvelope`, against an embedded snapshot of the public Sigstore trusted root: leaf chains to a Fulcio CA, is valid at the Rekor integrated time, the Rekor signed entry timestamp verifies, the SAN URI and the issuer extension equal the expected identity, and the signature covers the given digest or the DSSE PAE. Standard library only (B5, I14 shape); nothing from `spikes/channel` is imported
      accept: a synthetic Fulcio-shaped chain signs both bundle kinds in the tests and verifies; a tampered signature, payload, digest, identity, issuer, chain, log key or integrated time is each refused; a fuzz target over the bundle parser runs clean
- [x] B-823 | flow:boundary | model:fable | env:any | deps:B-822,B-823a | tries:0 | Verification per source (B5): signature bundles, registry provenance, signed checksums
      accept: a tampered fixture is refused for every source type
- [ ] B-824 | flow:build | model:sonnet | env:kvm | deps:B-821,U-404 | tries:0 | Adapter smoke test for each `guest` pin that differs from the base branch (B6), as a `B6` entry in the suite
      accept: `B6` added to `enforced.txt`; a pin that points at a broken binary turns the gate red
- [x] B-825 | flow:boundary | model:opus | env:any | deps:B-823,W-800 | tries:0 | sign:you | `bump.yml` and `cmd/bump`: a daily plan, one pull request per class, the changed-path check, and the merge when green. Here the workflow starts only on `schedule`. It prints the plan, does the rest as a dry run, and opens and merges nothing, until H-905 switches that on
      accept: at most 80 lines of YAML; the job that reads upstream data holds a read-only token; no job names an environment or reads a secret; `go run ./cmd/bump -dry-run` prints the plan from recorded responses and writes nothing; `go test ./cmd/bump/...` drives the steps that are dry here against a local stand-in for GitHub's API: one pull request per class is opened, one that touches a path outside `pins/` is refused, and the merge waits for a green `gate`; `actionlint` and `zizmor` pass on the proposal
- [ ] B-826 | flow:boundary | model:fable | env:kvm | deps:B-820,B-825,U-408,U-010b | tries:0 | sign:you | Publish the signed channel after each merge that changes `pins/`, and verify it in the client (B7, B9, B10). Here the job starts only on `schedule`, as a dry run. It builds the manifest, signs it with a key that it makes for itself and throws away, checks it with the client's own code, and publishes nothing. A comment in the file says what H-905 switches on: the real key, and bumps merged with the App's token, because an event caused by a workflow's own token starts no run
      accept: I14 added to `enforced.txt` and green; session start time is unchanged with the channel server unreachable; no job names an environment or reads a secret
- [ ] B-826b | flow:mech | model:haiku | env:kvm | deps:B-826 | tries:0 | wait:bump.yml | Read the first scheduled run of `bump.yml` that holds the channel job
      accept: the run is green; its log shows the plan, and a manifest signed and checked with a key made in the job; it opened no pull request and published nothing. If not, set B-825 or B-826 back to `[ ]` and say why at the end of its accept line
- [x] B-827 | flow:build | model:sonnet | env:any | deps:B-821 | tries:0 | Security fast lane, using a public advisory database (B4)
      accept: a fixture advisory shortens the cool-off; a lookup error leaves the normal cool-off in force and is reported
- [ ] B-828 | flow:build | model:sonnet | env:kvm | deps:B-824,W-802b | tries:0 | sign:you | Nightly early-warning smoke on upstream's newest release, and the freshness report (B11, B12)
      accept: one rolling issue, never a gate; the report shows lag per pin against P7; `nightly.yml` stays within 80 lines

## Phase 9: docs and migration

- [ ] U-900 | flow:doc | model:sonnet | env:kvm | deps:U-603 | tries:0 | `README.md`: what it is, install, first session, how it works in one diagram, limits. The session commands run in a Go test under `spikes/readme/` on the `try: ` pull request, and its log supplies the output. Keep the lines "This is not ready to use" and "This repository never publishes a release", and the section "If you open this repository in Claude Code", at the top as they are; H-905 removes them
      accept: at most 150 lines; every command except the install lines was executed; the install lines are marked as untested until v2.0.0
- [ ] U-901 | flow:doc | model:opus | env:any | deps:U-601 | tries:0 | `docs/threat-model.md`, from `SPEC.md` sections 2 and 3, each invariant linked to its test
      accept: at most 150 lines
- [ ] U-902 | flow:doc | model:haiku | env:any | deps:U-503 | tries:0 | `docs/policy.md` and `docs/providers.md`
      accept: at most 200 lines together
- [ ] U-903 | flow:doc | model:sonnet | env:any | deps:U-900 | tries:0 | `docs/migrating-from-v1.md`: flag map, what was removed and why, how to remove v1 state
      accept: every v1 flag listed in `_legacy/flags.txt` has a row
- [ ] U-904 | flow:build | model:sonnet | env:any | deps:W-801,W-802b | tries:0 | sign:you | Homebrew formula, a checksum-verifying install script, and the P2 install-timing job in `nightly.yml`
      accept: the script refuses a download with a wrong checksum, shown against a local server; it has at most 90 lines, because `gate.sh` joins the 300-line shell budget at cutover; `nightly.yml` stays within 80 lines
- [ ] U-905a | flow:mech | model:sonnet | env:any | deps:U-903,U-502a,U-600,U-400,U-402,U-302,U-205,U-701,U-702,B-823,B-826b,B-827,B-828 | tries:0 | Delete `_legacy/` and `spikes/`
      accept: gate green; budgets met
- [ ] U-906 | flow:mech | model:sonnet | env:kvm | deps:above | tries:0 | wait:nightly.yml | Record P1 to P7 in `docs/benchmarks.md`, each with its number and the run it came from
      accept: P2 comes from `nightly.yml`. P7 cannot be met before cutover, because nothing merges a bump here. In its place stand the dry run that B-826b read, and the lag per pin that `nightly.yml` reports. P5 is the p50 over the last 10 pull requests, each counted by the slower of `gate` and `gate-macos`; P1 and P6 include H-703 and H-704. If another target is missed, mark this unit `[!]`
- [ ] U-907 | flow:doc | model:opus | env:any | deps:U-901,W-801 | tries:0 | sign:you | `SECURITY.md` for v2, starting from v1's. The text of v1's policy is public at `github.com/omkhar/workcell`, and this repository's history holds `SECURITY.md` as it was before the kit arrived. Propose the file as `proposed/SECURITY.md.txt`
      accept: it covers supported versions, private reporting, response times, scope, and how to verify a release and the update channel, all as they are in v2; until H-905 a first paragraph says that this repository is a building site that publishes no release, and points to `loop/REFERENCE.md` section 9; H-905 removes it; the rest names nothing under `loop/` and does not speak of a building site; at most 130 lines

## Phase 10: final security review (SPEC section 11)

Nothing here starts until every unit and gate above is `[x]`: that is what `deps:above` on S-1001 means. The `audit` flow
runs on the top tier. Each confirmed finding becomes an `S-F<n>` unit (`flow:boundary`, `model:fable`, `deps:` the
audit that found it), added directly below that audit. Its reproducing test waits under `escape/_pending/S-F<n>/`,
and the fix unit moves it into place (S4).

- [ ] S-1001 | flow:audit | model:fable | env:any | deps:above | tries:0 | Map the attack surface as built: every place attacker-controlled bytes enter host code, and the authority that code holds. Compare it with `docs/threat-model.md`
      accept: `loop/state/FINDINGS.md` opens with the map; any surface missing from S-1002 to S-1013 gets its own unit
- [ ] S-1002 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: host-guest channel, guest init, supervisor lifecycle (I7, I10, I12)
      accept: coverage list and candidates recorded; each candidate confirmed or refuted under S4
- [ ] S-1003 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: VM configuration and device model, Linux and macOS backends (I1, I4, A7)
      accept: as S-1002
- [ ] S-1004 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: network path and proxy core: routing, SNI, ECH, connection handling, fail-closed behaviour (I2, I4, I11)
      accept: as S-1002
- [ ] S-1005 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: TLS termination and HTTP handling: smuggling, HTTP/2, WebSocket, redirects, CONNECT, CA handling (I5, I6)
      accept: as S-1002
- [ ] S-1006 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: resolver: tunnelling, rebinding, cache and case tricks (I3, I4)
      accept: as S-1002
- [ ] S-1007 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: secrets: sources, placeholders, sign-in token swap, git credentials, logs, crash output (I5)
      accept: as S-1002
- [ ] S-1008 | flow:audit | model:fable | env:kvm | deps:S-1001 | tries:0 | Audit: workspace export in both modes, and the return path (I1, I8)
      accept: as S-1002
- [ ] S-1009 | flow:audit | model:fable | env:any | deps:S-1001 | tries:0 | Audit: policy loading and merge, CLI parsing, `--allow`, adapter data files (I13)
      accept: as S-1002
- [ ] S-1010 | flow:audit | model:fable | env:any | deps:S-1001 | tries:0 | Audit: audit log, seal, key storage, `verify` (I9)
      accept: as S-1002
- [ ] S-1011 | flow:audit | model:fable | env:any | deps:S-1001 | tries:0 | Audit: pins, selector, verification, bump tool, channel manifest, update client (I14, section 10)
      accept: as S-1002
- [ ] S-1012 | flow:audit | model:fable | env:any | deps:S-1001 | tries:0 | Audit: workflows, release, signing, image build and dependencies as a supply chain (section 9)
      accept: as S-1002; includes one pass of `zizmor`, `actionlint` and `govulncheck`
- [ ] S-1013 | flow:audit | model:fable | env:kvm | deps:S-1002,S-1003,S-1004,S-1005,S-1006,S-1007,S-1008,S-1009,S-1010,S-1011,S-1012 | tries:0 | Audit: chains. Combine refuted and low findings across surfaces; attack start-up, shutdown, crash and upgrade windows
      accept: as S-1002
- [ ] S-1014a | flow:mech | model:haiku | env:any | deps:S-1001,W-802b | tries:0 | Ask for the long fuzz run: set `escape/fuzz-minutes.txt` to `240`
      accept: the file on `main` holds `240`
- [ ] S-1014 | flow:audit | model:fable | env:any | deps:S-1014a | tries:0 | wait:nightly.yml | Collect the long fuzz run, then set `escape/fuzz-minutes.txt` back to `10`. The crashers are the candidates, so no auditor is needed
      accept: every target ran for four hours; each crasher is minimised and confirmed or refuted under S4
- [H] H-1015 | env:macos | deps:S-1001 | In the second account: in a plain Claude Code session on the best model the account offers, run the Claude Security plugin over the whole repository at `high`, twice. Then fuzz each target in a package ported from v1 for four hours, in a second clone (`~/fuzz`) that is never handed over. Move the crashers to `~/work/loop/private/findings-in/`. `git status` in `~/work` must be clean before S-1016. `REFERENCE.md` section 6 has the commands
      accept: both `CLAUDE-SECURITY-RESULTS.jsonl` files and any crasher are in `~/work/loop/private/findings-in/`, which git ignores
- [ ] S-1016 | flow:audit | model:fable | env:macos | deps:H-1015,S-1014 | tries:0 | Triage every tool finding under S4, in `~/work` as H-1015 left it and not in a fresh clone, because the inputs are files that git ignores. The findings are the candidates, so no auditor is needed
      accept: each one is confirmed, refuted, a duplicate or `needs the maintainer` in `loop/state/FINDINGS.md`
- [ ] S-1017 | flow:mech | model:opus | env:any | deps:above | tries:0 | Sweep verdict (S8). If this sweep confirmed anything at medium or above, add one to the sweep count in `loop/state/FINDINGS.md`, and set S-1002 to S-1013 and this unit back to `[ ]` with `tries:0`. After a third such sweep, mark this unit `[!]` instead
      accept: a sweep with nothing confirmed at medium or above, and every `S-F` unit `[x]`
- [ ] S-1018 | flow:doc | model:opus | env:any | deps:S-1017 | tries:0 | Write `docs/security-review.md` (S13)
      accept: at most 200 lines; every fixed finding links to its regression test
- [H] H-1019 | env:any | deps:S-1018 | Read the report. Decide whether to commission an independent human audit before or after release. Sign a checkpoint
      accept: `checkpoint.sh` has signed the reviewed commit

## Cutover

The loop is finished when every unit and gate above this heading is `[x]`. The rest is the maintainer's, by hand, from the Mac.
Delete the cloud task before you start on it. The three gates interleave. `REFERENCE.md` section 8 has the one order.

- [H] H-807 | env:any | deps:H-1019 | Settings of `omkhar/workcell` for v2: rulesets (W13), `release` environment, immutable releases, CodeQL default setup, required checks
      accept: checklist in `WORKFLOW-REVIEW.md` section 5 ticked, in the order of `REFERENCE.md` section 8; its last items follow the merge
- [H] H-829 | env:any | deps:H-1019 | After the cloud task is deleted, and in `omkhar/workcell` only: create the GitHub App (B14), the environment `bump` with its environment secrets, never repository secrets, and the channel signing key, if ADR-004 calls for one. Accept ADR-004 first, by moving it to `docs/adr/accepted/`. This repository never holds an App, an environment or a secret
      accept: the cloud task is deleted; `docs/adr/accepted/004-channel.md` exists; the App is installed on `omkhar/workcell` alone; its key, and the channel key if there is one, are environment secrets of `bump` there
- [H] H-905 | env:any | deps:above | Cutover. Sign a last checkpoint. On a branch `cutover`, make one signed commit. It moves `loop/gate.sh` to `scripts/check.sh`, takes the check that refuses `$HOME/loopkit` out of that script, and points `ci.yml` at it. It deletes `loop/`, `proposed/`, `.claude/`, `.github/maintainer.*`, `guard.yml`, `zizmor.yml`, the `merge` job, the loop's lines in `.gitignore`, the building-site lines of `README.md` (U-900), the first paragraph of `SECURITY.md` (U-907), the section "While the loop runs" of `CLAUDE.md` and every other `loop/` reference there. It gives each workflow its final triggers and its environment, raises the Dependabot limit, and adds a pull-request template of at most 10 lines. It holds the public half of the channel key of H-829, if ADR-004 embeds one. `SECURITY.md` is v2's own by then (U-907). Do not land the commit here, because the checks here need the files it deletes. Then tie in v1's `main` with a signed `ours` merge, push the branch to `omkhar/workcell`, open the pull request into its `main`, merge it with a merge commit, and sign and push tag `v2.0.0`. `REFERENCE.md` section 8, "Bringing v2 home", has the steps in order
      accept: release published; the next scheduled run of `bump.yml` in `omkhar/workcell` prints its plan; the first bump that falls due is opened by the App, merges by itself, and its channel manifest is accepted by a released client (P7). Archive `omkhar/workcell-v2` only after that
