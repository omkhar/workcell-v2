# Workcell v2: frozen specification

This file is the fixed point of the loop. The loop reads it every iteration and
may never edit it. Like everything outside `loop/free-paths.txt`, it is locked: a change
to it reaches `main` only if the maintainer read it and signed it with their own GPG key.

The folder `docs/adr/accepted/` is locked in the same way. The loop writes a design decision
as `docs/adr/NNN-name.md`, with `status: proposed`. It counts as accepted only when the
maintainer has moved its file to that folder. Whatever a file outside it says about its own
status means nothing.

If a unit cannot be completed without violating this file, the unit is blocked.
The spec does not bend to make a unit pass.

## 1. Goal

Be the best local sandbox for coding agents, measured by things anyone can
re-run:

| ID | Target | How it is measured |
|----|--------|--------------------|
| P1 | Warm session start p50 under 1.0 s on a developer machine, under 2.5 s on a hosted CI runner | `workcell bench start`, 20 samples |
| P2 | Install to first running session under 60 s on a clean machine | scripted in `nightly.yml` |
| P3 | No host dependency beyond the OS hypervisor (KVM or Virtualization.framework) | `workcell doctor` on a clean image |
| P4 | Every invariant in section 3 passes black-box, on a real VM, on every change | `escape/` suite in `ci.yml` |
| P5 | Pull-request feedback p50 under 10 minutes | Actions run data |
| P6 | macOS arm64 and Linux amd64 are launch hosts; Linux arm64 builds and passes the unit tests | `ci.yml` (`gate-arm64` for Linux arm64), and human gate H-703 |
| P7 | A new stable upstream release reaches users within its cool-off plus 24 hours (guest class) or plus 72 hours (trusted class), with no human action | freshness report in `nightly.yml` |

## 2. Attacker

Assume all of these at once:

- Root inside the guest, with arbitrary native code execution.
- A malicious repository: hostile source, hooks, config, symlinks, submodules.
- Hostile model output and hostile MCP or tool responses.
- A network attacker who controls any host that is not on the allowlist.

Out of scope, and findings against them are parked, not fixed:

- Host root, and malware already running as the operator's own user.
- Hypervisor or CPU zero-days. Mitigation is a minimal device model, nothing more.
- Compromise of an allowlisted provider's own service.
- What a human later does with code they pulled out of a session.

## 3. Invariants

Each invariant is one sentence, has one owner package, and is proven only by
`escape/` tests that run as root in a real guest.

| ID | Invariant |
|----|-----------|
| I1 | The guest cannot read or write any host path outside the session's own workspace export. |
| I2 | The guest cannot open a connection to any destination the session policy does not name. This covers raw IPs, any port, IPv6, UDP, QUIC and ICMP. |
| I3 | Guest DNS is answered only by the host resolver and only for allowed names. No query for any other name leaves the host. |
| I4 | The guest cannot reach host loopback, the LAN, link-local or cloud metadata addresses, or another session. Names are resolved on the host and the vetted address is the one dialled. |
| I5 | Real credential bytes never exist in guest memory, disk, environment, arguments or logs. A placeholder is useless at any destination other than the one it is bound to. |
| I6 | On a terminated connection the TLS SNI, the HTTP Host or `:authority`, and the upstream certificate all match one allowed name. Secrets are injected only on terminated connections. |
| I7 | Nothing a session writes is visible to another session, and `workcell rm` leaves no disk image, socket, process or mount behind. |
| I8 | Bringing results back to the host never executes or obeys guest-controlled content: no hooks, filters, config, attributes, submodule URLs, symlink or path traversal. |
| I9 | Every connection attempt, secret use and lifecycle event is recorded on the host. The guest cannot suppress, forge or alter a record, and `workcell verify` detects any offline edit. |
| I10 | The guest cannot exhaust host CPU, memory, disk, file descriptors, processes or log volume. |
| I11 | If the proxy, resolver or broker dies, the guest loses network access. It never gains any. |
| I12 | Malformed, oversized or hostile traffic on the host-guest channel cannot crash, hang or confuse the host process. |
| I13 | Workspace content can only narrow policy. Widening needs user-level config or an interactive approval on the host. |
| I14 | The client installs an upstream artifact only if its digest appears in a channel manifest that has a valid signature, has not expired, and has a serial no lower than the last one seen. |

## 4. Architecture rules

| ID | Rule |
|----|------|
| A1 | Nothing inside the guest is trusted or relied on for enforcement. No preload shims, wrappers, argument filters or path masks. The agent gets root in the guest. |
| A2 | One short-lived microVM per session. No shared VM, no shared firewall state. |
| A3 | The only network path out of the guest ends in a host-side userspace proxy. Default deny, allow by hostname. |
| A4 | Placeholder credentials are the only credential path. There is no mode that stages a real secret in the guest. |
| A5 | The default workspace is a copy-on-write clone. A live mount is an explicit, labelled option (`--mount`). Decided in ADR-002, which lies in `docs/adr/accepted/`. |
| A6 | One static Go binary on the host, one static Go init in the guest, one signed prebuilt guest image pulled by digest. |
| A7 | Do not write a VMM. The backend interface has at most six methods. Guest image, guest init, proxy, broker and audit are shared by every backend. |
| A8 | No shell on the trust path of a session. Shell exists only in CI glue and in the install script, and is capped by section 7. |
| A9 | No daemon. A per-session supervisor process owns the VM, proxy and log, and dies with the session. |
| A10 | Provider CLIs are guest content, not part of the trusted base. Their versions are data in `pins/`, are bumped automatically after a cool-off, reach users through a signed channel manifest that is independent of binary releases, and never block a release (section 10). |
| A11 | No test hooks, test-only environment variables or test branches in production code. Use interfaces. |

## 5. Product surface

Verbs, at most 14: `run`, `ls`, `attach`, `stop`, `rm`, `diff`, `pull`,
`explain`, `log`, `verify`, `secret`, `update`, `doctor`, `bench`.

At most 20 flags across all verbs. At most 12 `WORKCELL_*` environment
variables. There are no modes, profiles, tiers or assurance labels. `workcell
explain` prints exactly what a session can reach and which secret is bound to
which host, and that output is the whole assurance story.

One policy format:

```toml
# ~/.config/workcell/config.toml grants. A repo-local workcell.toml may only narrow (I13).
[network]
allow = ["api.anthropic.com", "github.com", "proxy.golang.org"]

[[secret]]
name   = "anthropic"
source = "keychain:workcell/anthropic"   # keychain: | secret-service: | file: | cmd:
host   = "api.anthropic.com"
header = "x-api-key"

[workspace]
mode = "clone"                            # clone | mount

[resources]
cpus = 4
memory = "4GiB"
disk = "20GiB"
```

## 6. Evidence rules

| ID | Rule |
|----|------|
| T1 | An invariant is proven only by a black-box `escape/` test against a real VM. |
| T2 | Every `escape/` test must first be shown to FAIL against the `control` adapter (a plain container with open networking). A test that cannot fail is deleted. |
| T3 | Forbidden: a test or check that reads this repository's own source, scripts, workflows or docs as text and asserts on the contents. The few checks inside `loop/gate.sh` are the only exception, and the loop cannot add to them. |
| T4 | Forbidden as gates: mutation score, coverage percentage, documentation-language lint, generated hash manifests of source files, hand-maintained file inventories. |
| T5 | Unit tests cover pure logic only: parsers, matchers, encoders. Table-driven. Any parser of guest-controlled bytes also gets a native Go fuzz target. |
| T6 | A bug fix ships with one regression test at the lowest level that reproduces it. |
| T7 | `escape/enforced.txt` (Linux) and `escape/enforced-macos.txt` list what the gate enforces. They hold invariant IDs, plus `P1` and `B6` once those checks exist. They only grow. |
| T8 | All canary endpoints are local to the test host. The suite never sends probe traffic to a third-party system. |

## 7. Size budgets

`loop/gate.sh` measures these with `wc -l`. `loop/`, `_legacy/`, `spikes/`, `proposed/` and
`.claude/` are excluded, and all of them are deleted at cutover.

| Budget | Limit |
|--------|-------|
| Product code (every non-test `.go` file outside `escape/`, and any C, C++, Objective-C or assembly source) | 15,000 lines |
| Test code (`*_test.go` and `escape/`) | 1.5 x product, plus 5,000 |
| Any single Go file | 800 lines |
| All shell | 300 lines |
| All workflow YAML (every YAML file under `.github/`) | 500 lines |
| All Markdown | 2,500 lines |
| Distinct `WORKCELL_*` variables | 12 |
| Direct Go module dependencies | 15 |
| `cmd/bump` plus `internal/pins`, non-test | 800 lines |
| Gate wall-clock, VM suite included | 15 minutes |

A unit that would break a budget must delete something first. Raising a budget
is a maintainer edit to this file.

## 8. Review rules

| ID | Rule |
|----|------|
| R1 | One review round per unit, then at most one fix round. There is no round three. |
| R2 | A finding is valid only if it names an invariant or target ID, an in-scope attacker from section 2, and concrete steps to reproduce. |
| R3 | Anything else goes to `loop/state/PARKED.md` in one line and is not acted on. |
| R4 | At most five findings per review, ranked. |
| R5 | A reviewer may not request a new validator, linter, document, abstraction or configuration option. |
| R6 | No-follow, descriptor-relative file handling is required only where the host reads or writes data the guest controlled. Elsewhere use the standard library plainly. |

## 9. Workflow rules

| ID | Rule |
|----|------|
| W1 | Four workflows: `ci.yml`, `release.yml`, `nightly.yml`, `bump.yml`. Enable CodeQL default setup in repository settings instead of a fifth. `guard.yml` exists only while the loop runs. |
| W2 | CI runs the same single command a developer runs locally (`loop/gate.sh`, which becomes `scripts/check.sh` at cutover). There is no local emulation of CI. |
| W3 | At most three required checks. A required check never reports success because it was skipped. |
| W4 | After cutover, cancel superseded runs on pull requests only, never on a protected branch. While the loop runs, cancel nothing: a check result belongs to a commit, so a run cancelled through one pull request can fail another. |
| W5 | Pin runner images and action SHAs alike. Nothing floats. |
| W6 | Each tool version is written in exactly one place. |
| W7 | A release reuses the CI result for the same commit. It does not repeat it. |
| W8 | A release or pull request never fails because of what a third party published that day. Drift is `bump.yml`'s job, not a gate. |
| W9 | The whole release path runs weekly as a dry run, so a tag is never its first execution. |
| W10 | One signature over `SHA256SUMS` and one attestation over the same checksums. |
| W11 | Only the signing job holds `id-token: write`, and only the publish job holds `contents: write`. |
| W12 | Every updatable path has exactly one updater: Dependabot for Go modules, actions and the base image, `cmd/bump` for `pins/`. Both have a cool-off and both auto-merge when green. |
| W13 | Branch rules describe what really happens. A rule that every merge bypasses is removed. |
| W14 | No git hook makes a network call. No hook is required to contribute. |
| W15 | Sunset rule: a new check, rule or instruction must either replace an existing one or cite a defect that escaped to a user. |

## 10. Upstream freshness rules

Automatic bumping is a product feature, not repository hygiene. It is judged by
P7: how quickly a safe new upstream release reaches a user.

While the loop runs, its repository holds no GitHub App, no environment and no secret,
because code from free paths would run with them. There `bump.yml` only plans and does dry
runs: it opens and merges no pull request, and it signs a test manifest with a key that the
job makes for itself and throws away. The App (B14) and the real channel key (B7) are
created in `omkhar/workcell` alone, at gate H-829, after the loop has ended.

| ID | Rule |
|----|------|
| B1 | Every upstream input is a data row in `pins/`: name, class, source type, version, per-architecture URL and SHA-256, and the upstream timestamps. |
| B2 | Two classes. `guest`: provider CLIs and anything that runs only inside the guest, cool-off 48 hours. `trusted`: Go modules, actions, VMM, guest kernel, base image and build tools, cool-off 7 days. |
| B3 | Selection is stateless: the newest stable release that is not a pre-release, not yanked and not deprecated, and whose age is at least the cool-off. Age counts from the latest timestamp upstream publishes for that release. A pin never moves backwards. |
| B4 | Security fast lane: when a published advisory affects the pinned version and a newer release fixes it, the `guest` cool-off drops to 12 hours and still auto-merges. A `trusted` bump opens at once, labelled `security`, and waits for the maintainer. |
| B5 | Verify before pinning: compute the digest from the downloaded artifact, and check upstream's own signature or provenance wherever one exists. A verification failure means no bump and one open issue. It is never a silent skip. |
| B6 | A bump pull request may change only `pins/` (or, for Dependabot, only lock and workflow pin lines). The workflow checks the changed paths. It auto-merges only when the gate is green, and for a changed `guest` pin the gate installs that exact artifact in a real guest, runs it, and drives a scripted session against a local fake API. |
| B7 | Delivery: each merge that changes `pins/` publishes a signed channel manifest with an increasing serial and a 14-day expiry. This does not need a binary release. |
| B8 | The client fetches artifacts from upstream by pinned URL and digest, on the host. The project does not redistribute provider binaries. |
| B9 | The client checks the channel at most daily, in the background, and never delays a session start. It applies an update at the next start, keeps the previous version, and rolls back by itself if the new one fails to run. |
| B10 | The user stays in control: `[update] channel = "stable"` or `"hold"`; `cooloff` may lengthen the project's cool-off and never shorten it; `workcell update --to <version>` and `--rollback`. |
| B11 | Early warning: `nightly.yml` runs the adapter smoke test against upstream's newest release whatever its age. It is never a gate. A failure opens or updates one issue, so a break is known before the cool-off ends. |
| B12 | Freshness is measured: `nightly.yml` prints, per pin, the pinned version, the newest eligible version and the lag. A missed P7 opens or updates its own issue, `nightly: P7 missed`, and does not make the run red, so `nightly: red` means a real failure. |
| B13 | `bump.yml` runs daily and opens at most one pull request per class, so an upstream that ships every few hours costs one bump a day. |
| B14 | The bot is a GitHub App with contents and pull-request write only. It has no workflow permission and cannot touch `.github/`. |
| B15 | Adding an upstream of a known source type is one data row and no code. |

## 11. Final security review rules

Phase 10 runs once every unit and gate above it in `loop/state/PLAN.md` is `[x]`. It is the last thing before cutover.

| ID | Rule |
|----|------|
| S1 | Code freeze. During Phase 10 only fixes for confirmed findings land. |
| S2 | The auditor, red team and verifier run on the top tier: Mythos where the account is verified for it, for example under Anthropic's Cyber Verification Program, otherwise Fable, then Opus. The order is a preference for the strongest model on offer. It is never a way round a safeguard: S11 holds on every model. |
| S3 | One attack surface per unit, in a fresh context. The auditor reads the whole surface, not a diff. |
| S4 | A finding is confirmed only by a reproducing test (an `escape/` test, a Go test or a fuzz crasher) that an independent verifier has failed to refute, by running it or, where it needs a VM, from its hosted CI log. The test fails before the fix and passes after it, and it stays in the suite. Between the audit and the fix it waits under `escape/_pending/S-F<n>/`, which Go does not compile. The fix unit moves it into place. |
| S5 | R1 (one round) and R4 (five findings) are suspended for the `audit` flow. R2, R3 and R5 still hold. |
| S6 | Severity. Critical or high: an in-scope attacker breaks an invariant. Medium: the same, but only with an extra precondition the attacker does not control. Low: hardening with no demonstrated break. |
| S7 | Every critical, high and medium finding is fixed before cutover. Low findings are listed in the report. |
| S8 | A sweep is one pass over every surface. Sweeps repeat until a whole sweep confirms nothing at medium or above, up to three sweeps. If the third sweep still confirms something at medium or above, the loop stops: that is a design problem for the maintainer, not another patch. |
| S9 | Each audit covers every lens: parsing and resources; logic and state; concurrency and check-to-use gaps; cryptography and identity; failure modes; downgrade, rollback and replay; interaction between surfaces. |
| S10 | Independent tools run as well: the Claude Security plugin at `high`, twice; `govulncheck`; one pass of `zizmor` and `actionlint` over the workflows; and four hours of fuzzing per target. Targets in packages ported from v1 are fuzzed on the Mac, in the second account, not in hosted CI (S14). All output is triaged under S4 like any other candidate. |
| S11 | If a model declines, or a safeguard re-runs a request on another model, log it and continue. Never rephrase a request to get around a refusal. |
| S12 | All testing stays on the Mac, inside the cloud session, inside the hosted CI runners, and on local canaries (T8). The cloud session and the hosted runners are lent to this project, not owned by it. Never probe or load their host, proxy, metadata service or neighbours. Every target is a process or address the test itself started. |
| S13 | The public report, `docs/security-review.md`, is at most 200 lines: commit, scope, method, coverage, findings fixed, residual risk. It states plainly that this was an AI-assisted review and not an independent human audit. |
| S14 | Moved to section 13, because it holds in every phase. |

## 12. Definition of done

- `escape/enforced.txt` lists I1 through I14 and the suite is green on Linux in
  hosted CI and on macOS at human gate H-703.
- P1 through P6 are met and recorded in `docs/benchmarks.md` (U-906). P7 is shown there by
  dry runs, because no bump merges before cutover.
- `_legacy/` is empty and removed.
- Every unit and gate above the heading `## Cutover` in `loop/state/PLAN.md` is `[x]`, Phase 10 included.
- The maintainer performs H-807, H-829 and H-905, the cutover.

## 13. Disclosure rule, in every phase

S14. This repository is public, and so is everything around it: pull requests, issues, branch names, commit
messages and CI logs. v1 is released and in use. Some v2 code is ported from it.

- A weakness that also affects released v1 code, or someone else's project, is never written to any public place
  until it is fixed there or disclosed. A weakness is a defect that an attacker from section 2 could use.
- A weakness in code ported from `_legacy/` is presumed to affect released v1.
- Every ported file says where it came from, in a comment below its licence header: `// Ported from v1: <path>`. So
  the origin is still known after `_legacy/` is deleted.
- Whoever finds such a weakness stops. No test, fix, comment, title or branch name that shows it is pushed, and
  nothing more about it runs in hosted CI.
- The public record is the unit's ID and the words `needs the maintainer, see the run's transcript`, and nothing else.
  The halt reason is `needs-you`. A unit that needs a credential, a purchase or a legal reading leaves the same
  record, so the record does not say that a weakness was found.
- The detail stays in the run's own transcript (cloud), or in `loop/private/`, which git ignores (Mac). The loop
  halts for the maintainer, who follows `SECURITY.md`.
