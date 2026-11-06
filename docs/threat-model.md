# Threat model

This page says who Workcell defends against, the fourteen promises it makes, and which test proves each one. The full
rules are in [`loop/SPEC.md`](../loop/SPEC.md), sections 2, 3 and 6.

To list every test and the invariant it proves (output cut short here):

```
$ go run ./escape/cmd/escape -sandbox control -list
I2	raw-ip-odd-port-tcp4
I2	ipv4-mapped-ipv6-tcp
I2	udp4-datagram
...
```

## The attacker

Workcell assumes all of these at once:

- Root inside the guest, with arbitrary native code execution.
- A malicious repository: hostile source, hooks, config, symlinks, submodules.
- Hostile model output and hostile MCP or tool responses.
- A network attacker who controls any host that is not on the allowlist.

## Out of scope

- Host root, and malware already running as the operator's own user.
- Hypervisor or CPU zero-days. The only mitigation is a minimal device model.
- Compromise of an allowlisted provider's own service.
- What a human later does with code they pulled out of a session.

A finding against one of these is parked, not fixed. Workcell's controls stand between the guest and the host, so
they cannot stop an attacker who already holds the host, the CPU or an allowed service.

## How an invariant is proven

- Each invariant is proven only by a black-box test in `escape/` that runs as root in a real VM (SPEC T1).
- Each test is first shown to fail against the `control` adapter, a plain container with open networking (SPEC T2).
- Every canary a test listens on is local to the test host; no probe goes to a third-party system (SPEC T8).

Every test row lives in [`escape/suite/tests.go`](../escape/suite/tests.go). The files linked below hold the probe the
guest runs and the judge that watches from the host. [`escape/enforced.txt`](../escape/enforced.txt) lists what the
Linux gate enforces today: I1 to I13. The macOS gate enforces I7, I8 and I12
([`escape/enforced-macos.txt`](../escape/enforced-macos.txt)).

## Invariants

**I1. Host files.** The guest cannot read or write any host path outside the session's own workspace export.
Tests: [`files.go`](../escape/suite/files.go), [`device.go`](../escape/suite/device.go). Rows `dotdot-traversal`,
`planted-symlink`, `bind-mount`, `open-by-handle`, `device-node`, `link-rename`, and each again in mount mode
(`mount-dotdot-traversal` and so on).

**I2. Egress.** The guest cannot open a connection to any destination the session policy does not name. This covers
raw IPs, any port, IPv6, UDP, QUIC and ICMP.
Tests: [`tests.go`](../escape/suite/tests.go), [`icmp_linux.go`](../escape/suite/icmp_linux.go),
[`relay.go`](../escape/suite/relay.go). Rows `raw-ip-odd-port-tcp4`, `ipv4-mapped-ipv6-tcp`, `udp4-datagram`,
`quic-initial`, `icmp-echo`, `allowed-port-raw-ip-tcp4`, `allowed-port-udp4`, `relay-header-tcp`,
`relay-header-udp`, `relay-header-bad-version`, `relay-header-bad-proto`, `relay-header-allowed-port`,
`relay-header-allowed-port-udp`.

**I3. DNS.** Guest DNS is answered only by the host resolver and only for allowed names. No query for any other name
leaves the host.
Tests: [`dnstests.go`](../escape/suite/dnstests.go), [`resolver.go`](../escape/suite/resolver.go). Rows
`direct-resolver-udp4`, `direct-resolver-tcp4`, `dot-tcp4`, `doh-post-tcp4`, `doh-get-tcp4`, `tunnel-txt-udp4`,
`resolver-answers-allowed`, `resolver-refuses-others`, `resolver-at-host-address`, `resolver-at-lan-address`,
`resolver-empty-policy`, `resolver-after-garbage`, `resolver-after-burst`.

**I4. Private addresses.** The guest cannot reach host loopback, the LAN, link-local or cloud metadata addresses, or
another session. Names are resolved on the host and the vetted address is the one dialled.
Tests: [`tests.go`](../escape/suite/tests.go), [`relay.go`](../escape/suite/relay.go),
[`rebind.go`](../escape/suite/rebind.go). Rows `host-loopback-tcp4`, `lan-rfc1918-tcp4`, `link-local-tcp4`,
`metadata-tcp4`, `relay-header-host-loopback`, `relay-header-metadata`, and the eight `rebind-*` rows.

**I5. Secrets.** Real credential bytes never exist in guest memory, disk, environment, arguments or logs. A
placeholder is useless at any destination other than the one it is bound to.
Tests: [`secrets.go`](../escape/suite/secrets.go), [`https.go`](../escape/suite/https.go),
[`signin.go`](../escape/suite/signin.go). Rows `secret-in-guest`, the four `placeholder-*` rows,
`redirect-carries-secret`, `repo-token-swapped`, `repo-token-elsewhere`, and the eight `signin-*` rows.

**I6. TLS termination.** On a terminated connection the TLS SNI, the HTTP Host or `:authority`, and the upstream
certificate all match one allowed name. Secrets are injected only on terminated connections.
Tests: [`https.go`](../escape/suite/https.go), [`terminate.go`](../escape/suite/terminate.go). Rows
`sni-host-mismatch-h1`, `sni-authority-mismatch-h2`, `ech-hidden-sni`, `terminated-session-leaf`,
`upstream-leaf-mismatch`.

**I7. Session isolation.** Nothing a session writes is visible to another session, and `workcell rm` leaves no disk
image, socket, process or mount behind.
Tests: [`files.go`](../escape/suite/files.go), [`layer.go`](../escape/suite/layer.go). Rows `cross-session-residue`,
`layer-read-only`.

**I8. Safe pull.** Bringing results back to the host never executes or obeys guest-controlled content: no hooks,
filters, config, attributes, submodule URLs, symlink or path traversal.
Tests: [`repo.go`](../escape/suite/repo.go), [`gitdir.go`](../escape/suite/gitdir.go). Rows `pull-runs-hook`,
`pull-obeys-git-config`, `pull-fetches-submodule`, `pull-dotdot-path`, `pull-through-symlink`, `pull-case-collision`,
`pull-writes-dotgit`.

**I9. Audit.** Every connection attempt, secret use and lifecycle event is recorded on the host. The guest cannot
suppress, forge or alter a record, and `workcell verify` detects any offline edit.
Tests: [`audit.go`](../escape/suite/audit.go). Rows `audit-forge-record`, `audit-suppress-record`,
`audit-truncate-record`, `audit-records-connection`, and the five `verify-*` rows.

**I10. Resource caps.** The guest cannot exhaust host CPU, memory, disk, file descriptors, processes or log volume.
Tests: [`floods.go`](../escape/suite/floods.go). Rows `fork-flood`, `memory-flood`, `disk-flood`, `descriptor-flood`,
`log-flood`, `cpu-flood`, `mount-disk-flood`.

**I11. Fail closed.** If the proxy, resolver or broker dies, the guest loses network access. It never gains any.
Tests: [`helpers.go`](../escape/suite/helpers.go). Rows `proxy-killed`, `resolver-killed`, `broker-killed`,
`proxy-killed-at-start`.

**I12. Hostile channel.** Malformed, oversized or hostile traffic on the host-guest channel cannot crash, hang or
confuse the host process.
Tests: [`channel.go`](../escape/suite/channel.go), [`relay.go`](../escape/suite/relay.go). Rows `relay-short-header`,
`relay-slow-header`, and the eight `channel-*` rows, such as `channel-oversized-frame`.

**I13. Policy only narrows.** Workspace content can only narrow policy. Widening needs user-level config or an
interactive approval on the host.
Tests: [`repo.go`](../escape/suite/repo.go). The ten `repo-policy-*` rows, such as `repo-policy-widens-allowlist`,
`repo-policy-rebinds-secret` and `repo-policy-lifts-memory-cap`.

**I14. Signed updates.** The client installs an upstream artifact only if its digest appears in a channel manifest
that has a valid signature, has not expired, and has a serial no lower than the last one seen.
Tests: [`update.go`](../escape/suite/update.go). The nine `update-*` rows, such as `update-wrong-key`,
`update-expired-manifest`, `update-lower-serial` and `update-digest-mismatch`.
The gate does not enforce I14 yet: it is not in `escape/enforced.txt`.
