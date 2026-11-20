# Findings

Phase 10 record (SPEC section 11). Sweep count: 1. One section per audit unit: the attack-surface map (S-1001),
then each audit's coverage list and candidates, each confirmed, refuted or downgraded under S4.

## S-1001: attack-surface map, as built at main 30ea6e2

Attackers (SPEC section 2): G guest root, R malicious repository, M hostile model or tool output, N network attacker
off the allowlist. U (the operator) and K (the channel key holder) are out of scope and appear only where their bytes
mix with in-scope ones. Authority: SUP is the per-session supervisor `workcell run` (the user's uid; owns the VM, proxy,
resolver, broker, audit log, data dir, cwd and terminal); CLI is another verb as the user; INIT is guest PID 1
(untrusted, A1); RUN is the hosted CI runner. "ported" marks a handling file that carries `// Ported from v1`.

| # | surface | entry (path:line, fn) | att | first parser or handler | authority | inv | ported | unit | fuzz | escape rows |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | channel frames on the init's vsock conn (port 5000) | cmd/workcell/run_vm.go:445 output, internal/wire/wire.go:71 ReadFrame | G | 6 B header, 64 KiB cap, 5 s/frame; guest.DecodeAck/DecodeExit | SUP: exit code, terminal bytes, session end | I12 I10 | no | S-1002 | FuzzReadFrame, guest FuzzDecode | channel-* (8), relay-short/slow-header |
| 2 | Exit{Err} as the guest's first frame drives installer.fail | run_vm.go:72 run, :481 exitResult, cmd/workcell/update.go:283 fail | G (via R hooks, M) | DecodeExit kind 2 | SUP writes layers/<agent>/{failed,current,previous}, deletes the set-aside image, appends updates.log | I12, B9/B10 | no | S-1002 (+S-1011, S-1013) | guest FuzzDecode | channel-forged-exit-text runs sh, so the side effect was untested; candidate C1 below |
| 3 | Stdout/Stderr frames to the user's terminal | run_vm.go:591 client | G M | none, passed through (PTY by design) | SUP | none | no | S-1002 | n/a | channel rows check only the host's own stderr |
| 4 | later connections to port 5000 | run_vm.go:379 once, internal/vmm/vz/vz.go:333 (backlog 16), firecracker UDS | G | accept then close | SUP | I12 I10 | no | S-1002 | n/a | channel-connect-storm, channel-connect-flood |
| 5 | pull stream (Entry/Data/Exit) | cmd/workcell/pull_vm.go:196 manifest, :236 data, :257 end; cmd/workcell/pull.go:33 add, :65 checkPath, :93 fold | G R | guest.DecodeEntry; path judge; MaxEntries 1M, MaxNames 64 MiB, size <= image | CLI pull/diff: openat2 RESOLVE_BENEATH+NO_SYMLINKS (linux), O_NOFOLLOW_ANY (darwin); unlinks non-dirs, writes files and symlinks into dest | I8 I12 I10 | no | S-1008 | guest FuzzDecode; checkPath/fold/add have none (T5) | pull-* (7) |
| 6 | guest console bytes and the VMM's stderr | run_vm.go:646 tail.Write (4 KiB), :664 lastLines | G | sanitiser | SUP prints on boot failure | I10 | no | S-1002 | none | none |
| 7 | VMM process exit, vz state | run_vm.go:425 accept; firecracker.go:130 Wait; vz.go:153 Wait | G | fixed strings | SUP | I12 | no | S-1002, S-1003 | n/a | proxy-killed-at-start |
| 8 | relay header, one per guest connection (port 5001) | cmd/workcell/relay.go:142 stream; internal/relay/relay.go:42 Decode; 1024 slots, 5 s | G | 20 B header; port selects adapter; address never dialled | SUP | I2 I4 I12 I10 | no | S-1004 | relay FuzzDecode | relay-header-* (8), relay-short/slow-header |
| 9 | DNS query frame on a UDP-53 header | relay.go:171 exchange; relay.ReadFrame; internal/resolver/resolver.go:52 Answer | G | 2 B length frame; one question, plain labels, 253 B | SUP answers from policy; refusals to the audit log | I3 I12 I9 | no | S-1006 (+S-1010) | relay FuzzReadFrame, resolver FuzzAnswer | resolver-* (7), direct-resolver-*, dot-tcp4, doh-*, tunnel-txt-udp4 |
| 10 | TCP stream to a forward port (not 443) | internal/proxy/proxy.go:157 handle, :184 route, :209 connect, :281 splice | G, N (upstream bytes) | none: raw splice | SUP dials the vetted IP; audit line | I2 I4 I9 I11 | yes | S-1004 | n/a | allowed-port-raw-ip-tcp4, relay-header-allowed-port, rebind-*-forward |
| 11 | TLS ClientHello on 443 | proxy.go:263 peekSNI (crypto/tls, 16 KiB since B-835, 10 s); :199 case and ECH check | G | crypto/tls ClientHello parser | SUP | I2 I6 I12 | yes | S-1004 | FuzzPeekSNI | sni-host-mismatch-h1, sni-authority-mismatch-h2, ech-hidden-sni, rebind-*-sni |
| 12 | terminated HTTP/1.1 request from the guest | internal/proxy/terminate.go:370 serveTerminated (tls.Server leaf, net/http, ReadHeaderTimeout 10 s, ReverseProxy Rewrite); :358 sameHost, :457 placeholderForm, :484 basicDecode, :125 admits, :496 carriesPlaceholder; internal/proxy/signin.go:69 tokenEndpoint, :91 tokenRequest (256 KiB) | G M | net/http parser; header and placeholder judges | SUP injects the real secret via broker.Lookup (internal/secret/broker.go:95); strips X-Forwarded-*; refuses TRACE/CONNECT; Upgrade passes raw bytes after the check | I5 I6 I9 I10 | terminate.go yes, signin.go no | S-1005 (+S-1007) | FuzzCarriesPlaceholder, FuzzSwapRefresh, FuzzHide | placeholder-* (4), repo-token-* (2), signin-* (8), redirect-carries-secret, terminated-session-leaf |
| 13 | upstream TLS cert and HTTP response from an allowed host | terminate.go:279 transport (system roots + SSL_CERT_FILE, TLS 1.2+, ServerName=host, h2 off, no proxy env); signin.go:154 tokenResponse, :176 readToken (gzip), :203 learn, :238 hide | N (MITM) | crypto/x509; net/http response parser; token JSON | SUP relays the body unbounded; rewrites token answers | I6 I5 | yes/no | S-1005 | FuzzHide | upstream-leaf-mismatch, signin-gzip, signin-chunked, signin-error-echo |
| 14 | host DNS answers for allowed names | proxy.go:209 connect, net.DefaultResolver, :62 blockedAddr | N (LAN DNS) | netip classification, blocked prefixes | SUP dials one vetted address, 30 s budget | I4 | yes | S-1006 | none | rebind-* (8) |
| 15 | FUSE requests in mount mode (port 5002) | internal/fileserve/serve_linux.go:152 Serve, codec.go:162 parse, ops_linux.go:20 op; maxFDs 4096, maxNodes 128K, 16 workers | G | FUSE 7.37 decoder; one component, 255 B | SUP holds the export dir fd; *at calls O_NOFOLLOW; ESTALE re-check; EPERM chown | I1 I10 I12 I7 | no | S-1008 | FuzzRequest | mount-* (6), mount-disk-flood |
| 16 | repository tree exported in clone mode | internal/workspace/workspace.go:35 Export (fd walk, Readlinkat, hard links; FIFO and device skipped); internal/rootfs/ext4file.go:94 openSource (dev/ino/size re-check) | R | directory walk; ext4 writer | SUP reads cwd, writes sessions/<id>/workspace.ext4 | I1 I10 | no | S-1008 | none | planted-symlink indirectly; no row for hostile export shapes (FIFO, device, link farms, name limits) |
| 17 | repo-local workcell.toml | cmd/workcell/policy.go:53 loadPolicy; internal/policy/policy.go:96 ReadRepo (O_NOFOLLOW, regular, 1 MiB), :173 Parse, :133 Narrow | R | own TOML subset | SUP before boot; CLI explain | I13 | no | S-1009 | FuzzParse | repo-policy-* (10) |
| 18 | guest-written ext4 images reattached later: workspace.ext4 (pull boots a VM), caches/<name>.ext4 with --cache NAME:rw (shared across sessions and repos, flock) | cmd/workcell/cache_vm.go:26 openCaches, run_vm.go:291 Config.Caches, firecracker.go:231, vz.go:261 | G (prior session) | none on the host: never mounted or parsed there | SUP attaches it as a drive to the next guest | I7 (operator opt-in), I1 | no | S-1003, S-1013 (chain) | n/a | layer-read-only covers layers only; none for caches |
| 19 | git metadata the guest writes | returns only through row 5; checkPath refuses .git components; the host runs no git | G R | pull judge | CLI pull | I8 | no | S-1008 | none | pull-runs-hook, pull-obeys-git-config, pull-fetches-submodule, pull-writes-dotgit |
| 20 | memory and CPU pressure | firecracker.go:216 machineConfig, vz.go:231; caps from cmd/workcell/caps.go:78 parseRun | G | VMM enforces | SUP | I10 | no | S-1003 | n/a | memory-flood, cpu-flood, fork-flood |
| 21 | disk pressure | workspace.Export free = --disk (run_vm.go:250); fileserve grow (serve_linux.go:116); cache image free | G | n/a | SUP | I10 | no | S-1003, S-1008 | n/a | disk-flood, mount-disk-flood |
| 22 | descriptor and connection pressure | relay.go:30 maxStreams 1024; proxy.go:33 maxConns 1024, :140 shed and lost counters; fileserve maxFDs; vz backlog 16 | G | n/a | SUP | I10 I12 | proxy.go yes | S-1004, S-1002 | n/a | descriptor-flood, channel-connect-flood, relay-* |
| 23 | log volume | internal/audit/audit.go:35 SoftLimit 8 MiB, HardLimit 16 MiB, :119 append (Note not fsynced, Record fsynced); tail 4 KiB; broker deny window | G | n/a | SUP | I10 I9 | lines.go yes | S-1010 | FuzzEachLine | log-flood, audit-* |
| 24 | secret-source program spawned per guest request | internal/secret/source.go:101 run (fixed paths, scrubbed env, 2 min); broker rate 300/min (broker.go:19) | G (timing, rate); U (config) | n/a | SUP forks secret-tool, security or the user's cmd: program | I10 I5 | yes | S-1007 | none | none for the rate limit; secret-in-guest, placeholder-*, signin-* for values |
| 25 | audit.log, audit.seal, audit.key on disk (offline edit; guest-chosen fields inside) | audit.go:213 Verify, :255 ParseLine, :273 SafeHost; internal/audit/key.go:22 LoadKey; cmd/workcell/log.go:117 feed, :143 denyMessage; cmd/workcell/ocsf.go:57 | offline editor; G (fields) | strict JSON line reader, 16 KiB/line | CLI log/verify | I9 | lines.go yes | S-1010 | FuzzEachLine; feed, denyMessage, ocsfLine have none (T5) | verify-* (5), audit-* (3), audit-records-connection |
| 26 | session directory state: lock (pid), repo, vmm (tmp paths), attach socket | cmd/workcell/session.go:80 supervisor, :136 removeSession (Lstat, IsAbs, wc prefix), :189 stopSession (flock-gated kill); run_vm.go:613 attach | host-written | n/a | CLI rm/stop/attach/ls; RemoveAll of listed tmp dirs; kill(pid) | I7 | no | S-1002 | n/a | cross-session-residue; none for rm/stop/attach |
| 27 | layers/<agent>/{current,previous,failed}, caches/*.lock, channel.{serial,day,next}, updates.log | update.go:455 marker, :461 writeMarker, :233 daily, :251 apply; cmd/workcell/layer.go:20 findLayers | host-written; row 2 lets G drive them | n/a | SUP, CLI | I14 I7 | no | S-1011 | n/a | update-daily-* (3), layer-read-only |
| 28 | channel.json | update.go:201 manifest; internal/artifact/verify.go:242 Fetch (64 KiB, no redirect); internal/channel/channel.go:111 Verify (strict envelope, ed25519 over PAE, serial, skew, expiry, sha and https per pin; Pin.Version unconstrained and used by update.go:172 in a file name) | N; K out of scope | DSSE and JSON decoder | CLI update; SUP startup goroutine writes <data> | I14 | no | S-1011 | FuzzVerify | update-* (12) |
| 29 | provider artifact download | update.go:337 fetch; artifact.Fetch (512 MiB; pins.Redirect https only, 3 hops); sha256; :369 unpack (rootfs.Apply tar and gzip, 1 GiB, or a bare file to bin/<binary> 0755); WriteExt4File | N | gzip, tar, ext4 writer | CLI writes layers/<agent>/<version>-<sha>.ext4 (read-only drive) | I14 B8 | no | S-1011 | FuzzLayer, FuzzTarMember | update-digest-mismatch, -truncated, -redirected, -plain-http; layer-read-only; pin-smoke-* (B6) |
| 30 | [update] table (channel URL, ca file, key, cooloff) | update.go:101 newInstaller; policy.go:222 updateTable | U | TOML subset | CLI | I14 | no | S-1011 | FuzzParse | update-* |
| 31 | OCI registry answers (base image build) | internal/rootfs/oci.go:82 Pull (manifest 64 KiB by digest, blobs 512 MiB by digest, 128 layers, raw 2 GiB, Bearer realm https, token to the registry only); layer.go:55 applyLayer (no .., whiteouts, hardlinks); ext4.go WriteExt4 (400 MiB); cmd/mkimage/main.go:44 | N | JSON, gzip, tar | RUN (release build, nightly repro), developer, escape Prepare | A6, section 9 | no | S-1012 | FuzzLayer | none |
| 32 | upstream listings for cmd/bump (npm packument 64 MiB, GitHub releases JSON, vendor latest and manifest.json, OCI tags and manifests, WWW-Authenticate) | internal/pins/sources.go:35 Candidates, :106 BearerParams, :166 Redirect; internal/pins/pins.go:129 Select | N, hostile upstream | encoding/json; BearerParams; semver and date parse | RUN: bump.yml dry run; nightly -newest rewrites pins/*.json in the runner tree then runs the B6 smoke; later the App token | B3 B5 B13 | no | S-1011 | none for sources (table tests only) | pin-smoke-* |
| 33 | OSV advisory answers | internal/advisory/advisory.go:61 Lookup (4 MiB, 8 pages, https, no redirects), :134 match | N | encoding/json | RUN: a crafted answer shortens the guest cool-off to 12 h or makes a trusted bump wait | B4 | no | S-1011 | FuzzAnswer | none |
| 34 | Sigstore bundles, npm attestations, tar members | internal/artifact/verify.go:56 Verify, :305 tarMember; internal/sigstore/verify.go:132 Verify, root.go:75 ParseRoot (embedded trusted root) | N | protobuf JSON, x509, DSSE, Rekor SET | RUN | B5 I14 | no | S-1011, S-1012 | FuzzTarMember, FuzzProvenance, FuzzParse | none |
| 35 | GitHub REST answers to cmd/bump (pulls, files, check-runs, Link, refs) | internal/bump/github.go:69 do (8 MiB), :101 list (next within the API root), :138 FilesOK, :154 Green, :123 class | N (API path); hostile PR content | encoding/json | RUN: merges a bump PR when live (B6) | B6 B14 | no | S-1011 | none (table tests) | none |
| 36 | CI workflow steps with repository content as input | ci.yml:25-48 (pull_request_target checks out the PR head and runs its loop/gate.sh with contents: read and sudo); guard.yml:27-40 (main's guard over PR objects, gpg import, awk filters); release.yml (sha256sum, cosign, attest, release with contents: write); nightly.yml (repro, fuzz matrix from go test -list through jq, bump -newest, escape -only B6, issue job with issues: write); bump.yml (dry run, throwaway key) | R (fork PR; the protection is an interaction limit collaborators_only that expires after six months, loop/settings.sh:42); N (upstreams); M (tool output in shell) | bash, awk, jq, gh | RUN with the scopes named | section 9, S12 | no | S-1012 | n/a | none |
| 37 | scripts/install.sh | scripts/install.sh:41-51: curl SHA256SUMS and asset from INSTALL_URL, sha256 -c, runs --version, mv into INSTALL_DIR; no signature check in the script | N (TLS); release compromise out of scope | sh | user shell | P2, section 9 | no | S-1012 | n/a | spikes/install (nightly, local server) |
| 38 | Go module dependencies (vz v3.8.0, purego, x/sys; indirect go-infinity-channel, x/mod); Dependabot limit 0 | go.mod; .github/dependabot.yml | N (supply chain) | n/a | build | A6 W12 | no | S-1012 | n/a | none |
| 39 | CLI arguments | caps.go:78 parseRun (--cpus, --memory, --disk; --allow judged by policy.go:155; --cache regex cache.go:21; command argv forwarded to guest Exec); session.go:38 validID; update.go:54 flags (--to matched against the manifest); log.go:30; main.go:36 verb map | U | flag, regexp | CLI | I13 I10 | no | S-1009 | none | none |
| 40 | environment read by the host | cmd/workcell/data.go:19 XDG_CONFIG_HOME, XDG_DATA_HOME, HOME; run_vm.go:140 TERM (into the guest env); terminate.go:274 SSL_CERT_FILE (unreadable file refuses termination); source.go:107 HOME, DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR to secret programs; TMPDIR via MkdirTemp; HTTP(S)_PROXY honoured by http.DefaultTransport in update, bump and mkimage only | U | n/a | CLI, SUP | I5 I6 | source.go, terminate.go yes | S-1009, S-1007, S-1005, S-1011 | n/a | none |
| 41 | user config.toml and embedded provider TOML (internal/provider/*.toml) | policy.go:77 Read; cmd/workcell/policy.go:113 bindings, :155 allowlist; internal/provider/provider.go:73 Load, :97 parse | U, build time | own TOML subset | CLI, SUP | I13 I5 | no | S-1009 | FuzzParse | repo-policy-* (narrowing only) |
| 42 | secret sources file:, cmd:, secret-service:, keychain: | source.go:37 Resolve (absolute paths, 64 KiB, one line, scrubbed env, stderr never echoed), called per request by broker.go:105 release (grant by host and header; ledger record before release) | U config; G drives timing | n/a | SUP reads the value into memory per use, clears after the swap | I5 I9 | yes | S-1007 | none | secret-in-guest, placeholder-*, signin-* |
| 43 | guest init: what it takes from the host, what flows back | takes the kernel cmdline (cmd/workcell-init/root.go: root=, workcell.workspace=, .mount=, .layer=, .cache=, .disk=, .ports=), Exec JSON (main.go:179: argv, env, dir, pty, rows and cols, CA 16 KiB to internal/guest/trust.go:50 WriteTrust), Stdin, Resize, Signal and Pull frames, FUSE replies written raw to /dev/fuse (mount.go:77); sends Stdout, Stderr, Exit, Ack (exec.go), Entry, Data, Exit on pull (pull.go, openat2 RESOLVE_BENEATH), FUSE requests, relay streams with getsockname as destination (net.go:136), DNS frames (net.go:169), console | G | n/a | INIT (root in the guest). Host reliance: none for enforcement; liveness only (Exit ends the session); the first-frame heuristic (row 2); Ack flow control (a guest that never Acks blocks run_vm.go:523 and so the attach client's input relay: a host-side stall only); unix.Sync before Exit for the pull reads | A1 I12 | no | S-1002 | guest FuzzDecode | channel-*, pull-*, relay-*, mount-* |

Comparison with docs/threat-model.md. Named there with an invariant and test rows, all of which exist in
escape/suite/tests.go: I1 (rows 5, 15, 16 indirectly), I2 (8, 10, 11), I3 (9), I4 (10, 11, 14), I5 (12, 13, 42),
I6 (11, 12, 13), I7 (18 layers only, 26), I8 (5, 19), I9 (23, 25), I10 (20 to 23), I11 (7, 10), I12 (1, 4, 8),
I13 (17), I14 (27 to 29). Not named there, with no invariant text and no row: 2 (first-frame rollback), 3 (terminal
output), 6 (console tail), 16 as a surface of its own (export walk of a hostile repository), 18 (caches), 24 (a host
process spawned per guest request), 26 (rm, stop and attach state), 31 to 38 (image build, bump, OSV, Sigstore, GitHub
API, workflows, install.sh, modules), 39 to 41 (CLI, environment, config). Those are non-invariant or supply-chain
surfaces, and S-1011 and S-1012 own them. Stale statements in the document, drift only: it says the Linux gate
enforces I1 to I13 and that I14 is not enforced, while escape/enforced.txt lists I14, B6 and P1; it says macOS
enforces I7, I8 and I12, while escape/enforced-macos.txt also lists P1, I2, I3, I4, I6 and I11; it counts nine
update-* rows where tests.go has twelve.

Gaps: none that the wording of S-1002 to S-1013 does not include. Explicit assignments where the wording is thin:
caches (18) to S-1003, with the cross-session chain to S-1013; terminal output and console tail (3, 6) to S-1002;
the clone-mode export walk of a hostile repository (16) to S-1008; the GitHub REST client and OSV (33, 35) to S-1011;
mkimage and rootfs OCI (31), install.sh (37) and the suite and spikes running under sudo on the runner (36) to S-1012.
No new unit.

Coverage: every non-test .go file under cmd/ and internal/ read in full, with pins/*.json, internal/provider/*.toml,
the five workflows, dependabot.yml, zizmor.yml, scripts/install.sh, loop/gate.sh, loop/guard.sh, loop/lib.sh, the
threat model, docs/policy.md, docs/providers.md, ADR-003 to 005, spikes/install, the escape harness, suite and
sandbox adapters, go.mod and both enforced lists. Skimmed: the fuzz and first-frame unit tests, loop/settings.sh.
Not opened: the remaining *_test.go files, the platform-specific suite files, internal/sigstore/trusted-root.json,
testdata, _legacy/. No ported file holds a weakness found by this map, so nothing falls under S14.

Observations handed to the named audits (not candidates):
- S-1012: ci.yml's gate job runs the pull request head's loop/gate.sh under pull_request_target; the comment and
  zizmor.yml rest on the interaction limit collaborators_only, which expires after six months (loop/settings.sh:42).
  After expiry a fork pull request runs its code on the lent runner with sudo and a read token (S12).
- S-1011: channel.Verify constrains the sha256 and url of each pin but not Pin.Version, which update.go:172 and :269
  use in a file name under layers/<agent>/ and in --to matching; cmd/bump checks VersionOK on its side only. The
  attacker would be the key holder, so hardening only.
- S-1008, S-1010, S-1011 (T5): checkPath, fold and manifest.add (pull.go), denyReader.feed, denyMessage and ocsfLine
  (log.go, ocsf.go) judge guest-chosen bytes with no fuzz target; internal/pins/sources.go (BearerParams, vendor
  latest) has none.
- S-1010, S-1013: audit Note (connection records) is not fsynced, so a host crash loses the tail; the allowed line for
  a terminated host is written before the upstream dial (proxy.go:165), with a deny line later if the dial fails.
- S-1003, S-1013: a --cache NAME:rw image is guest-written ext4 reattached to later guests of any repository, a
  guest-to-guest channel by operator opt-in; the flock keeps it exclusive while written.
- S-1005: serveTerminated's http.Server sets ReadHeaderTimeout only (no IdleTimeout, default MaxHeaderBytes); after an
  Upgrade the ReverseProxy copies bytes raw both ways with no further placeholder check, to the allowed host only.
- S-1002: an init that never Acks blocks run_vm.go:523 after 32 unacknowledged Stdin frames; a host-side input stall.

### S-1001 candidates

C1. ID I12, with the downgrade lens of B9/B10. Attacker: guest root, reached by a malicious repository (an agent hook
at session start) or hostile model output. Severity claimed: medium (the downgrade needs a previous layer, which the
attacker does not control; without one the effect is removal of the agent layer). Where: cmd/workcell/run_vm.go run
(if r.first then in.fail), output (first is true for an Exit that is the guest's first frame), exitResult;
cmd/workcell/update.go fail (writes failed, points current at previous), point (deletes every image that is neither
current nor previous), apply (skips the digest named in failed until the pin changes). Input: the user runs
`workcell run claude ...`; before the command writes a byte, a root process in the guest duplicates PID 1's vsock
connection (pidfd_getfd, as the suite's stealChannel does) and writes one Exit frame of kind 2. Effect: the host
exits 126, writes layers/claude/failed, sets current to previous or empty, deletes the current image, appends a failed
line to updates.log; later sessions run the previous provider version or none, and the daily apply refuses that
digest until the pin changes. Host state outside the workspace export changes persistently at the guest's say-so.
Outcome: CONFIRMED, medium. Reproducing test: escape row `I12 channel-first-frame-rollback` (probe and judge in
rollback.go; the harness's Command plumbing and the control adapter's naive rollback stay in escape/sandbox/). T2:
fails on control (exit 127, claude not found after the hostile run's exit 126). On a real VM, hosted gate on commit
edf1791 of PR #185: 138 passed, 1 failed, the row's detail says the layer image 5.5.5-<sha256>.ext4 is gone from the
host after the hostile run's "could not run, so its layer is set aside". The verifier confirmed from that log, and
restated the precondition: `previous` is not it, since without one the layer is deleted and every later run of the
provider exits 126 until a manual update; the attacker-uncontrolled precondition is that no guest frame precedes the
hostile code, since the init Acks the host's first Stdin frame, which in non-tty use with stdin at EOF is sent at once,
so the forgery must beat both the agent's own first output and any Stdin, and hostile model output cannot do it. The
test waits under escape/_pending/S-F1/. Fix unit: S-F1, below S-1001 in PLAN.md. Not S14: neither file is ported.
C1 FIXED by S-F1, commit ad3fac7 (PR #186). The installer's apply now returns the providers whose layer it installed in
this start, startup keeps them, and fail acts only for one of them, so an Exit forged as the guest's first frame in any
other session changes nothing on the host (TestFail row 1). point spares the image the failed marker names and clears
the marker when that image becomes current again; update reinstalls a set-aside image from disk with no fetch, so
`workcell update <agent> --to <version>` restores it (TestFail tail). The row `I12 channel-first-frame-rollback` is back
in escape/suite/: on a real VM it failed on e3c24e3 (138 passed, 1 failed, before the fix) and passed on ad3fac7 (139
passed, 0 failed). The honest B9 self-rollback, a fresh layer whose command cannot run, still works (TestFail rows 2, 3).

## S-1002: host-guest channel, guest init, supervisor lifecycle (I7, I10, I12), as built at main 7c4edb7

Trust boundary. Attacker bytes reach the supervisor (the operator's uid; owns the VM, proxy, resolver, broker, audit
log, data dir, cwd and terminal) at: the one accepted connection on vsock 5000 (wire.ReadFrame, then output(): Stdout
and Stderr raw to the seat, Ack through DecodeAck, Exit through DecodeExit; on pull Entry, Data and Exit); later
connects to 5000 and 5002, refused by once (5001 capped at 1024, S-1004); the VMM's stdout and stderr and the vz
console pipe (tail of 4 KiB, lastLines sanitiser); the VMM's exit (fixed strings); and guest-written workspace.ext4,
never parsed on the host (reattached by pull: S-1008, S-1003). Host-to-guest bytes (kernel cmdline, Exec JSON with
placeholders and the session CA, Stdin, Resize, Signal, Pull) are host-built; no attacker byte reaches the cmdline.
The host relies on the init only for liveness (Exit ends the session), the first-frame heuristic (B9 self-rollback,
narrowed by S-F1 to a layer installed in this very start), Ack flow control on the input side, and Sync before Exit
(the guest's own loss). Every enforcement is host-side (A1). Persistent host state a guest frame can change: the
command's exit code, session_end's exit N and, in the fresh-layer window only, layers/<agent>/{failed,current,previous}
and updates.log.

Lenses (S9). Parsing and resources: 6-byte header, 64 KiB cap before allocation, 5 s per frame once begun, no resync
after an error; Exit, Ack and Entry decoders bounded and round-trip; console tail 4 KiB sanitised; one connection on
5000 and 5002; host memory per guest frame is one payload; 60 s of fuzzing on FuzzReadFrame and guest FuzzDecode (8.1M
and 5.1M execs), no crasher. Logic and state: output() ends on Exit, a bad Ack or an unknown type; a host-only or pull
type during a run ends the session with 125; frames after Exit are ignored (row exists); the first-frame heuristic is
correct in output and inert in client; fail, point and apply marker transitions are consistent (TestFail, TestUpdate);
pull's manifest, data, end sequence is strict. Concurrency and check-to-use: once closes the listener after the first
accept, so queued connects are reset (TestOnceTakesOneConnection, channel-connect-storm and -flood); the seat mutex
covers send against sit; rm's Lstat then RemoveAll never follows a link (TestRemoveSession); stop checks the lock
before each kill (pid reuse within milliseconds is the only gap, not attacker-reachable). Cryptography and identity:
none on the channel by design; the first connection on 5000 can only be the init's, since no guest code runs before
Exec; the CA sent is the public certificate only. Failure modes: every boot, export and channel error tears the VM
down and exits 125; export failure removes the session dir; no path leaves the VM running; SIGPIPE (C3) is the one
abrupt exit the code does not handle. Downgrade, rollback, replay: C2 below; frames after Exit ignored; the failed
marker is skipped by apply until the pin changes; update --to restores from disk. Interaction between surfaces: Exec
carries placeholders only (I5); apply fetches at session start before boot (B9, synchronous, up to 10 min, a visible
delay, not an attack); session_end is written after the VM is gone; pull boots an image without the session lock
(PARKED U-205, user-triggered).

Refuted by the auditor before any candidate was raised: the Ack stall S-1001 handed over (an overlay test shows
exactly 32 Stdin frames pass and the 33rd blocks the attach reader only; the main select still writes Signal and guest
output still reaches the seat; an input-side stall that workcell stop or two signals end; not I12); a zero installer
after a failed startup given r.first (fresh is nil, so nothing changes and no updates.log is written; overlay test);
forged Exit text (%q quoting leaves no control byte; channel-forged-exit-text); teardown order (defers run LIFO:
attach listener, terminal, VM kill and tmp dir, session_end, lock; Firecracker dies with the supervisor by Pdeathsig on
a locked thread, TestFirecracker/supervisor-killed; rm refuses while the flock is held and removes only absolute wc*
directories); every type assertion, index and decode on guest bytes is bounded and no fail-open error path was found.

Coverage. Read in full: cmd/workcell/{run_vm,session,update,caps,data,layer,cache,cache_vm,policy,relay,pull_vm,log,
main,explain,bench_vm,backend_linux,backend_darwin,mount_linux,mount_darwin,term_vm,term_linux,term_darwin,run_other}.go;
cmd/workcell-init/{main,root,exec,pull,net,mount}.go; internal/wire/wire.go; internal/guest/{guest,trust,walk}.go;
internal/vmm/vmm.go, firecracker/firecracker.go, vz/vz.go, vz/args.go; internal/relay/relay.go;
internal/fileserve/serve_linux.go; internal/audit/audit.go; internal/workspace/workspace.go; internal/proxy/proxy.go
(ported; the lifecycle API boot() uses only, nothing found there); escape/suite/{channel,channel_linux,channel_other,
rollback,tests,suite,helpers,files,floods,floods_linux,relay,layer}.go; escape/sandbox/{sandbox,workcell,workcell_vm,
workcell_linux,control_linux,control_channel_linux}.go; escape/cmd/escape/main.go; the tests wire_test, guest_test,
run_vm_test, session_test, update_test, root_test, firecracker_test, run_test, init_test and testdata/guest;
docs/threat-model.md, ADR-001, 003, 004, 005; escape/enforced.txt. Skimmed: internal/vmm/vz/vz_test.go,
firecracker/mount_test.go, internal/fileserve/codec.go constants, escape/suite/audit.go. Not opened: _legacy/,
internal/proxy/{terminate,allowlist,signin}.go, internal/secret, internal/resolver, internal/rootfs, cmd/workcell/pull.go,
the suite files of other surfaces, cmd/mkimage, cmd/bump. No file of this surface is ported from v1, so nothing falls
under S14. No model declined.

Evidence gaps, not findings (for S-1013, or a redteam unit if test lines are freed): I7's rm clause has no escape row
(the adapter's Stop removes sessions itself; PARKED U-205), and stopSession has no test of any kind, so workcell stop
on a running session is unproven end to end. Smallest rows: stop = run a sleeping command, workcell stop <id>, assert
exit 143 within 10 s and no VMM process or temp dir left; rm = then workcell rm <id>, assert the session dir and the
recorded temp dirs are gone. The vz guest-initiated reset path (C5) is untested on the Mac.

### S-1002 candidates

C2. ID I12 with the B9/B10 downgrade lens; the residual of C1 after S-F1. Attacker: a malicious repository (a hook that
runs as the agent starts) acting as guest root; hostile model output cannot, since its bytes follow the agent's own.
Where: cmd/workcell/run_vm.go run and output (first), cmd/workcell/update.go fail and apply (fresh). Input: the first
workcell run <agent> after the daily check kept a manifest with a new pin, so apply installs the layer in this very
start; before any guest byte, the hook duplicates PID 1's vsock connection and writes one Exit frame of kind 2.
Effect: the session ends 126, failed names the new image, current goes back to previous, one updates.log line; later
sessions run version N-1 until the pin changes or the user runs update; the image stays on disk. Evidence: TestFail
row 2 (cmd/workcell/update_test.go) is the exact fresh-window effect, row 1 shows an earlier-start layer unchanged,
the tail shows update --to restoring from disk; go test ./cmd/workcell -run TestFail passes. Outcome: CONFIRMED, low,
by the verifier: the effect is what SPEC B9 orders (the client rolls back by itself when the new version fails to
run), the init sends nothing after a successful start so an Exit{Err} first frame is the only could-not-run signal B9
has, the host moves between two manifest-verified versions (I14 holds), nothing is deleted, the line is recorded, and
the S-F1 unit text accepts the fresh-start window by name. The attacker-uncontrolled precondition is that the session
is the one that installed the layer. No invariant break remains to fix; listed under S7. If the maintainer wants it
narrower: act on an Exit of kind 2 only within a short bound of the Exec frame, or drop B9's self-rollback for update
--rollback (less code). Not S14.

C3. ID I9 (the session's end is a lifecycle event the host must record) and I7 (the session's temp directory stays
until workcell rm). Attacker: guest root or hostile model output choose the moment; the trigger is the operator's
own stdout reader closing early, which no section-2 attacker can cause, so R2 is met only thinly. Where:
cmd/workcell/run_vm.go client (os.Stdout.Write of guest Stdout frames in the supervisor process); session() ignores
SIGHUP only, and nothing handles SIGPIPE. Input: workcell run -- <cmd> | head -1, then the command writes another
line. Effect: the supervisor dies of SIGPIPE, so its deferred cleanup never runs: no session_end record, the temp
directory (attach socket, VMM config, vsock) stays until rm, and with a tty on stdin the terminal stays raw; the VMM
still dies through the parent-death signal, and every record written so far is sealed. Reproducing test: escape row
I9 run-stdout-reader-closed (escape/_pending/S-F2/lifecycle.go; the plumbing Config.Head, headPipe and Want.Head in
escape/sandbox/ and escape/suite/suite.go stays live). T2: fails on control (the run ended with exit 141 and added 1
record; the command itself ended with exit 0). On a real VM, hosted gate on commit 6932a4f of PR #187: 139 passed, 1
failed, the row's detail says the run ended with exit -1 (death by signal, no "workcell: detached" line) and added 1
record, session_start only. A host-only mimic of client() piped into head -1 exits 141 and its deferred line never
prints. Outcome: CONFIRMED, low, by the verifier from that log: the judge measures exactly the exit code and the record
count, so the log shows the effect and not a look-alike; I7 is not broken, since rm is designed for a killed supervisor
and removes the directory; I9's end record is genuinely missing, through operator action, so it is hardening under S6
and a robustness defect that reaches users, not an invariant break by an in-scope attacker. Fix unit: S-F2, below
S-1002 in PLAN.md (ignore SIGPIPE in session() and treat EPIPE from the terminal in client() as a detach). Variants the
redteam could not express: the tty case (needs a pty in the adapter); the stderr path, 2>&1 | head, the same death via
os.Stderr.Write and via the detached line itself; workcell attach with a closed stdout (the attach process dies, the
session is unaffected); after the fix a detached run should still take workcell attach and return the command's exit
code. Not S14: no file of the candidate is ported.
C3 FIXED by S-F2, commit 81dc8c8 (PR #188). client() now ignores SIGPIPE, so a terminal write whose reader has gone
returns EPIPE and takes the detach path that already existed (restore the tty, print "workcell: detached", return 0); the
seat drops the frames, the command runs on, and the supervisor's deferred session_end record and temp-directory cleanup
run as before. One place covers both the supervisor and `workcell attach | head -1`. The row `I9 run-stdout-reader-closed`
is back in escape/suite/lifecycle.go: on a real VM it failed on 7e92b29 (139 passed, 1 failed, exit -1, 1 record, before
the fix) and passed on 81dc8c8 (140 passed, 0 failed, exit 0 and 2 records). Regression test TestClientEndsAsADetach in
cmd/workcell/run_vm_test.go dies of SIGPIPE without the one line and passes with it. Product 14999 of 15000 (tail.Write
bound folded to pay); the stderr, tty and stdin-raw variants stay unexpressed, as the C3 entry says.

C4. ID none (surface row 3, Stdout and Stderr frames to the user's terminal, which no invariant names). Attacker:
hostile model output, or guest root. Where: cmd/workcell/run_vm.go client (raw bytes to the terminal; the terminal's
answers go back to the guest as Stdin). Input: terminal query sequences in Stdout, such as an OSC 52 clipboard read or
a device-attributes or cursor-position query. Effect: on terminals that allow it, the operator's clipboard, and always
the terminal's identity, reach the guest; the screen can be rewritten to hide what ran. Inherent to a PTY, as for any
container run with a terminal; SPEC section 2 does not name it in or out of scope. Outcome: low, no test (R2: no
invariant), listed under S7 and parked; a line in docs/threat-model.md's out-of-scope list would make the claim
explicit (S-1018 may add it). Not S14.

C5. ID I12 hang, I10; macOS only, shared with S-1003. Attacker: guest root. Where: internal/vmm/vz/vz.go listener
(closed after once) and Wait; cmd/workcell/run_vm.go output (ReadFrame waits without limit for a frame to begin).
Input: guest root runs reboot -f while the session runs. Effect, reasoned only: on vz a restart boots the kernel again
(vz_test keeps restart_stops_vm=false), the new init cannot connect to 5000, halts and reboots, a boot loop at the vCPU
cap; if the framework does not deliver EOF on the old connection the supervisor never ends the session by itself, and
the user ends it with two signals or workcell stop. On Firecracker reboot=k ends the VMM and the connection gets EOF
(TestInit/disconnect). Outcome: UNVERIFIED, needs a Mac: no hosted runner has a hypervisor for vz, so no test can run
here; severity low if real (a command that never exits, which the user already can end). Handed to S-1003 (device
model, both backends) and to the Mac triage of S-1016; the check is one guest reboot -f under vz with the channel open,
and the fix if needed is that vz's Start goroutine closes the accepted connections on a state change. Not S14.

## S-1003: VM configuration and device model, Linux and macOS backends (I1, I4, A7), as built at main 278bf48

Trust boundary. Attacker bytes on this surface are what the guest does with the devices the host hands it (the virtio-blk
drives, the vsock device, the serial or virtio console, the kernel cmdline it reads back), the guest-written ext4 images
the host later reattaches (sessions/<id>/workspace.ext4 to pull, caches/<name>.ext4 to later guests of any repository
with --cache), the VMM process's exit and the vz state channel. Entry points: internal/vmm/firecracker/firecracker.go
(encode, Start, Wait, Close), internal/vmm/vz/vz.go (configure, listener pump, Wait, Kill, Close), cmd/workcell/run_vm.go
boot, accept and closeAll, cmd/workcell/cache_vm.go openCaches, cmd/workcell/layer.go findLayers. Authority: the
supervisor (operator uid) and, for the Firecracker child, the same uid with the VMM's default seccomp and no jailer. No
attacker byte reaches the kernel cmdline: it is built from integers (caps, ports), fixed strings, provider names (build-time
TOML, ^[a-z][a-z0-9-]*$) and cache names (^[a-z0-9][a-z0-9_-]{0,31}$); the repository path, session id, TERM and argv
travel in the Exec frame, never on the cmdline. Host paths attached as drives: <data>/root.ext4 read-only (host-written,
shared), sessions/<id>/workspace.ext4 read-write (the session's own, 0600 in a 0700 directory), layers/<agent>/<current>
read-only (host-written by update), caches/<name>.ext4 read-only or read-write by flag (operator opt-in, flock-gated).
No other host path is attached on either backend; mount mode attaches no disk and serves cwd over vsock 5002 (S-1008).
Network devices: none on either backend (Firecracker's config has no network-interfaces; vz configures serial, socket,
entropy and storage only, no network, shared-directory, Rosetta or clipboard device). vsock ports: 5000 (channel, closed
by once after the init's one connection), 5001 (relay to the proxy, S-1004), 5002 (FUSE, mount mode, one accept).
Firecracker forwards guest connections only to CID 2 as <dir>/vsock_<port> and resets any port with no socket; vz
delivers only to a registered listener. No MMDS (it needs a network device), no balloon, no API socket (--no-api), default
seccomp on. The temp directory is MkdirTemp 0700 with firecracker.json 0600; the attach socket and the VMM's own
host-initiated socket live inside it, so another local user reaches neither, and a guest reaches no host path at all.

Lenses (S9). Parsing and resources: no parser of guest bytes on this surface; the console tail is 4 KiB; vz backlog 16 and
the pump close excess connections; Firecracker's vsock muxer caps connections; disk is bounded by fixed image sizes
(WriteExt4File truncates to content plus free, free capped); host CPU of device threads is the one unbounded figure (C6).
Logic and state: once takes one connection then unlinks or removes the listener; drive order and the cmdline's letters
agree on both backends (root, workspace, layers, caches); Firecracker's reboot=k and panic=-1 end the VMM; vz's Wait
returns only on Stopped or Error by design (C5). Concurrency and check-to-use: openCaches stats, locks, then creates under
LOCK_EX with a rename into place, readers take LOCK_SH, the lock is released after the VMM is gone; m.mu covers Start,
Listen, Kill and Wait; Firecracker's exitErr is written before exited is closed. Cryptography and identity: none here; the
vsock peer is the VMM by construction (per-session socket in a 0700 directory; a per-VM socket device). Failure modes: no
fail-open found; a boot that gets no connection in 20 s, a VMM that dies, or a signal all tear down and exit 125 or
128+sig; export failure removes the session directory; the one unbounded wait is vz Close after a failed Kill (C5).
Downgrade, rollback, replay: not applicable to the device model; the only persistent host state a guest changes through a
device is its own workspace image and an rw cache it was given. Interaction with other surfaces: caches (S-1013 chain),
the layer marker (S-1011), the relay and proxy behind 5001 (S-1004), FUSE behind 5002 (S-1008), the channel's unbounded
first-frame wait (S-1002), the environment-chosen data directory (S-1009).

Refuted by the auditor before any candidate was raised: a nil audit log in pull and bench (Recorder is an interface and
audit.Log's methods take a nil receiver, so a relay header or DNS frame from a pull guest records nothing and panics
nothing); findLayers joining the marker's text without filepath.Base (only update.go and the host user write the marker,
from Pin.Version, whose author is the key holder K, out of scope; hardening noted by S-1011 already); caches as a
guest-to-guest channel (row 18: the host never mounts or parses workspace.ext4 or caches/*.ext4; a hostile rw-cache writer
poisons the next guest's cache or hands its kernel a crafted ext4, which is the operator's opt-in by --cache and the chain
handed to S-1013; the flock and the read-only flag hold as designed); cmdline length (many --cache flags or hundreds of
ports could truncate the trailing workcell.ports= or run drive letters past z: operator-controlled, and the init then
mounts less, never more); guest halt without reboot (idles or spins one vCPU within the cap); virtio reset or hot-unplug
(no hotplug on either backend; a VMM fault is a hypervisor bug, out of scope, and surfaces as EOF then 125); console
floods (tail bounded, TestTailIsBounded); CID 3 on every session (Firecracker bypasses vhost-vsock; vz ignores the CID);
a repository's .envrc pointing XDG_DATA_HOME or TMPDIR at hostile artifacts through the operator's own shell tooling (out
of scope; S-1009 row 40); every error path in boot and teardown (closeAll on each exit from boot; Firecracker Close safe
before Start and after exit; recordBoot before Start so rm finds the directory after SIGKILL; session's defers run
listener, terminal, VM, session_end, lock, signal.Stop in order); A7 (Machine has exactly six methods; Binary and CID are
Config fields only Firecracker reads; mount_darwin.go refuses --mount rather than taking a backend path).

Coverage. Read in full: internal/vmm/vmm.go; internal/vmm/firecracker/{firecracker,doc,firecracker_test,run_test,
init_test,mount_test}.go and testdata/guest/main.go; internal/vmm/vz/{vz,args,doc,vz_test,args_test}.go;
cmd/workcell/{run_vm,backend_linux,backend_darwin,caps,cache,cache_vm,layer,mount_linux,mount_darwin,session,data,relay,
pull_vm,bench_vm,run_other,main,policy,run_vm_test,cache_vm_test,caps_test,layer_test}.go; cmd/workcell-init/{root,main,
mount,net,exec,pull}.go; cmd/mkimage/main.go; internal/workspace/workspace.go; escape/suite/{device,floods,floods_linux,
layer,files,files_linux,files_other,tests,helpers,host_linux}.go; escape/sandbox/{workcell_vm,workcell_linux,
workcell_darwin,workcell,sandbox}.go; docs/adr/accepted/001-vmm.md, 002-workspace-default.md, docs/adr/005-mount-mode.md,
docs/threat-model.md; both enforced lists; the vsock and argument documentation of the pinned Firecracker release and the
socket, lifecycle and listener code of the pinned vz library (fetched into the scratchpad, read as data). Skimmed:
internal/proxy/proxy.go New, Recorder and Deny (ported; only the nil-recorder path, nothing found); internal/audit/audit.go
nil-receiver methods; internal/policy/policy.go resources (read past, never applied to caps, so I13 on caps holds because
caps come from flags alone); internal/provider/provider.go name regexes; internal/fileserve/serve_linux.go Open and grow;
internal/rootfs/ext4file.go and ext4.go size constants; cmd/workcell/update.go marker, writeMarker, point; escape/suite/
channel.go judges, suite.go Want, channel_linux.go stealChannel. Not opened: cmd/workcell/{explain,log,ocsf,pull,
pull_linux,pull_darwin,bench,term_*}.go and their tests, cmd/workcell-init/root_test.go, firecracker/testdata/probe,
internal/rootfs/tree.go and the ext4 writer body, internal/guest, internal/wire, internal/relay, internal/resolver,
internal/secret, the other escape rows, escape/cmd, pins/*.json, _legacy/. Ran: go test ./internal/vmm/... ./cmd/... (all
pass; VM-booting tests skip without /dev/kvm), go vet on the backends, supervisor and init. No file of this surface is
ported from v1, so nothing falls under S14. No model declined. Two observations about a third-party library were not
reachable by a section-2 attacker through the product and stay in this run's transcript.

Evidence gaps, not findings (for S-1013, S-1016 or a redteam unit if test lines are freed): the vz reset path (C5) has no
Mac run yet; reboot variants (HALT and POWER_OFF, sysrq-trigger b, kexec, a reboot racing the init's first connect); a
write flood with O_DIRECT and O_SYNC on the workspace drive (host fsync cost); many /dev/vd? at once (layers and caches,
one virtqueue each); a virtio-rng read loop on vz; serial output while the supervisor stops reading the console pipe; a
vsock connect loop at port 5000 after the host closed the listener, measured as host CPU; cpuJudge's bound (system-wide
/proc/stat, 1.0 CPU-second slack) is thin on a noisy runner.

### S-1003 candidates

C6. ID I10 (host CPU), with A7's minimal device model as the only mitigation named. Attacker: guest root. Where:
internal/vmm/firecracker/firecracker.go Start (exec with Pdeathsig and Setpgid; no rlimit, affinity or cgroup);
internal/vmm/vz/vz.go configure (vCPU count only); docs/adr/accepted/001-vmm.md promises rlimits on the child, which the
code does not set. Input: in a --cpus 1 guest, for the suite's cpuSpin window at once, O_DIRECT 1 MiB reads of the first
/dev/vd? device, a connect-then-close loop on vsock 2:5001, and a serial-console writer. Effect: host CPU time beyond the
vCPU cap, because device emulation runs on the VMM's device thread and the supervisor's relay goroutines, outside the
vCPU count; the existing row cpu-flood spins vCPUs only, so this had never been measured. Reproducing test: escape row
I10 device-cpu-flood (probe emulationProbe, judge cpuJudge(true), the same judge as cpu-flood with the relay address
passed through). T2: fails on control (the host spent 10.5 CPU seconds in 3.0 s of wall time, allowed 4.0). On a real
VM, hosted gate on commit ea45d64 of PR #189: 141 passed, 1 failed; the row's detail says the host spent 4.8 CPU seconds
in 3.4 s of wall time while the guest, capped at 1 CPU, loaded it (allowed 4.4; disk 49 MiB, 267 connects, console under 1
MiB), where cpu-flood in the same run spent 3.4 CPU seconds in 3.5 s (allowed 4.5), so the judge's noise floor was about
0.4 and the device path cost about 1.4 CPU seconds above the vCPU line. Outcome: CONFIRMED, low, by the verifier from
that log: the effect is real, not noise (same judge, same runner, sequential rows); the console arm cannot explain it
(every byte is a vCPU exit, counted inside the vCPU); the attacker is in scope (guest root opens /dev/vd?, /dev/ttyS0 and
dials 2:5001, a public constant; the harness passing the relay address is convenience, not power); I10's text is not
broken (1.4 CPUs on a 4-CPU runner is not exhaustion, and Firecracker serves every device on one thread, so the overrun
is bounded near vCPUs plus one plus the supervisor's share), so this is hardening under S6 and the ADR's unkept promise.
Fix unit: S-F3, below S-1003 in PLAN.md (pin the Firecracker child to --cpus cores, or cpu.max in a per-session cgroup
child). The test waits under escape/_pending/S-F3/emulation.go; cpuJudge(relay bool), onDisk and the row guest-reboot
stay live. Not S14: no file of the candidate is ported.

C6 FIXED by S-F3, commit 1854647 (PR #190). Two causes, both outside the vCPU count. First, Firecracker's device threads:
Start now pins the thread that forks Firecracker to the first --cpus CPUs of the supervisor's own mask (sched_setaffinity;
the vCPU and device threads inherit it; a start the host cannot bound is refused), with the table-driven regression test
TestPin beside TestConfig. Second, and larger, the console: Firecracker flushes every serial byte as its own write, and the
supervisor read the exec pipe through Go's poller, which wakes on every write, so a guest flooding ttyS0 cost the host one
wakeup and read per byte, about 1.1 CPU s per 3 s at serial speed, the same before and after the pin (4.8 then 4.6 CPU s,
allowed 4.4). Start now reads the console from a blocking pipe the poller never sees, in 4 KiB batches a millisecond apart,
so a flood costs at most a thousand reads a second; measured here against a child writing a byte per write: parent CPU
1.97 s per 1.5 MB before, 0.16 s per 7.4 MB after. The row `I10 device-cpu-flood` is back in escape/suite/floods_linux.go:
on a real VM it failed on 0ccb160 (141 passed, 1 failed, 4.8 CPU s in 3.4 s, before the fix) and passed on 1854647 (142
passed, 0 failed, 3.6 CPU s in 3.3 s, allowed 4.3, while the guest read 66 MiB, made 738 connects and wrote under 1 MiB to
the console); cpu-flood 3.4 in the same run. vz unchanged. Product 15000 of 15000, paid by folds in cmd/workcell and the
firecracker package (smt:false dropped from the config, Firecracker's default).

C5 (restated from S-1002; I12 hang and I7, vz only). Reproducing test: escape row I12 guest-reboot (probe rebootGuest:
one line of output, sync, reboot(RESTART), refused unless the channel address is vsock so it never reboots the control
container or the session host under S12; judge rebootJudge: the run ends within hangBound with exit 125, no descendant of
the supervisor survives within deathWait, a plain run after works). T2: fails on control (reboot: exit 0 after 0s, want
one of [125]). Firecracker: REFUTED by the verifier from the hosted gate on ea45d64: the row passed (the run ended with
exit 125 once the guest restarted its kernel, the session's 2 processes went with it, and a plain run after still works);
125 can only come from the channel's EOF when the VMM died of reboot=k, and the probe's own return would be 0 and fail.
vz: UNVERIFIED, needs a Mac (vz.go builds only on darwin arm64 cgo; the hosted gate-macos runner has no hypervisor; the
mechanism exists in the code, since once closes the 5000 listener after the first accept and vz then refuses every later
guest connection, and the unsettled fact is whether the framework closes the old connection on a guest reset). If real:
low, not medium (no invariant break shown; the supervisor waits as on a sleeping command; workcell stop or two signals end
it; the loop is bounded by the vCPU cap; the Kill then Close block needs vm.Stop to fail, which the guest does not
control). The row stays live in the suite as the Linux proof and as the measurement S-1016 runs on the Mac. Not S14.

C5 CONFIRMED on vz by S-1016a (low), from runs on the Mac (macOS 27.2.1, Apple Silicon) at main 7c46d53: the row I12
guest-reboot failed twice (the full Mac gate at 87ad563 and a run of the I12 rows at 7c46d53: reboot: the run did not end
within 15s; the other eleven I12 rows passed), and the verifier could not refute it. It drove the harness's signed binary
with the same probe: stdout said rebooting, reboot(RESTART) never returned, workcell ls still said running after 123 s and,
in a second run, after 542 s, and the session's workspace.ext4 changed every 5 to 6 s, so the guest restarts in a loop and
the run never ends by itself. Not a bound artifact and no power beyond guest root's one reboot(2) call. Where: session in
cmd/workcell/run_vm.go waits on client input, signals and done only, output sits in ReadFrame, which waits without limit
for a frame to begin, and m.Wait is asked only in accept, during boot; Wait and the Start goroutine in
internal/vmm/vz/vz.go end only on Stopped or Error, and a guest restart leaves the VM running; the accepted 5000
connection gives no EOF at the reset, only at the host's next write; once has closed the listener, so each new init's 5 s
dial fails and halt restarts again (cmd/workcell-init/main.go). Bounds, measured: one SIGINT ends it at once with exit 125
(guest channel: EOF); workcell stop ends it in 0 s; any host-to-guest frame ends it (one stdin byte, or workcell attach),
so it hangs only while the host sends nothing, the headless case; the VM's process stayed at 2 to 9 percent of one core and
about 113 MB with --cpus 1 and with 2, the supervisor below 1.2 percent, so the loop is far below the vCPU cap; after any
ending no process, no socket directory and nothing beyond a normal ended session's files stay. Severity under S6: low, no
invariant break shown, since the supervisor answers every control input at once and a command that never ends is guest
root's by design (a shell that traps INT and TERM ran on through one SIGINT and needed two). The verifier notes the other
reading for the maintainer: if I12's hang means the run must end by itself once the guest is gone, it is medium, the
precondition being that the host sends nothing. Either way I12 is in escape/enforced-macos.txt, so the Mac gate is red
until the row passes. Fix unit: S-F24 (env:macos), below S-1016a in PLAN.md; the row stays in the suite, so nothing waits
under escape/_pending/. Not S14: internal/vmm/vz is not ported and the wait is this repository's own. The logs are in
loop/private/ on the Mac (c5-mac-7c46d53-I12.log, gate-mac-87ad563.log, c5-verifier/).

## S-1004: network path and proxy core: routing, SNI, ECH, connection handling, fail-closed behaviour (I2, I4, I11), as built at main 5f5b941

Trust boundary. Guest root owns every byte on vsock 5001: the 20 B relay header (version, proto, port, 16 B address), all
that follows it (a ClientHello on 443, raw bytes on a forward port, one DNS frame on UDP 53), and the connect rate and
timing. The network attacker owns the host resolver's answers for allowed names (the rebind model, map row 14) and the
upstream bytes. Entry: cmd/workcell/relay.go stream (20 B under 5 s, 1024 slots) to an adapter, then internal/proxy/proxy.go
Serve, handle, route, connect and splice, then net.Dialer on the host as the operator's uid; DNS goes to internal/resolver
and never to a host query. Authority: the supervisor dials TCP from the host, writes audit lines, and holds up to 1024 relay
and 1024 proxy slots. Lenses worked in order: parsing and resources, logic and state, concurrency and check-to-use gaps,
cryptography and identity, failure modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real functions, nothing in the tree
changed, every probe a process in this session):
- ECH: a genuine ECH ClientHello (Go client with a config list; outer SNI allowed, inner hidden) is refused by peekSNI and
  by route even with both names allowed (no_sni); Go 1.27 runs processECHClientHello before GetConfigForClient and, with no
  keys, hands the outer hello through, so the check sees extension 0xfe0d. A malformed or inner-type ECH extension fails
  earlier (alert) and is also refused. Chrome-class clients send GREASE ECH on the same codepoint, so they get no_sni:
  fail-closed, a developer-experience note only.
- Mixed answer sets, first-dialable-then-host-network, a second answer after a dial (the parked B-836 ideas): one lookup per
  connection, every address vetted before any dial, one dial loop over that one set; the terminated transport's DialContext
  re-enters connect per upstream connection (TestConnectVetsEveryAnswerOnEveryConnection rows "public and private mixed"
  and "answer changes to loopback"). The IPv6 variant: a host prefix 2606:4700:abcd::/64 blocks 2606:4700:abcd::1 and not
  2606:4700:abce::1; a /128 interface address blocks exactly itself. No check-to-use gap found.
- Address encodings: Unmap before every check and before the dial; ::ffff:, ::a.b.c.d, 64:ff9b::, 2002::, Teredo, 2001:db8,
  3fff and 5f00 are all refused (TestBlockedAddr plus overlay); the relay header's own address is never dialled (relay-header-*).
- Every I4 class per protocol: TCP is the only protocol the host ever dials, always through connect; UDP crosses only as port
  53 to the in-process resolver; other protocols and versions close the stream; ICMP and QUIC never cross (no device). Host
  loopback, private, link-local, the host's own interface networks and other sessions (no addresses exist) are refused; of the
  cloud metadata addresses, one is missing: C7 below.
- Fail-closed (I11): no error path in route, lookup, dial or Write reaches splice; the Allowed line is noted before traffic on
  the splice path; adapters close when the relay listener closes (TestRelayCloseEndsAdapters, TestStreamAfterAdaptersClosed);
  a relay Accept error ends every Serve loop closed, not open; an unreadable host-network list refuses everything; a nil log
  records nothing and panics nothing.
- Deadlines as a slot-holding tool: the 5 s header and 10 s peek deadlines are absolute, so a drip cannot extend them
  (TestPeekSNI 64 KiB case, relay-slow-header); a guest can still hold all 1024 slots with idle spliced or keep-alive
  connections, bounded at about 64 KiB of io.Copy buffers plus 16 KiB of peek per slot, within ADR-003's vsock budget.
- Per-connect host cost (the S-F3 lead): at the relay cap a connect costs Accept plus Close; below it one goroutine, one timer
  and a 20 B read; on a forward port it adds one rooted lookup, one InterfaceAddrs netlink dump and one dial per attempt,
  bounded at 1024 concurrent and by the vsock path in rate (738 connects in 3 s in S-F3's run). No row floods a forward port
  (evidence gap, not a finding).
- Paths that skip SNI: forward ports route by the port's one host with no SNI or Host check, by design (ADR-003,
  allowlist.go); CONNECT is refused on terminated connections (S-1005).
- SNI case and fold: ToLower with a length check; a non-ASCII fold either shortens or stays non-ASCII, and the allowlist holds
  only ASCII names, so no fold matches (TestRouteRefusesUnicodeFoldedSNI; "API.Example.COM" routes to api.example.com);
  crypto/tls rejects a trailing-dot SNI. Name agreement: resolver names are allow.Hosts(), lowercased and unrooted; the proxy
  admits by exact port-scoped sets; a forward-only host dialled at 443 gets sni_not_allowed. No panic found (Decode's
  slice-to-array is exact, the resolver bounds every index, a nil allowlist never reaches route).

Handoffs: S-1005 (serveTerminated's ln.addr is the guest-chosen header address, only its port is used; http.Server bounds the
TLS handshake by ReadHeaderTimeout and has no idle timeout); S-1006 and S-1007 (resolver parsing; the refused callback's host
string); S-1010 (Deny ignores Note errors, so after SoftLimit or a failed log connections continue unrecorded, a documented
design; the lost counter is flushed only by a later queued shed; the terminated path's Allowed line precedes its dial).

Coverage. Read in full: internal/proxy/proxy.go, allowlist.go, terminate.go and the proxy, forward and clients tests;
internal/relay/relay.go and its test; internal/resolver/resolver.go; cmd/workcell/relay.go, relay_test.go and run_vm.go;
cmd/workcell-init/net.go as data (A1); internal/audit/audit.go; the Listen and Start paths of both backends; escape/suite
relay, rebind, packets, https, icmp_linux, dns, tests, floods and lifecycle; escape/sandbox/workcell_vm.go; ADR-003; SPEC
sections 2, 3, 6, 8, 11 and 13; FINDINGS S-1001 and S-1003; both enforced lists; Go 1.27 crypto/tls readClientHello and
processECHClientHello. Skimmed: internal/proxy/signin.go (S-1005), escape/suite/host_linux.go. Not opened:
internal/resolver/resolver_test.go, the control adapters, workcell_linux.go isolate, the pinned vz library's connection type.
Ran: the proxy, relay, resolver and cmd tests (green) and the overlay probes. Nothing needing a VM was run; no probe left the
session. proxy.go is ported, so its candidate is an ordinary public one under section 13; relay.go is not ported. No model
declined, and no safeguard re-ran a request.

### S-1004 candidates

C7. ID I4 (cloud metadata addresses). Attacker: guest root, with the host resolver's answer for an allowed name (the network
attacker as the LAN DNS, the model of the rebind-* rows). Where: internal/proxy/proxy.go blockedPrefixes, blockedAddr,
connect. Input: the policy forwards a plain port of an allowed name (`name.example:80`, documented in docs/policy.md); the
host's resolver answers that name with A 168.63.129.16; the guest opens TCP to it and speaks the Azure WireServer protocol
(goal state, then the certificates endpoint with a transport certificate it mints). Effect: the host dials Azure's platform
virtual IP for the guest. blockedPrefixes enumerates the other providers' metadata endpoints (169.254.0.0/16,
100.100.100.200, 192.0.0.192, fd00:ec2::254) but not this one, the only global-unicast metadata address among the providers
examined (AWS, GCP, Azure, Oracle, Alibaba, Tencent, Huawei, OpenStack, Hetzner, DigitalOcean, Vultr, Linode, Scaleway, IBM,
Yandex; all the others are link-local, ULA or CGNAT); it is never an interface address of the host, so B-836's host-network
check does not catch it either; GitHub-hosted runners and Codespaces are Azure VMs. Reproducing test:
escape/_pending/S-F4/proxy_azure_test.go, TestBlockedAddrAzure (package proxy, rows 168.63.129.16 and ::ffff:168.63.129.16
with no host prefixes), run by overlay: fails on 079960b with `blockedAddr(168.63.129.16) = false, want true` for both rows,
while TestBlockedAddr passes. Outcome: CONFIRMED, medium, by the verifier: a second probe with a stubbed lookup and dial ran
Proxy.connect("name.example", 80) with the resolver answering 168.63.129.16 and saw dial_failed with 168.63.129.16:80 dialled,
while the four controls got blocked_address; blockedAddr is the only gate in connect, the resolver filters nothing and the
plain-port path verifies no TLS, so nothing else refuses it; the attacker is in scope and the test grants no extra power; the
preconditions the attacker does not control (an Azure host, a policy forwarding port 80 or 32526) make it medium under S6.
Fix unit: S-F4, below S-1004 in PLAN.md (one /32 in blockedPrefixes; the test folds into TestBlockedAddr as one row).
also in v1 main: egressproxy/proxy.go
C7 FIXED by S-F4, commit ce316be (PR #199). blockedPrefixes in internal/proxy/proxy.go gains the row 168.63.129.16/32, named as
Azure's platform virtual IP (WireServer) metadata address, and its header comment now says the list also holds a cloud
metadata address on public space. blockedAddr unmaps before matching, so ::ffff:168.63.129.16 is refused by the same row.
The pending test became one row of TestBlockedAddr (168.63.129.16 and ::ffff:168.63.129.16 with no host prefixes); it
failed on the parent commit for both forms and passes now; escape/_pending/ is gone. The reviewer's overlay probe also saw
the IPv4-compatible, NAT64 and 6to4 encodings refused and 168.63.129.15, .17 and 168.63.128.16 still allowed, so the /32 is
the whole platform address and no wider. Product 14994 of 15000.

C8. ID I9 with I10. Attacker: guest root. Where: cmd/workcell/relay.go serveRelay (the default branch that closes a stream
when its 1024 slots are full); internal/proxy/proxy.go Serve (the shed branch that records overloaded). Input: 1024 open
streams to 5001, then one more. Claimed effect: the 1025th stream is closed with no record, and the proxy's recorded shed
branch cannot fire in production because every proxy connection also holds a relay slot and the caps are equal. Reproducing
test: TestRelayRecordsTheShedStream (package main), run by overlay: fails on 079960b with "the shed stream left no record".
Outcome: REFUTED by the verifier. The mechanism is real, but a stream whose header was never read is not a connection
attempt in I9's sense: the relay records at header decode only, and dropping an unread stream without a record is proven
intended by TestRelayDropsAnIncompleteHeader and the rows relay-short-header and relay-slow-header; the test's own 1024
held streams are such streams, and no destination is known, so a record could only be a count. On Linux the guest cannot
reach the branch at all: Firecracker's connection limit (ADR-003, measured) resets the 1023rd guest connect before the relay
sees it, so the slots never fill except in a transient churn race; the test granted itself 1024 accepted streams over
net.Pipe. Only on vz is the branch reachable. No reach is gained and no record is suppressed, forged or altered; S6's ceiling
is low, hardening only. What remains is a less-code note: the proxy's queued-or-counted shed path and its lost counter are
dead code in production (PARKED.md). The test was deleted.

C9. ID I4 (the LAN), the residual of the line B-836 drew. Attacker: guest root with the network attacker as DNS. Where:
internal/proxy/proxy.go nets (net.InterfaceAddrs only). Input: a host whose interface prefix is narrower than what is on-link
or routed (a /32 or /128 with a wider on-link route; an enterprise VPN addressing internal hosts from public space); the
resolver answers an allowed name with a neighbour in that space. Effect: the neighbour is global unicast, outside every
blocked prefix and outside the host's interface prefix, so it is dialled through the host's tunnel or link. Outcome: not
reproduced, reasoned only, low: no break of I4's wording is demonstrated, the host is uncommon, and a route-only neighbour
is indistinguishable from the suite's own canary (CanaryAddr is reachable by a local route and must be dialled), so no test
can fail on it without redrawing B-836's line; a route-table read costs tens of product lines per OS at the ceiling.
Recorded as residual risk for docs/security-review.md (PARKED.md).

## S-1005: TLS termination and HTTP handling: smuggling, HTTP/2, WebSocket, redirects, CONNECT, CA handling (I5, I6), as built at main 8ca74f0

Trust boundary. Guest root (G) and hostile model output (M) own every byte after the relay header on a 443 stream: the
ClientHello (peeked by S-1004's path, then replayed), then everything the per-connection tls.Server decrypts and net/http
parses in internal/proxy/terminate.go serveTerminated: request line, headers, bodies, pipelining, timing, and the request
path that admits and signin.go tokenEndpoint judge. The network attacker (N) owns the host resolver's answers for allowed
names and the TCP path to whatever they name; it does not own an allowed host's TLS identity. Authority: the supervisor's uid
dials the vetted address of the SNI host (p.transport.DialContext re-enters p.connect), verifies the upstream chain against
system roots plus SSL_CERT_FILE with ServerName = SNI host, calls broker.Lookup or Refresh (a host process per use for cmd:
and secret-service: sources) and writes the real value into the outgoing header or token body, records every refusal, and
rewrites token-endpoint answers before the guest sees a byte. sameHost's port is the relay header's port, which must be
443 to reach the 443 adapter (cmd/workcell/relay.go), so in production only ":443" or no port passes. Lenses worked in
order: parsing and resources, logic and state, concurrency and check-to-use gaps, cryptography and identity, failure
modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay probes from the scratchpad against the real package, 28 raw request
shapes and nine upstream certificates among them; nothing in the tree changed; every listener on loopback):
- Smuggling: CL.TE (Content-Length plus chunked, a second request with another allowed Host inside) is re-framed by
  net/http, which drops Content-Length when chunked; the upstream saw one request and the proxy parsed the "smuggled" one as
  the next request and refused it 421 host_mismatch. TE.CL with a malformed chunk: 502, nothing crossed. "xchunked" and
  "chunked, identity": 501; "Transfer-Encoding : chunked": 400; duplicate Host: 400. An undeclared trailer and a chunk
  extension carrying the placeholder are not forwarded; declared trailers are refused by carriesPlaceholder (existing test).
- Host versus SNI on a kept-alive connection: every request is re-judged by sameHost against the connection's SNI host and
  Rewrite forces the upstream Host to the SNI host (I6). Pipelined example.com then a.example.com: 200 then 421.
  Absolute-form target naming another allowed host: 421; naming the SNI host with a foreign Host header: 200 and the
  upstream saw the SNI host. Host with another port, an empty port, HTTP/1.0 without Host: 421. Trailing dot, capitals and
  :443 are the same name (TestSameHost). An opaque target reaches the right host as a malformed request-target only.
- HTTP/2: h2-only ALPN is refused (existing test); a "PRI * HTTP/2.0" preface is a method without Host, 421, and with a Host
  it crosses as "PRI * HTTP/1.1" with no key; an h2c upgrade is forwarded as a plain request with HTTP2-Settings dropped, no
  101; the upstream transport has ForceAttemptHTTP2 false and no ALPN, so :authority exists on neither side.
- Upgrade: a 101 from the allowed host opens a raw tunnel to that host only (DialContext admits terminate hosts alone); the
  placeholder crosses unswapped, useless there; a bare 101 to a plain request gives 502 and no tunnel.
- CONNECT: refused 405 before any check, authority form included; lowercase "connect" crosses as an ordinary method with
  the swapped key to the bound host, no tunnel; "Connection: X-Api-Key" makes ReverseProxy drop the swapped header, self-harm.
- obs-fold: Go 1.27 joins folded header lines with a space, so a placeholder folded across lines crosses broken and
  unswapped: no secret.
- CA and leaf: P-256, at most 24 h, name-constrained (critical) to the allowed names and their subdomains with every IP range
  excluded, pathlen 0, key only in host memory; leaves are minted once per allowed name under a mutex, SAN = host, so the
  cache is bounded by the allowlist; GetCertificate uses the peeked host, the same bytes replayed. Resumption across
  connections is impossible: ticket keys live in the tls.Config and serveTerminated makes one per connection; three
  connections sharing a client session cache all showed DidResume false (TLS 1.3). No client certificate is requested.
- Upstream verification: expired, not-yet-valid, other-SAN, CN-only and other-authority leaves and a TLS 1.1-only upstream
  all gave 502 with the real secret never written, since the handshake fails first; a wildcard leaf is accepted for the
  subdomain and refused for the apex, as x509 says. ServerName is the SNI host; Transport.Proxy is nil, so no proxy
  environment is honoured; an unreadable SSL_CERT_FILE refuses termination (existing test).
- Secret injection forms: bare, Bearer and Basic (strict base64, 4 KiB) only; case, two values, suffixes, the placeholder
  as the Basic user, query strings, path, header names and trailers are refused or left unswapped (existing tests and
  FuzzCarriesPlaceholder); bodies of non-token requests are never scanned. Sign-in: form and JSON refresh swaps, gzip and
  chunked answers, a 2xx that is not one JSON object, an over-bound answer and an unrecordable one are refused whole
  (existing tests). Accept-Encoding is added only when the guest sent none and dropped at the token endpoint.
- Failure modes: every error path answers 4xx or 5xx or closes (leaf error, Lookup error, tokenRequest reasons, a
  ModifyResponse error gives an empty 502 before any upstream header is copied); handler panics are recovered per
  connection. Nothing fails open. The handshake and each header read are bounded by ReadHeaderTimeout, 10 s absolute; idle
  keep-alive holds are by design (S-1004) and cost about 69 KiB each.

Handoffs: S-1006 (p.transport has no TLSHandshakeTimeout or ResponseHeaderTimeout, so with N as DNS naming a public host
that accepts TCP and stalls, the guest's request hangs in its own slot until the guest gives up; nothing is written before
verification). S-1007 (each swap is one broker.Lookup, one Resolve and one host process for cmd: and secret-service:
sources per request under the 300 per minute window, PARKED line 10; the Lookup error text is dropped; the header string
and the transport's write buffer are transient host-side copies of a value; nested token shapes stay parked, U-403).
S-1010 (one kept-alive terminated connection produced about 57,000 refusal records per second, 20,000 pipelined requests
with a foreign Host in 349 ms, so the 8 MiB SoftLimit fills in about 1.3 s and connection records then stop while the
session continues: the terminated path makes I9's recording budget exhaustible at request rate, where the splice path is
bound by the vsock connect rate). S-1013 (a real token obtained through C10 chains with "a key the guest made up is not
swapped" into a working credential used through the proxy; the Upgrade tunnel to a WebSocket-speaking allowed host carries
raw bytes with no further check, bounded to that host).

Coverage. Read in full: internal/proxy/terminate.go, signin.go, proxy.go, allowlist.go, terminate_test.go, signin_test.go,
proxy_test.go, clients_test.go, git_test.go, providers_test.go; internal/secret/broker.go; internal/guest/trust.go;
cmd/workcell/policy.go and relay.go; escape/suite/terminate.go, secrets.go and signin.go; SPEC; PARKED; FINDINGS lines
1-133 and 404-520; Go 1.27 net/http readRequest (both), parseTransferEncoding, fixLength, ReverseProxy ServeHTTP and
handleUpgradeResponse, crypto/tls ticketKeys. Skimmed: cmd/workcell/run_vm.go boot and bind, escape/suite/https.go and
tests.go, internal/audit/audit.go limits, internal/provider/*.toml (no method, path or signin rows ship), ADR-003,
docs/policy.md, crypto/tls checkForResumption. Not opened: internal/secret/source.go and its tests (S-1007),
internal/proxy/allowlist_test.go and forward_test.go, internal/resolver (S-1006), internal/guest/guest.go, cmd/workcell-init,
the escape sandbox adapters, FINDINGS lines 134-403. Ran: go test ./internal/proxy/ (green) and the overlay probes named
above; nothing needing a VM; no probe left the session. terminate.go is ported, signin.go is not. No model declined, and
no safeguard re-ran a request.

### S-1005 candidates

C10. ID I5 (sign-in flow: a real token the broker holds never appears in an answer; narrowing: a placeholder sent any other
way to the host is refused), with I6's Host leg intact. Attacker: hostile model output choosing the request path, and guest
root. Where: internal/proxy/signin.go tokenEndpoint and sameEndpoint (not ported); internal/proxy/terminate.go admits
(ported). Input: (a) with a signin row for login.example.com/oauth/token, the guest POSTs an authorization-code grant to
/oauth/x/..;/token, /oauth%5Ctoken or /oauth/./token;a/..;/token; (b) with a rule narrowed to POST /v1/ or to one
repository, the guest sends the placeholder to POST /v1/..;/admin, /v1/..%5Cadmin, GET /octo/allowed.git/..;/other.git/info/refs
or POST /octo/allowed/..;/..;/evil/repo.git/git-receive-pack. Effect: (a) tokenEndpoint matches neither reading, since
sameEndpoint strips ;params but never re-resolves the dot segments that uncovers and knows nothing of backslashes, so the
request crosses as an ordinary one; a router that drops ;params before normalising (Tomcat, Jetty, Undertow) or folds a
backslash to a slash (HTTP.sys, IIS) serves it as the token endpoint and answers real access and refresh tokens that the
proxy never reads, learns or hides: the guest holds working credentials, and "a key the guest made up is not swapped" lets
it use them through the proxy. (b) admits judges the path as sent and as decoded with dot segments resolved, but ..; and
..\ are not dot segments to path.Clean, so the real secret reaches /admin or another repository on the bound host, outside
the rule. Reproducing test: escape/_pending/S-F5/c10_test.go, TestFoldedPathEscapesTheEndpointAndTheRule (package proxy;
the fake upstream folds the path as those routers do and the head comment names that as the precondition), run by overlay:
fails on 6294e07 with "the guest read a real token: 200 {access_token sk-acc-1, refresh_token sk-ref-1}" for all three
token spellings and "got (200, /admin real-secret), want it refused" and "/octo/other.git/info/refs Bearer real-secret" for
the narrowed rows, while the package's own tests pass. Outcome: CONFIRMED, medium, by the verifier: the test reaches the
proxy through the session CA as a guest does and takes the same fixture arrangement as signinFixture, the only modelled
element being the router's folding, which is the stated precondition and standard behaviour of those servers, not a
compromise of an allowlisted provider; the product's own comments promise the router's reading and that no ".." leads
out from under a prefix on either reading, and the suite already pins ;jsessionid and %2e%2e forms, so the combination
is an omission, not a design; medium under S6 because the operator's host must sit behind such a router. Fix unit: S-F5,
below S-1005 in PLAN.md. Residual, unmodelled: IIS trailing-dot and trailing-space stripping, and double decoding.
also in v1 main: egressproxy/terminate.go

C10 FIXED by S-F5, commits c48a5a2 and 7fa56d7 (PR #201). fold in internal/proxy/signin.go reads a path as sent the way those routers
do: ;params cut from each raw segment (so a param cannot hide an encoded slash), PathUnescape, ;params cut again, backslash to
slash, then path.Clean. It replaces sameEndpoint, whose per-segment cut it absorbs, and path.Clean as the second reading in both
tokenEndpoint and admits; the as-sent reading (EscapedPath) stays first in each. So /oauth/x/..;/token, /oauth%5Ctoken,
/oauth/./token;a/..;/token and /oauth/token;%2Fx are the token endpoint, read whole and their answers learned and hidden, and the
placeholder on /v1/..;/admin, /v1/..%5Cadmin, /v1/x;%2Fa%2Fb/../../admin and the three repository spellings is refused 403 with
the secret withheld. The pending test moved whole to internal/proxy/c10_test.go, its fake upstream cutting raw ;params before it
decodes as those routers do; it failed on the parent for all seven rows, the review's ;%2F rows failed on the first fix, and all
ten pass now, with TestTokenEndpoint and TestTerminateNarrowedRule unchanged; escape/_pending/S-F5/ is gone. Product 14995 of 15000.

C11. ID I10 (host memory), with I12's hang. Attacker: guest root. Where: internal/proxy/terminate.go serveTerminated's
http.Server literal (ReadHeaderTimeout only; MaxHeaderBytes at the 1 MiB default; no ReadTimeout, IdleTimeout or
post-header deadline anywhere in the package); internal/proxy/signin.go tokenRequest's io.ReadAll with no deadline.
Input: up to 1024 terminated connections, each sending a complete header block just under 1 MiB with Content-Length: 100
and no body, to a sign-in row's token endpoint (held with no deadline and no upstream dialled, since tokenRequest reads
the body whole first) or to any bound host (held while the upstream waits for the body). Effect: each held slot pins the
parsed header map, about 1.0 MiB of live heap and 1.3 to 1.65 MiB of RSS, against ADR-003's 55 KiB per held stream:
about 1 to 1.7 GiB at the slot cap, for as long as the guest likes. Reproducing test: escape/_pending/S-F6/c11_test.go,
TestTokenEndpointHoldsOversizedHeaders (16 raw TLS connections send 979 KiB of headers with Expect: 100-continue; the
proxy's own 100 Continue proves the block was parsed and the handler is blocked in ReadAll; live heap per held connection
is compared with 512 KiB), run by overlay: fails on 6294e07 with "pin 1038 KiB of live heap each, over 512 KiB; a client
needs a few KiB", stable at 1037 to 1042 across eight runs by the redteam and the verifier. Outcome: CONFIRMED, low, by
the verifier: the effect is real and the attacker needs only a sign-in row in policy and ordinary TLS connections; the
"no idle timeout" comment accepts a held connection, not a held slot at twenty times the budget; low stands under S6
because maxConns bounds the total and no exhaustion of host memory or hang of the host process is demonstrated. Fix unit:
S-F6, below S-1005 in PLAN.md (one line, MaxHeaderBytes 64 KiB; optionally a read deadline before tokenRequest).
also in v1 main: egressproxy/terminate.go
C11 FIXED by S-F6, commits 8814d3b and 85e56f8 (PR #202). serveTerminated's http.Server literal in internal/proxy/terminate.go
now sets MaxHeaderBytes to 64 KiB, so net/http refuses a header block above that with 431 and Connection: close before the handler
runs, and a held slot can pin no more than ADR-003 budgets; the 431 body is Go's fixed string, so no swapped key or placeholder is
echoed. The pending measured test became internal/proxy/c11_test.go TestOversizedHeaderBlockRefused, two rows on raw TLS
connections: a 98 KiB block to the sign-in token endpoint with a declared, withheld body (answered 100 Continue on the parent) and
a 97 KiB block to a plain terminated host (answered 200 on the parent); both now see 431 and then EOF. escape/_pending/S-F6/ is
gone. The optional read deadline before tokenRequest went in and came out again in the review round: set under a bodyless token
request, net/http's background read hit it after 10 s against a slow upstream and cancelled the connection's context, so every
later keep-alive request on it was answered 502, and no test in the suite would have noticed the line going away. So the hang half
of C11 (a sub-64 KiB header block with a withheld body parks one slot and one goroutine until the guest closes, bounded by maxConns)
stays as recorded under low, in PARKED.md for S-1013. Product 14996 of 15000.

C12. ID I5 (sign-in: a real token the broker holds never appears in an answer). Attacker: guest root, with two
preconditions it does not control. Where: internal/proxy/signin.go hide's plain-bytes pass and hideIn (not ported); the
spelling comes from swapRefresh's url.QueryEscape. Input: a broker refresh token holding +, / or = (base64-shaped, as
some providers' tokens are), which the proxy sends to the token endpoint as refresh_token=a%2Bb%2Fc%3D, and a token-endpoint
error answer that echoes the parameter as received, in text or inside a JSON string. Effect: hide replaces the verbatim
bytes and the JSON-escaped spellings of the real values but not the percent-encoded spelling the proxy itself put on the
wire, so the answer reaches the guest one decode away from the real refresh token. Reproducing test:
escape/_pending/S-F7/c12_test.go, TestLearnHidesTheEncodedSpelling (through learn, with a broker holding a+b/c=), run by
overlay: fails on 6294e07 with learn("error=invalid_grant&refresh_token=a%2Bb%2Fc%3D") returned unchanged, and the same
inside a JSON string. Outcome: CONFIRMED by the verifier, who also ran it end to end through the real terminating proxy
with a loopback token endpoint echoing its raw form body in a 400: the endpoint received refresh_token=a%2Bb%2Fc%3D and the
guest received that 400 body untouched. The guest sends only the placeholder, the documented flow, and gains no extra
power. The auditor rated it low because no allowlisted provider was shown to echo raw parameters (T8 forbids probing one);
the verifier read S6's letter as medium, since the break is demonstrated under preconditions the attacker does not
control. Recorded at medium on the verifier's reading, so S7 fixes it before cutover; the fix is two lines in hide
(the QueryEscape spelling, and the JSON-marshalled form of it). Fix unit: S-F7, below S-1005 in PLAN.md.

C12 FIXED by S-F7, commits 34b8e83 and 8b957b0 (PR #203). hide in internal/proxy/signin.go now widens swaps, before both of
its passes, with every spelling of a real value that swapRefresh itself puts on the wire and that differs from the value: the
url-encoded one of a form body (url.QueryEscape) and the json-escaped one of a JSON object body (encoding/json, which spells
& < > as \u0026 \u003c \u003e), so an echo of either spelling, as text or inside a JSON string, reaches the guest as the
placeholder. The second spelling came from the review round: a refresh token holding & went on the wire as "a\u0026b" and the
first round hid only the url-encoded form (same class, I5, S6 medium). The pending test became internal/proxy/c12_test.go
TestLearnHidesTheEncodedSpelling with a broker refresh token a+b/c=& and three rows: the form echo, the form echo inside a
JSON string, and the JSON wire body echoed as text; all three failed on the parent and the third on 34b8e83. FuzzHide's
seeds hold a base64-shaped refresh value with &, one seed echoes both spellings, and its assertion refuses the real value,
its url-encoded and its json-escaped spelling, plain and in the re-marshalled JSON reading. escape/_pending/S-F7/ is gone.
Product 15000 of 15000, paid by folding the doc comments of learn and hide; test 27486 of 27500.

## S-1006: resolver: tunnelling, rebinding, cache and case tricks (I3, I4), as built at main 64eeaad

Trust boundary. Guest root owns every byte on vsock 5001 after the 20 B header of a UDP-53 stream: the 2 B length and up to 65535 B
of DNS message (cmd/workcell/relay.go exchange, internal/relay ReadFrame, internal/resolver Answer), and the stream rate and timing.
The handling code is the supervisor, as the operator's uid: it answers from policy, writes one audit Note per refused name through
proxy.Deny and never forwards a query. The network attacker owns the host resolver's answers for allowed names (internal/proxy/proxy.go
connect, net.DefaultResolver; map row 14) and every upstream byte; the supervisor dials TCP from the host with those answers after
blockedAddr. The allowed-name set reaches the resolver as allow.Hosts() (lowercase, unrooted, dnsName-validated) and the proxy as the
exact port-scoped sets of the same strings; the session CA's PermittedDNSDomains is allow.TLSHosts(). The guest's resolv.conf
(cmd/workcell-init/net.go) is data only (A1): whatever it names, every address routes to the init and UDP 53 is relayed to the
in-process resolver. Lenses worked in order: parsing and resources, logic and state, concurrency and check-to-use, cryptography and
identity, failure modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real packages, nothing in the tree changed,
every target a listener this session bound on 127.0.0.1; nothing here needed a VM):
- Parsing: label types 0x41 and 0x80, a compression pointer to a later offset, 128 one-byte labels (255 text bytes) and QDCOUNT other
  than 1 all get FORMERR in a 12-byte reply; 127 one-byte labels (253 bytes) parse; a valid question followed by 65 KB of junk is
  answered normally (49 bytes); TC, AA, Z, AD and CD are masked out of the reply; every reply is at most the question plus 16 bytes,
  so maxReply 287 holds and there is no amplification, and the reply goes back over vsock only. A 65535-byte frame through the real
  stream dispatcher is answered; a frame that promises 65535 bytes and sends 3 is dropped at the absolute deadline (701 ms with a
  700 ms wait), so a DNS stream holds a slot for at most headerWait, within the 1024 slots.
- Logic and state: case folding is ASCII-only on both sides and the allowlist is ASCII, so no fold matches a non-ASCII spelling; a
  trailing dot is trimmed by the query form and refused by crypto/tls in an SNI; subdomain, suffix, prefix and one-label-with-a-dot
  are refused (TestAnswer); underscore and wildcard labels give name "" (refused, "(invalid)" in the log); punycode is compared
  literally; ANY, AAAA, TXT and HTTPS on an allowed name are NOERROR with no record; class 0, CH and every opcode but QUERY are
  REFUSED without a record. REFUSED against nodata tells the guest whether a name is allowed, which the CA's PermittedDNSDomains
  already discloses. The resolver's 127.0.0.1 answer is a hint only: the dialled address is connect's own lookup.
- Concurrency and check-to-use: one lookup per connection, every answer vetted before any dial, sequential dials over that one set
  under a shared budget, no second lookup and no Happy Eyeballs (TestConnectVetsEveryAnswerOnEveryConnection); Go's singleflight
  dedups concurrent lookups of one name; the Go stub never chases a CNAME (a canary resolver answering `CNAME denied.example`, with
  and without the target's A, produced only A and AAAA queries for allowed.example.); the interface list is read per connect. No gap.
- Cryptography and identity: none on this surface. DNSSEC is not consulted (no DO bit, AD ignored, the OS resolver's validation is
  not visible); the only identity check on the path is upstream x509 for terminated hosts (S-1005).
- Failure modes (I11): the resolver is in-process and cannot die apart from the supervisor; a ReadFrame error or a nil Answer closes
  the stream; a lookup error or an empty set is resolve_failed, an unreadable interface list is blocked_address, an Accept error ends
  serveRelay and closes every adapter so Serve ends. No error path reaches a dial or a splice.
- Downgrade, rollback and replay: header version 1 only; the resolver is stateless, so a replayed frame gets the same reply; the
  product caches nothing across sessions; OS caches hold answers for allowed names only, since the host asks for nothing else.
- Interaction: DNS tunnelling moves at most 253 bytes per refused query into the host's own log and nothing off the host; the host's
  only outbound queries are A and AAAA of the rooted allowed name (I3). Forward ports map to one host each and the resolver answers
  that host too. The terminated transport's DialContext re-enters connect per upstream connection, so vetting is per connection, but
  that dial is detached from the guest's request: candidate C13 below.
- S-1004 handoff, the refused callback's host string (I9): the name reaching Deny is lowercase [a-z0-9.-] of at most 253 bytes, or ""
  for any other byte; audit clips at 253 and JSON-escapes. Names `-dash.example`, `a_b.example`, `x"y`, `x\n`,
  `x,"event":"session_end"`, a 253-byte name and the root went through resolver.New, p.Deny and a real audit.Create log: Verify
  passes, every line parses, denyReader prints one line each, the non-hostname ones as `denied (invalid) (dns): not a host name`. No
  forge, no second line, no confusion with a host-set field. The only suppression path is the SoftLimit fill (S-1010's design): about
  130 B per refused query at 240 streams/s or less is about 4.5 min to 8 MiB, against 1.3 s through the terminated path (S-1005).
- PARKED line 8, address-shaped names (I13): netip.ParseAddr refuses exactly what dnsName lets through, and Go's lookupIPAddr parses
  with netip first, then isDomainName refuses all-numeric names. With a local canary resolver, lookups of `01.2.3.4.`, `2130706433.`,
  `127.1.` and `1.2.3.4.5.` sent no query and gave resolve_failed; `0x7f.1.`, `localhost.` and `a.localhost.` went out as names (A and
  AAAA of the rooted name only) and any answer meets blockedAddr. absDomainName roots only dotted names, so a single-label /etc/hosts
  entry is skipped by the rooted lookup and DNS is asked instead. All operator-chosen: no guest path puts a name into the policy.
- PARKED line 44, resolver caches (I4): on darwin Go resolves through libSystem getaddrinfo, so mDNSResponder's cache applies; Linux
  pure Go has none; systemd-resolved caches per TTL. The product caches nothing and vets every address per connection, so a cached or
  stale answer changes which vetted address is dialled or gives resolve_failed; it cannot widen reach. The cross-session effect is on
  suite verdicts only (tests.go orders the no-data row last; workcell_darwin.go settle sleeps 16 s). Mac only, reasoned.
- PARKED line 7, untested variants (I3): only TCP to listed ports and UDP 53 cross the vsock. DoQ and h3 are UDP to 853 and 443 with
  no listener in the guest (udp4-datagram and quic-initial rows); mDNS and LLMNR have no device and no group membership; IPv6 forms
  share the dual-stack listeners and AnyIP ::/0 (relay rows and the `[fd00::1]:53` unit row); DoH over h2 to an allowed host at 443 is
  HTTPS to an allowed host, the operator's choice, and the terminated server offers http/1.1 only. No new row needed.
- S-1005 handoff, the transport's timeouts: a stall on the forward (splice) path holds the slot with the socket (5 guests gone, 5 slots
  held, 5 upstreams open), bounded by maxConns; a post-handshake stall needs a certificate valid for the allowed name, so only the
  provider (out of scope) can cause it, and the transport closes that connection on cancel. The handshake phase is C13.

Observations (R3, suite hygiene; not candidates): denyMessage's remedy for a refused name with a leading or trailing hyphen is one
ParseAllowlist refuses; PARKED line 26 is still open (the `forwarded` Want has no Resolver, so four forwarded rows ask the runner's
resolver for allowed.escape.test); a single-label allowlist name never matches /etc/hosts under the rooted lookup on Linux.

Coverage. Read in full: internal/resolver/resolver.go and resolver_test.go; internal/relay/relay.go and relay_test.go;
cmd/workcell/relay.go, relay_test.go, policy.go, log.go, ocsf.go; cmd/workcell/run_vm.go lines 230-369 (boot, bind, resolver wiring);
internal/proxy/proxy.go, allowlist.go, terminate.go, proxy_test.go, terminate_test.go lines 1-200; cmd/workcell-init/net.go as data;
internal/audit/audit.go and lines.go; escape/suite/dns.go, dnstests.go, resolver.go, rebind.go, tests.go;
escape/sandbox/control_resolver_linux.go; ADR-003; docs/policy.md; PARKED.md; SPEC sections 2, 3, 6, 11 and 13; FINDINGS lines 1-133
and 404-521; Go 1.27 net/http transport.go (getConn, wantConn, dialConnFor, addTLS, CloseIdleConnections), net lookup.go, hosts.go,
dnsclient.go absDomainName, conf.go and cgo_unix_syscall.go. Skimmed: terminate_test.go past line 200; signin.go (Deny sites);
escape/sandbox workcell_vm.go, workcell_darwin.go, workcell_linux.go, workcell.go, sandbox.go; escape/suite/relay.go and helpers.go;
docs/threat-model.md; loop/gate.sh budgets; the proxy forward, clients, c10 to c12, git and providers tests by name. Not opened:
internal/proxy/signin_test.go, escape/suite/packets.go and icmp_linux.go, the remaining sandbox files, cmd/workcell/explain.go,
docs/providers.md, _legacy/. Ran: go test ./internal/proxy ./internal/resolver ./internal/relay ./cmd/workcell on the tree (green) and
nine overlay probes; nothing needing a VM; no probe left the session. terminate.go and proxy.go are ported, so C13 is an ordinary
public candidate under section 13 with its `also in v1 main` line; cmd/workcell/relay.go is not ported. No model declined, and no
safeguard re-ran a request.

### S-1006 candidates

C13. ID I10 (host memory, file descriptors and goroutines), on the I4 rebind path; I11 holds. Attacker: the network attacker as the
host's DNS for an allowed name (the model of the rebind-* rows, map row 14), with guest root making requests. Where:
internal/proxy/terminate.go Terminate, the http.Transport literal (no TLSHandshakeTimeout, no MaxConnsPerHost; DialContext ignores
its ctx and calls connect), with internal/proxy/proxy.go connect, which bounds only the TCP dial. Input: the host resolver answers an
allowed bare (443) name with a public address the attacker runs, whose TCP accept completes and whose server never answers the
ClientHello (a SYN-dropping variant is bounded by the 30 s dial budget). The guest opens a terminated connection, sends
`GET / HTTP/1.1\r\nHost: <name>\r\n\r\n`, waits about 100 ms and closes; repeat at the vsock connect rate. Effect: Go 1.27 net/http
dials on context.WithoutCancel, so the upstream dial is detached from the request, and with TLSHandshakeTimeout 0 the handshake waits
on the attacker forever. The guest's close ends the handler and releases the relay slot and the proxy slot, but the upstream socket
and two goroutines stay. Measured by the auditor: 600 requests in 2.5 s left 0 slots held, 600 handshakes open, +600 fds, +1200
goroutines and +24.9 MiB heap (42.5 KiB each), never closed: about 10 MiB/s and 240 fds/s of host growth outside the 1024-slot bound
for as long as the attacker holds the sockets. At the fd ceiling Accept fails and the guest loses network (fail closed), but the
memory is the host's. By contrast a stall on the splice path holds its slot with the socket (bounded by maxConns), and a
post-handshake stall needs a certificate valid for the allowed name (the provider, out of scope) and is closed on cancel.
Reproducing test: escape/_pending/S-F8/c13_test.go, TestUpstreamHandshakeEndsWithTheGuest (redteam; package proxy, 53 lines, run by
overlay): 8 guests each send one request to a tarpit upstream and close; fails on 9e88cea after 12 s with eight lines `upstream
connection N is still held with no slot held, 12s after its guest closed`, with zero proxy slots held. Outcome: CONFIRMED, high, by
the verifier: its own 45 s probe saw `slots held after guests closed: 0; goroutines 4 -> 44; fds 10 -> 50` and `after 45 s: 20 of 20
upstream connections still open`, past dialTimeout (10 s) and connectBudget (30 s), so this is no nearby bound; the dial stub stands
in for the host resolver returning a public address the attacker runs, the guest side is a plain TLS connection plus one HTTP/1.1
request, and Terminate marks every allowlisted 443 name terminated, so no rule or broker is needed; the host's resolver is "a host not
on the allowlist" in section 2's words, the same position the rebind-* rows use, so no precondition lies outside section 2 (the
verifier notes that a maintainer who reads the LAN-DNS position as a precondition would make it medium; both the auditor and the
verifier read it as high). The "no idle timeout, like splice" comment covers the guest-side hold, which a slot bounds; the upstream
pre-handshake hold sits outside the bound, so it is not intended. Fix unit: S-F8, below S-1006 in PLAN.md.
also in v1 main: egressproxy/terminate.go
C13 FIXED by S-F8, commit 4015cf7 (PR #207). Terminate's http.Transport literal in internal/proxy/terminate.go sets
TLSHandshakeTimeout to dialTimeout (10 s) in place of the zero-valued ForceAttemptHTTP2, so an upstream that accepts TCP and
never answers the ClientHello is dropped within the dial timeout after the guest has closed, and MaxConnsPerHost to maxConns
(1024), so the dials the transport holds for one host are bounded by the slot cap as well; the line for the second was paid
by deleting the dead shed queue of S-1004 C8 (PARKED line 60: shed, lost, the goroutine in New, the select in Serve, and
TestServeCountsRefusalsTheQueueDropped with stalledLog and countingListener, 17 product and 87 test lines). The pending test
became internal/proxy/c13_test.go TestUpstreamHandshakeEndsWithTheGuest, unchanged but for its head comment: eight guests
each send one request to a tarpit upstream and close; it fails on the parent in 12 s and passes on 4015cf7 in 10 s. The
reviewer ran both and found nothing: a request queued behind the per-host cap waits on its own context, which the server
cancels when the guest closes, and the proxy makes no request of its own on the transport, so sign-in cannot be starved.
Product 14984 of 15000.

C14. ID I9 (every connection attempt recorded). Attacker: guest root speaking the relay header itself. Where: cmd/workcell/relay.go
stream, the branch for a UDP header to a port other than 53. Input: a version-1 relay header with proto 17 and any port but 53, for
example UDP 5353. Claimed effect: the stream is closed with no audit record, while the same header with proto 6 to an unserved port is
recorded as port_not_allowed; nothing is dialled or reached. Reproducing test: TestStreamRecordsARefusedUDPHeader (package main, 36
lines, run by overlay): fails on 9e88cea with `proto 6 to port 5353 recorded ":5353 port_not_allowed"` beside `proto 17 to port 5353:
the closed stream recorded nothing`. Outcome: REFUTED by the verifier. The mechanism is real but it is tested, intended behaviour: the
init has exactly one UDP producer (cmd/workcell-init/net.go, a hard-coded header to 127.0.0.1:53) and one UDP listener (:53), and under
the AnyIP route a guest datagram to any other port is answered port-unreachable by the guest's own kernel (the udp4-datagram and
quic-initial rows pin that on a real VM), so the host never has an event to record and the only author of a UDP-5353 header is the
forger, who creates the one record he then calls missing. relay_test.go rows "UDP on a served port", "UDP on an unserved port" (5353
exactly), "version 2", "version 0", "proto 0" and "proto 1" all want no record, and relay.go's header comment states the contract: a
UDP non-53 header is hostile bytes on the channel (I12), not a connection attempt the policy could ever name (I2 has no UDP allow; the
TCP record exists because the log can tell the user how to allow host:N). C8's reasoning carries: nothing is dialled, no reach is
gained, no existing record is altered, and the I9 rows are untouched. Low ceiling under S6, and adding a record for an input only its
author can produce would be a new check without a defect that reached a user, so it is not a hardening item either. The test was deleted.

## S-1007: secrets: sources, placeholders, sign-in token swap, git credentials, logs, crash output (I5), as built at main 071a385

Trust boundary. Guest root and hostile model output own every byte of a terminated request after S-1005's parsing: the header values
judged by placeholderForm, the method and path judged by admits and tokenEndpoint, the token-endpoint body (256 KiB) read by
tokenRequest, and the timing and concurrency of requests. They also own the guest's environment, disk and memory, where only
placeholders ever arrive (wcph- plus 32 hex, 16 bytes of crypto/rand per rule and per sign-in, minted per session in
cmd/workcell/policy.go bindings), through guest.Exec Env alone (run_vm.go session; pull and bench boot with nil secrets). The network
attacker owns no upstream byte on this surface: the token host's answers are verified x509 (S-1005), and an allowed identity
provider's behaviour (rotation, echo) is a provider trait, not an attack. The operator (out of scope) owns the [[secret]] rows,
sources and env names. Authority: the supervisor, as the operator's uid, reads the value per use (a file open, or a child process
with a scrubbed env plus HOME, DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR, at a fixed path with no shell, A8), writes it into the
one outbound header or token body, records every release and denial in the session's audit log before the value leaves (fsynced),
holds sign-in tokens for the session in broker memory, and rewrites token-endpoint answers before the guest sees a byte. Lenses
worked in order: parsing and resources, logic and state, concurrency and check-to-use, cryptography and identity, failure modes,
downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real packages, nothing in the tree changed,
every listener the probe's own on 127.0.0.1; nothing here needed a VM):
- Parsing and resources, sources: file: needs an absolute path, Stat then a regular-file check, one 64 KiB+1 buffer, one line, trailing
  newline trimmed, CR refused (TestResolveFile); a FIFO is refused by the Stat check without opening, so no block (probe: `is not a
  regular file`); a symlink is followed and no mode is checked (a 0644 file and a linked file both resolve), both operator paths with
  no in-scope attacker (a guest reaches a host path only in --mount mode and only inside the operator's own tree; a FIFO swap between
  Stat and Open would park one handler, bounded by maxConns, and needs the operator to keep the secret inside the export). cmd: is
  strings.Fields of the operator's text, absolute program, no shell; secret-tool and security at fixed paths with `lookup service S
  account A` and `find-generic-password -s S -a A -w`; the value never enters argv or env of the child, whose env is PATH, LC_ALL and
  the three passed names only (TestResolveCmdRunsProgramWithScrubbedEnv). Output() captures stderr into ExitError.Stderr, which %v
  never prints (os/exec ExitError.Error is ProcessState.String); a timeout gives `signal: killed` with a canary on stdout and stderr
  absent; partial output is zeroed on every error path. The proxy drops the broker's error text (broker_denied), so no path name
  reaches the guest, and no Resolve runs at start, so none reaches the terminal either.
- Parsing and resources, placeholders: 128 bits of entropy, exact regex, two placeholders per sign-in row; a placeholder from another
  session or binding is refused wherever it stands: no rule's placeholderForm matches it and carriesPlaceholder refuses it in any
  header name or value, Basic decoded, or the target raw or decoded (502; existing tests and FuzzCarriesPlaceholder). A value that is
  itself placeholder-shaped is refused after the swap (fail closed). Token body 256 KiB and header block 64 KiB (S-F6) bound a held
  slot; 256 MiB at the cap is the hang half of C11, parked.
- Logic and state, where a placeholder is useless: another allowed 443 host, another header, the path, the query, a cookie-shaped
  value, the Basic user, two values, a suffix: all refused (TestTerminateRefusesUnswappedPlaceholder, placeholder-misplaced); a
  forward port, an Upgrade tunnel after 101 and a CONNECT (405) carry raw bytes with no swap (S-1005); a redirect to the other host
  carries the placeholder, refused there (redirect-carries-secret); a Host header holding a placeholder is 421 host_mismatch; a
  placeholder as the HTTP method is not scanned but reaches the bound host alone, as a method. Narrowing, through c10's folding
  upstream with hand-written request lines: `POST /oauth\token` (a raw backslash, which net/http accepts), `/oauth/x/%2e%2e/token`,
  `/oauth/./%2e%2e/oauth/token` and `Host: LOGIN.EXAMPLE.COM.` are read as the token endpoint and answered with placeholders;
  `/v1\..\admin`, `/v1/.%2e/admin`, `/v1/%2e./admin` and `/octo/allowed.git\..\other.git/info/refs` are 403 binding_mismatch with
  the secret withheld; `/v1/x/%5c..%5cadmin` folds to /v1/admin on both readings and is admitted, correctly. Repository scope: 12
  spellings refused in TestTerminateNarrowedRule and repo-token-elsewhere, plus the ;param forms of c10; real git clone and push
  through the proxy carry the token for octo/allowed alone (TestGitOverHTTPS). The data files bind one header each (x-api-key,
  authorization Bearer, x-goog-api-key); a CLI that instead sends `Authorization: token <ph>` (the Copilot exchange U-406 suspects,
  PARKED line 32) or `?key=<ph>` (Gemini's query form) is refused 502, a denied login and never a leak.
- Logic and state, token answers: a 2xx that is not one JSON object is refused whole; non-2xx are hidden and passed; gzip, chunked,
  escaped and oversize framings are covered (TestTokenAnswerFramings, signin-gzip, signin-chunked); hide's JSON pass covers every
  string of a decoded body, keys included after re-encoding, the plain pass the raw bytes, and the two wire spellings swapRefresh
  sends (S-F7). Probed: verbatim, QueryEscape, JSON \u escapes of ASCII (decoded first) and json-escaped-in-text are hidden;
  lowercase-hex percent-encoding (a%2bb), PathEscape's partial encoding (a+b%2Fc), double encoding and base64 are not, each needing
  an identity provider that echoes and re-encodes: residual for the report (PARKED line 69 judged), not a candidate. Duplicate JSON
  keys, encoded keys, ;-separated forms and a second refresh_token field all leave the placeholder in place and are refused
  placeholder_unswapped.
- Concurrency and check-to-use: Resolve's value goes into the header in the same statement sequence, no gap; grants and tokens maps
  are immutable after NewBroker; held and Issue run under mu and return clones, so two concurrent sign-ins are both hidden (each
  learn's swaps are its own copies); Issue after a ledger failure leaves tokens held, but every later release fails record and is
  zeroed (fail closed). The one cross-request gap is C15 below.
- Cryptography and identity: none beyond the placeholder entropy and S-1005's TLS; the ledger seal is S-1010's.
- Failure modes: every error path answers 403, 405, 421 or 502, or closes; a bad source scheme or a missing tool is a per-use
  broker_denied (TestResolveSecretServiceFailsClosedWithoutTool); a closed, failing or nil ledger withholds every value
  (TestGrantIsWithheldWhenTheRecordIsNotDurable); ModifyResponse errors give an empty 502 (ReverseProxy's default error handler logs
  to the discarded ErrorLog); handler panics are recovered per connection by net/http and logged to the discarded ErrorLog; a
  supervisor crash traceback prints pointers and lengths, never string bytes. Nothing fails open.
- Downgrade, rollback and replay: the two placeholders are constant across refreshes by design; a new session mints fresh ones, so a
  placeholder a CLI persisted in the workspace is refused next session; a guest that replays a code grant replaces the held tokens
  with its own account's, gaining nothing; a token answer cannot be forged (upstream x509); the broker's window uses monotonic time.
- Interaction, logs, terminal and crash output: audit records carry Event, Host, Header, Name and Result (clipped, JSON-escaped),
  never Source or a value (TestLookupReleasesOnlyGrantedPairs, TestSignInGrant assert no sk- in the ledger); `workcell log` prints the
  raw secret line and ocsfLine maps the same fields; `workcell explain` prints name, header, host, narrowing, sign-in endpoint and
  $ENV, no source; run's startup errors name file:line, host and name, and NewSignIn's %q of a sign-in source holds no secret; the
  guest Exec env is PATH, HOME, LANG, TrustEnv, cache vars, placeholders and the host's TERM; the escape rows' Detail prints the
  guest's placeholder and test values only. I5's guest side is pinned by secret-in-guest (/proc environ and cmdline, disk, process
  memory) and signin-scan.
- Map row 24, the per-request secret-source process (I10): measured, candidate C16 below, low.

Observations (R3, not candidates): internal/provider/provider.go checkKeys accepts optional `file` and `field` keys in a [[secret]]
row that parse never stores and no code reads, since no placeholder file is ever written (run_vm.go passes env only): two dead data
keys. cmd/workcell/policy.go bindings accepts an env name the host sets itself (PATH, HOME, LANG, TERM, SSL_CERT_FILE and the other
trust variables); the placeholder line comes last and wins, so the guest's PATH or trust store becomes a placeholder string: operator
misconfiguration, fails closed. Non-token answers of a bound host are never scanned, so a bound host that echoes the credential
header returns the real bytes to the guest (the fixture upstreams echo by design; a real API that prints a masked key on an invalid
key does the same): the bound host is the trusted destination, so this is residual risk for docs/security-review.md. tokenEndpoint
has no method check, so any method with a body reaches the token endpoint swapped (same host and path, no leak); only access_token
and refresh_token are hidden, so an id_token or other field reaches the guest as issued (the U-403 class, PARKED line 31). The header
string, the Basic base64 string, hide's spelling copies and json.Marshal outputs are host-side GC copies that cannot be zeroed, and
none reaches the guest. repoSegment refuses upper-case repository names while GitHub treats them case-insensitively: fails closed.
Residual for S-F5's fold: NUL truncation (`/oauth/token%00`) and overlong UTF-8 dot segments are not modelled; both need an exotic
router.

Coverage. Read in full: internal/secret/source.go, broker.go, source_test.go, broker_test.go, keychain_darwin_test.go;
internal/proxy/signin.go, terminate.go, proxy.go, allowlist.go, signin_test.go, terminate_test.go, git_test.go, providers_test.go,
c10_test.go, c11_test.go, c12_test.go, c13_test.go; internal/provider/provider.go and the four *.toml; cmd/workcell/policy.go,
explain.go, run_vm.go, log.go, ocsf.go, main.go; internal/audit/audit.go, lines.go, key.go; internal/policy/policy.go lines 30-320
(Secret, Read, ReadRepo, Narrow, Parse, secretRow); cmd/workcell-init/main.go, exec.go; internal/guest/guest.go lines 1-120 and
TrustEnv; escape/suite/secrets.go, signin.go, https.go, terminate.go, tests.go lines 100-160; escape/sandbox/workcell_vm.go lines
268-300; docs/providers.md lines 15-40, docs/policy.md lines 100-125; SPEC sections 2, 3, 4, 6, 8, 11, 13; FINDINGS lines 1-110 and
522-835; PARKED whole; GOROOT os/exec Output and ExitError.Error, net/http/httputil ReverseProxy X-Forwarded and defaultErrorHandler,
net/http conn.serve panic log, encoding/json appendString escaping. Skimmed: proxy_test.go fixtures (testProxy, listen, testLedger,
denies, recorder), internal/fileserve/ops_linux.go for mknod (none), cmd/workcell/pull_vm.go and bench_vm.go boot calls, cache_vm.go.
Not opened: internal/proxy/allowlist_test.go, forward_test.go, clients_test.go, proxy_test.go beyond the fixtures,
cmd/workcell/relay.go and session.go, escape/suite/repo.go, escape/sandbox control adapters, internal/provider/provider_test.go,
docs/threat-model.md, _legacy/ (v1 paths taken from the ported headers). Ran: go test ./internal/secret ./internal/proxy
./internal/provider ./internal/audit ./cmd/workcell on the unchanged tree (green) and four overlay probes (the race probe five times
and once under -race); nothing on a VM or against a real provider (T8, S12); no probe left the session. source.go, broker.go and
terminate.go are ported, signin.go is not, so C15 in signin.go carries no `also in v1 main` line and C16 does; nothing is private
under section 13. No model declined, and no safeguard re-ran a request.

### S-1007 candidates

C15. ID I5 (a real token the broker holds never appears in an answer to the guest; signin.go's own contract says "whatever its
status"). Attacker: guest root, or hostile model output, choosing request timing. Where: internal/proxy/signin.go learn (hide's swaps
are p.broker.Tokens, the tokens held now, plus those the answer issues) and tokenRequest (the refresh value it swapped in is cleared at
once and never reaches learn); internal/secret/broker.go Issue zeroes the replaced refresh token and keeps one generation; terminate.go
neither serialises token-endpoint requests nor passes the swapped-out value from tokenRequest to tokenResponse. Input: after a
sign-in, with the broker holding access A1 and refresh R1 behind the two placeholders, the guest sends two refresh requests at once,
each `POST /oauth/token` with `grant_type=refresh_token&refresh_token=<refresh placeholder>`; the proxy swaps both to R1 before either
answer arrives (tokenRequest runs before the upstream is asked); the provider answers the first with a new pair (A2, R2) and the
second, now stale, `400 {"error":"invalid_grant","error_description":"refresh token sk-ref-1 was already used"}`. Effect: learn for
the second answer hides (A2, R2) only, so R1, a refresh token the broker held until a moment before, reaches the guest verbatim. Dead
at a provider that revokes on rotation (then the gain is the bytes alone, and the stated rule is still broken); live at one with a
reuse grace window, and the guest can never re-present R1 through the proxy, so this echo is its only route to it. Preconditions the
attacker does not control: the provider rotates refresh tokens on use and echoes the presented token in its error (the echo
precondition C12 carried; the suite's own fake provider does both, row signin-error-echo); the concurrency is the attacker's. API-host
answers are never scanned, so no access-token analogue exists on this path (observation above). The auditor's probe, through the real
proxy, broker and ledger, failed 5 of 5 and clean under -race. Reproducing test: escape/_pending/S-F9/c15_test.go
TestConcurrentRefreshHidesTheReplacedToken (redteam; package proxy, 75 lines, run by overlay): the real Terminate, secret.NewBroker
with a signin grant and a real audit ledger against a loopback provider that holds both refreshes until both have arrived, rotates on
the first and answers the second 400 with the echo only after the guest holds the first answer, so the order is deterministic; it fails
on 7cc6129 (the tree of main 071a385) with `the guest read a real token: 400 {"error":"invalid_grant","error_description":"refresh
token sk-ref-1 was already used"}`, 5 of 5 and under -race with no data race, and only this test fails in the package. Outcome:
CONFIRMED, medium, by the verifier: it re-ran the test 3 of 3 on 7cc6129; the loopback provider does nothing an allowed provider would
not, since the hold only makes the natural order (rotate, 200, then reject the stale one) deterministic and the attacker can fire N
refreshes and retry; docs/providers.md bounds exposure (sign-in unsupported, proven only against the test endpoint) but does not
sanction the leak; the sequential echo is covered by TestSignInFlow's bad-grant row and C12, so this is the rotation race alone;
medium fits S6 as C12's precedent, not low (a break is shown) and not high (the provider's rotation, echo and grace window are
needed). Fix unit: S-F9, below S-1007 in PLAN.md. signin.go is not ported, so no `also in v1 main` line.

C15 FIXED by S-F9, commit ba8a401 (PR #209). tokenRequest in internal/proxy/signin.go clones the refresh token the broker released
for swapRefresh before swapRefresh wipes its copy, and returns it beside the body; serveTerminated in internal/proxy/terminate.go puts
a tokenCtx (the rule and that clone) under tokenKey in place of the bare rule, and its deferred clear, registered before the refusal
check, wipes the clone on every path; tokenResponse hands the clone to learn, which seeds its swaps with it as a third spelling of the
refresh placeholder, so the token the request itself carried is hidden in text, url-escaped and JSON-escaped, even once another request
has rotated it out of the broker, and the existing deferred clear wipes it. Product 14994 of 15000, +10 (gofmt lays the struct out on
four lines). Regression test: internal/proxy/c15_test.go TestConcurrentRefreshHidesTheReplacedToken, moved whole from
escape/_pending/S-F9/ by the redteam, failed on the parent 5 of 5 and under -race, passes on ba8a401; the reviewer re-ran it on a
worktree of main (3 of 3 fail) and on the branch (3 of 3 pass) and found nothing. escape/_pending/ is gone.

C16. ID I10 (host CPU, processes and file descriptors), map row 24, the no-row surface the S-1005 handoff named. Attacker: guest root.
Where: internal/secret/broker.go release (one Resolve per granted lookup) and internal/secret/source.go run (one child process with three
pipes per cmd:, secret-service: or keychain: use, 2 min timeout). Input: 300 requests carrying the placeholder in the bound header
within one minute (the rate window), all at once. Effect: one host process per guest request, outside the guest's --cpus cap. Measured
by the auditor (package secret by overlay, a sleeping cmd: program marking its pid): `310 concurrent lookups: granted 300,
rate_limited 10, in 2.3 s; peak concurrent child processes 300; fds 8 -> peak 908 -> after 8`; a program that runs to its 2 min
timeout lets the next window add 300 more, so about 600 processes and 1800 fds at most, and the ledger grows by at most 600 lines a
minute. With `security` each use is a keychain prompt until the operator clicks Always Allow; with a vault CLI each is a vault call;
v1 resolved once at start. No invariant breaks: processes, fds and ledger lines all stay bounded by the window. Outcome: low under S6
(hardening with no demonstrated break), measured only; no reproducing test and no fix unit, as S-1004's C9. Listed for
docs/security-review.md (S7) and for S-1013's chains. If hardening is wanted after the freeze: resolve program sources once per
session and hold the value in the broker under mu, zeroed at Close, as the sign-in tokens already are, about 10 lines in broker.go and
one sentence in docs/policy.md; lowering the window would throttle legitimate use at 5 requests a second.
also in v1 main: credbroker/cli.go (source.go) and credbroker/server.go (broker.go)

## S-1008: workspace export in both modes, and the return path (I1, I8), as built at main 2b03762

Trust boundary. Row 5 (pull, diff): guest root owns every Entry, Data and Exit frame on vsock 5000 of the pull VM, which boots the
session's guest-written workspace.ext4 with no network and default caps; they enter at cmd/workcell/pull_vm.go pulled.frame, then
manifest (guest.DecodeEntry, manifest.add, checkPath and fold in pull.go), then put and sameBytes, then end. Authority: the CLI as the
operator's uid holding dest open O_DIRECTORY: it unlinks non-directories and empty directories, makes directories 0755, symlinks with
any target and files 0644 or 0755 holding the guest's bytes, each path resolved with openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS
(pull_linux.go) or O_NOFOLLOW_ANY (pull_darwin.go); it prints guest strings quoted on stderr (shown) and as diff lines on stdout. The
whole manifest is judged before the first byte is written. Row 15 (mount mode): guest root owns every FUSE request frame on the first
vsock 5002 connection, including raw frames written on a duplicate of the init's socket (pidfd_getfd, as stealChannel does; ADR-005
names this attacker); they enter at internal/fileserve/serve_linux.go Serve, codec.go parse and checkName, ops_linux.go op.
Authority: the supervisor as the operator's uid holding the export fd and one fd per directory node; *at syscalls with O_NOFOLLOW;
creates, unlinks, renames, truncates and chmods (0777-masked) inside the export; grow() charges file-size growth against --disk.
Row 16 (clone export): the malicious repository shapes the operator's cwd tree, read by internal/workspace/workspace.go Export (fd
walk, Fstatat NOFOLLOW, Readlinkat, hard links by dev and ino), internal/rootfs tree.go and ext4.go, and ext4file.go openSource
(O_NOFOLLOW|O_NONBLOCK with a dev, ino, size and regular re-check), which writes sessions/<id>/workspace.ext4 0600 in the data
directory. Row 19: git metadata returns only through row 5; checkPath refuses a .git component in any ASCII case; guest.Walk skips
.git on both sides; the host runs no git. Row 21: --disk is the image's free room (clone) or the grow() cap (mount). The host relies
on the guest for nothing (A1); entry order only decides success. Lenses worked in order: parsing and resources, logic and state,
concurrency and check-to-use, cryptography and identity, failure modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real packages, nothing in the tree changed;
every target a file or process of this session, one 64 KiB tmpfs mounted and unmounted inside it for an ENOSPC probe; nothing here
needed a VM):
- Parsing and resources, pull: guest.DecodeEntry bounds every index (len >= 12, n in 1..MaxPath, len >= 14+n, len == 14+n+t,
  t <= MaxPath, Exec 0 or 1, Size >= 0, kind-specific zeros); manifest.add bounds entries (1M), name bytes (64 MiB) and file bytes
  (at most the image's apparent size, judged as e.Size > limit-bytes so no sum wraps) and refuses case-fold collisions (fold's orbit
  equals EqualFold's, the k and Kelvin row); checkPath refuses empty, over 4096, NUL, non-UTF-8, absolute, and empty, dot, dotdot
  and .git components; the worst-case host memory for a hostile manifest is about 280 MiB, bounded by constants; a 64 KiB Data frame
  is the unit of host memory per frame. checkPath, fold and add were read for panics and none was found: the T5 fuzz target that
  S-1001 asked for is still absent, a test-line item for a fix unit, not a defect. The pull's limit is the image's apparent size,
  the operator's --disk plus the repository, so a pull writes at most the operator's own cap.
- Parsing and resources, mount: parse checks every length before every index, walked case by case against the fuse.h 7.37 sizes
  (init >= 16, getattr 16, setattr 88, open, opendir, access and interrupt 8, read and write 40 with Size equal to the payload,
  release and flush 24, fsync 16, forget 8, batch_forget 8+16n exactly, statfs, readlink and destroy 0, names NUL-terminated and
  exactly counted); READ allocates min(size, 61440) per request with 16 in flight; readdir one 8 KiB buffer; node table 128K
  (ENOMEM) and descriptors 4096 (ENFILE); a SETXATTR larger than the init's 64 KiB buffer is ended by the guest kernel with E2BIG
  and never reaches the host. Export: names from Readdirnames hold no slash or NUL and rootfs split refuses over 255; Readlinkat's
  4097-byte buffer feeds validate's 4095 cap; a file over 32 GiB, more than 8M inodes, more than 65000 links to one inode all
  fail closed with ErrTooLarge, and depth overflows nothing (Go stacks grow).
- Logic and state, pull: the whole manifest is judged before the first write, so a refused entry writes nothing; Data bytes are
  consumed exactly Size per file in write and compare, so the stream stays aligned; end refuses leftover or extra Data and any
  Exit but the zero one; a corrupt or unmountable image yields an empty tree and the pull removes nothing. put keeps an existing
  directory for a directory entry, unlinks any other kind (a FIFO, device, socket or symlink in dest is replaced, never opened),
  refuses a non-empty directory (ENOTEMPTY) and creates with O_EXCL. Symlink targets are written as given and never followed by the
  product: the next Export Readlinkats them, openat2 RESOLVE_NO_SYMLINKS and O_NOFOLLOW_ANY refuse any path through them (TestWrite
  row "nothing is written through the symlink without its entry", row pull-through-symlink), fileserve opens O_NOFOLLOW and
  policy.ReadRepo O_NOFOLLOW (S-1009). Row 19: .git is refused in any ASCII case on the way back and skipped by Walk on both sides,
  so the guest's commits never return and the user's .git is never touched; .gitattributes, .gitmodules and hooks directories are
  written as data that nothing on the host obeys (pull-obeys-git-config, pull-fetches-submodule). Modes: pull writes 0644 and 0755
  only; fileserve masks to 0777 (no setuid) and MKDIR likewise; Export keeps 07777 bits in an image where everyone is root already.
  --mount comes from parseRun alone and run ignores [workspace] mode in both policies (row repo-policy-mounts-workspace);
  mount_darwin refuses the flag. FUSE state: EIO before INIT and after DESTROY, EPROTO for major != 7, minor negotiated down with
  fixed 7.37 layouts. PARKED line 17 and 18 ideas judged: raw names dotdot, a/b, NUL and 256 bytes are EINVAL before any syscall
  (adversarial rows 1-8, 67); OPEN on a symlink is ELOOP and on a FIFO, socket or device EPERM before the open (rows 9, 20, 21);
  RENAME to a nodeid the kernel never issued is ENOENT; FALLOCATE, LINK, MKNOD and every other opcode are ENOSYS with no syscall, so
  growth via fallocate KEEP_SIZE and a hard link inside the export are impossible for the guest; a rename from the guest's tmpfs into
  the export is EXDEV at the guest VFS, so mv copies and the copy is charged.
- Concurrency and check-to-use: pull has no in-scope concurrent actor (the VM only serves the pull; a concurrent --mount guest in the
  same directory, also the operator's, can only rename within the export and plant symlinks, which O_EXCL, EEXIST and
  RESOLVE_NO_SYMLINKS refuse). fileserve: life is held for reading by every descriptor-using request and for writing by FORGET,
  RELEASE, RENAME and Close, so no request uses a closed or reused descriptor and RENAME sees no half-moved node; at() re-checks
  every (parent fd, name, ino, dev) link of a directory chain, so a directory the host moved or replaced is ESTALE or ENOENT (rows
  14, 23); directory syscalls use the node's own fd and file opens use O_NOFOLLOW plus a post-open S_IFREG check (row 15: a file
  swapped for a symlink is ELOOP); the guest's own RENAME is serialised by life.Lock and cannot leave the export, so only the
  out-of-scope host user could win a race; the directory-to-symlink swap raced against LOOKUP then OPEN ends in ESTALE or ELOOP;
  concurrent grow() charges over-count, never under; a worker blocked in send times out at 5 s and ends Serve; FORGET waits for
  in-flight readers. go test -race ./internal/fileserve green. Export: openSource re-checks dev, ino, size and regular, so a swapped
  file, symlink or FIFO between walk and copy fails closed (TestSourceChecks); only a host-side actor could race it.
- Cryptography and identity: none on this surface by design; the first 5002 connection is the init's because no guest code runs
  before setup's dial; the host never parses the guest-written ext4 (map row 18).
- Failure modes: no fail-open found. Every pull error exits 1 or 2 after a refusal that wrote nothing (manifest) or a partial tree
  (stream errors, documented); a boot failure exits 125; an export failure removes the session directory; fileserve maps unknown
  errors to EIO, ends Serve on any stream error and Close releases every descriptor (TestStreamEnd), after which the init aborts
  the mount; openMount or Export failure stops the boot.
- Downgrade, rollback and replay: wire version 1 only; FUSE minor negotiated down with fixed layouts; node ids and file handles are
  never reused (rows 28, 35); the pull protocol is one-shot and a replayed frame is a stream error; the pull VM boots with
  defaults(), not the session's caps (harmless).
- Interaction with other surfaces: the pull boot passes a nil audit log and nil allowlist, so a relay or DNS frame from the pull
  guest records nothing and reaches nothing (S-1003); pull and diff refuse mount sessions by the absence of workspace.ext4; the
  mount-session record written before boot makes a failed --mount boot shadow the directory's earlier clone session for pull
  (fail-closed, PARKED line 17); two --mount sessions on one export have two caps (the operator's choice, 2x); a symlinked cwd fails
  fileserve.Open with ELOOP (TestOpen row; fail-closed DX, PARKED line 17); the data-directory interaction is C19 below. The
  mount-mode I1 rows dotdot and link-rename reach /workspace/.. in the guest kernel and never exercise fileserve's name checks, as
  PARKED line 17 noted: the raw-FUSE rows named under C17 would be the first real-VM exercise of the protocol tables.

Observations (R3, not candidates): pull's total time has no bound, since stallLimit is per frame (60 s between frames, 5 s within
one), so a guest that drips one entry per 59 s holds `workcell pull` as long as it likes; Ctrl-C ends it and one VM at its caps is
all it costs. A clone export that a repository shape makes fail (a 32 GiB sparse file, a 256-byte name) removes the session directory
and with it the session_start record, so such a start leaves no I9 record; the guest never ran. Mount mode exposes the real .git,
so hooks and config the guest writes there run at the user's next git command, A5's explicit option: residual risk for
docs/security-review.md, as is the hard-link sharing of a `git clone --local` repository (adversarial row 18 pins that the link is
served). A symlinked cwd records $PWD in the session's repo file, so a pull from the real path says no session has run (DX). STATFS,
Ino and Nlink pass the host filesystem's figures to the guest: information, not reach. maxFDs 4096 assumes the hard RLIMIT_NOFILE
leaves headroom; where it does not, a guest holding every slot starves the proxy and the audit log, fail-closed for the network.
A macOS lead for S-1016, unverified without a Mac: checkPath's .git test is EqualFold, whose fold of ".git" is ASCII-only, and a
case-insensitive APFS or HFS+ volume that folds U+0130 or U+0131 into i would land `.gIt/hooks/pre-commit` (dotted capital I) in
`.git/`; refute by creating `.git` and that spelling side by side on such a volume. Two names that differ only by NFC and NFD both
pass fold and collide on APFS, landing the second's content on the first inside dest; no .git spelling is among them (PARKED line
21). Interactive interrupt during a long clone export is deferred until boot (export takes context.Background()): DX only.

Coverage. Read in full: cmd/workcell/pull.go, pull_vm.go, pull_linux.go, pull_darwin.go, run_vm.go, session.go, explain.go,
mount_linux.go, mount_darwin.go, main.go, caps.go, data.go, backend_linux.go, pull_test.go, pull_vm_test.go; cmd/workcell-init/pull.go,
mount.go, main.go, root.go, exec.go; internal/fileserve/serve_linux.go, codec.go, ops_linux.go, adversarial_linux_test.go,
bounds_linux_test.go, harness_linux_test.go, codec_test.go; internal/workspace/workspace.go, workspace_test.go, clone_test.go;
internal/rootfs/ext4file.go, ext4.go, tree.go, ext4file_test.go; internal/guest/guest.go, walk.go; internal/wire/wire.go;
escape/suite/files.go, files_linux.go, repo.go, gitdir.go, floods.go, channel_linux.go, tests.go lines 1-200;
escape/sandbox/workcell_vm.go lines 280-420; docs/adr/accepted/002-workspace-default.md, docs/adr/005-mount-mode.md,
docs/threat-model.md lines 40-124; escape/enforced.txt; SPEC whole; FINDINGS whole; PARKED whole. Skimmed: cmd/workcell/update.go
(newInstaller, manifest, daily, startup), cmd/workcell/policy.go (configFile, loadPolicy), internal/vmm/firecracker/firecracker.go
(Check, Listen, Start), escape/suite/suite.go, escape/sandbox/sandbox.go. Not opened: cmd/workcell/log.go, ocsf.go, update_test.go,
relay.go, cache*.go, layer.go, bench*.go, term_*.go, verify_test.go; cmd/workcell-init/net.go, root_test.go; internal/rootfs/build.go,
layer.go, oci.go and their tests; internal/vmm/vz; the other suite and sandbox files; _legacy/. Ran: go test ./internal/fileserve
./internal/workspace ./internal/rootfs ./internal/guest ./cmd/workcell (green), go test -race ./internal/fileserve (green), four
overlay probes, a SimpleFold orbit check; nothing on a VM; no probe left the session (S12). No file on this surface carries
`// Ported from v1` (the ported files are internal/proxy, internal/secret and internal/audit/lines.go only), so no candidate below
carries an `also in v1 main` line, and nothing is private under section 13. No model declined, and no safeguard re-ran a request.

### S-1008 candidates

C17. ID I10 (host disk), the mount-mode growth cap that --disk sets and the row mount-disk-flood enforces. Attacker: guest root,
writing raw FUSE request frames on the init's vsock 5002 connection (a duplicate of PID 1's socket by pidfd_getfd, as stealChannel
does; ADR-005 says outright that guest root may speak the protocol itself). The kernel path cannot reach it, because the guest kernel
sends end-of-file offsets for O_APPEND; that is why raw frames are needed, not a reason to exclude them. Where:
internal/fileserve/ops_linux.go openFlags (keeps O_APPEND on the host descriptor) and opWrite (charges grow(fd, offset+len) by the
request's offset, then pwrites at that offset); internal/fileserve/serve_linux.go grow (an end at or below the current size is free,
and its comment states the intent "never less than the growth"). Input: INIT; CREATE or OPEN with flags O_RDWR|O_APPEND; WRITE(offset
0, 60000 bytes) twenty times against a 100000-byte cap. Effect: Linux pwrite on an O_APPEND descriptor appends whatever the offset
(pwrite(2) BUGS), so every WRITE after the first ends at or below the recorded size, is charged nothing, and still appends: the host
file is 1,200,000 bytes, twelve times the cap, with no ENOSPC, and nothing bounds it. The auditor's probe against the real Server over
the harness pipe showed it, and pinned the kernel fact (three pwrite of 4 bytes at offset 0 on an O_APPEND fd: size 12). Reproducing
test: escape/_pending/S-F10/c17_test.go TestGrowthCapAppend (redteam; package fileserve, run by overlay; arms create and open through
the package's own kern and startCapped helpers): on 2b03762 both arms fail with `20 writes of 60000 at offset 0 with a cap of 100000:
20 accepted, 0 ENOSPC, file is 1200000 bytes on the host`, 0.01 s; the redteam showed it passes under two scratch fix shapes (drop
O_APPEND from openFlags: 20 accepted, file 60000 bytes; or write and charge an append handle at the current end: 1 accepted, 19 ENOSPC)
with TestGrowthCap still green under both. Outcome: CONFIRMED, high, by the verifier: the test uses fileserve.Open plus Server.Serve
over a pipe, the same pair mount_linux.go and serveMount use with caps.disk(), and os.Stat on the export shows host disk, not a
bookkeeping artefact; the attacker takes no power beyond frames the host accepts on the one 5002 stream, which guest root reaches
through the untrusted init (A1); I10 is in enforced.txt, the row mount-disk-flood (Want cappedLive, judge bounding host free disk and
file size to cap plus slack) claims the cap in mount mode, and map row 21 names grow as that enforcement; high under S6 because mount
mode is a supported product mode with its own enforced I10 row and the attacker needs no further precondition inside a mount session,
medium only if --mount (A5) is read as an S6 precondition; either way S7 fixes it before cutover. Fix unit: S-F10, below S-1008 in
PLAN.md. Variants for S-F10 to carry: SETATTR size shrink then WRITE at offset 0 on an O_APPEND handle (both fix shapes cover it);
two WRITEs in flight on one O_APPEND handle are each charged as if alone, never less than the growth, so no second hole. Not ported.

C17 FIXED by S-F10, commit bd49c0f (PR #232). openFlags in internal/fileserve/ops_linux.go is now O_ACCMODE | O_TRUNC, so a
host descriptor opened through OPEN or CREATE never carries O_APPEND and opWrite's pwrite lands at the offset that grow charged;
net 0 product lines, the comment on the same line says why. TestGrowthCapAppend, moved from escape/_pending/S-F10/ to
internal/fileserve/c17_test.go unchanged, fails on main 445ca1d (both arms: 1,200,000 bytes against a cap of 100,000, 0 ENOSPC)
and passes at bd49c0f under -race with TestGrowthCap and the rest of the package. The reviewer drove the real Server over the harness
pipe at HEAD: the SETATTR-shrink-then-WRITE-at-0 variant gives 1 accepted, 19 ENOSPC, host size 0; a WRITE at offset 0 after one at
offset 10 overwrites in place (size 11, no append); WRITE at 1<<40 is ENOSPC; two O_APPEND handles alternating WRITE(0, 60000)
twenty times leave 60,000 bytes; no op in ops_linux.go other than opWrite and setattr(fattrSize) changes size, and FALLOCATE,
COPY_FILE_RANGE and LSEEK are ENOSYS, so no guest request places bytes at a host offset other than the charged one. Nothing changes
for a correct guest: initFlags does not negotiate writeback cache, so the guest kernel sends the end-of-file offset itself. Not ported.

C18. ID I10 (host disk and inodes), the same cap. Attacker: guest root, or any guest process, through the ordinary kernel FUSE path:
plain `ln -s` and `mkdir` under /workspace in a mount session; no raw frames. Where: internal/fileserve/ops_linux.go opSymlink, opMkdir
and the create path call Symlinkat, Mkdirat and Openat and never grow(); internal/fileserve/serve_linux.go grown counts WRITE past the
end and SETATTR size only, while its comment says the host loses at most limit however the guest mixes them, as a clone's image is
fixed-size. maxNodes (128K) does not bound entries, since FORGET frees nodes and guest root forces it with drop_caches. Input: against a
100000-byte cap, 200 SYMLINK requests with distinct names and 4000-byte targets, and 200 MKDIR requests. Effect: every request is
accepted and none answered ENOSPC; on ext4 or xfs each such symlink or directory takes a 4 KiB block (819,200 bytes per arm, eight times
the cap) and every entry takes a host inode, whose count ext4 fixed at mkfs; at ADR-005's measured rate of about 5,000 requests a second
that is about 20 MiB/s of blocks and 5,000 inodes a second with no ceiling, so an hour fills tens of GiB and about 18M inodes, after
which every program of the operator gets ENOSPC whatever the byte cap. Reproducing test: escape/_pending/S-F11/c18_test.go
TestGrowthCapEntries (redteam; package fileserve, run by overlay; arms symlink and mkdir; the judge is the count of entries accepted
without ENOSPC against limit/4096 plus 2, so it holds on tmpfs and btrfs too, with the st.Blocks sum logged): on 2b03762 both arms
fail with `200 accepted, 0 ENOSPC; the host holds 200 entries (inodes) and 819200 bytes of blocks against a cap of 100000`, stable 3 of
3. Outcome: CONFIRMED, high, by the verifier: startCapped is Open plus Serve over a pipe, the same path TestGrowthCap uses, with
well-formed frames the guest kernel emits for ln -s and mkdir, no extra power; I10 is claimed here and not intended behaviour
(serve_linux.go's own comment, the enforced row mount-disk-flood, docs/threat-model.md, ADR-005's I10 bounds that do not exclude
entries), and the row's judge samples free disk and file size only after a write or truncate probe, so entry growth was never
exercised; the clone image bounds blocks and inodes together, mount mode bounds neither for entries; the pass condition is fair, since
the current behaviour is unbounded and the threshold admits a fix that charges 4 KiB per entry or the symlink's target length (one
nit: a fix charging real st.Blocks on a 1 KiB-block filesystem would fail it); high for the reason C17 gives, medium only under the
A5 reading. Fix unit: S-F11, below S-1008 in PLAN.md. Variants for S-F11 and S-1013: CREATE of an empty file (an inode, no block) is
also uncharged and the test leaves it out, so a fix may choose; a RENAME-over or MKDIR-then-RMDIR cycle should give nothing back, as
grow does; 255-byte names inflate the parent's directory blocks. Not ported.

C18 FIXED by S-F11, commit 98cc62a (PR #233). charge(e, n) in internal/fileserve/serve_linux.go takes s.mu, is ENOSPC once n would
pass limit-grown, and otherwise adds n to grown; grow delegates to it with end-st.Size, so WRITE and SETATTR charge exactly as before;
the opSymlink/opMkdir arm and create in ops_linux.go charge block (4096 bytes) before the syscall, folded into the existing error check
after at, so a failed at or an EEXIST leaves nothing to undo and removal gives nothing back, as grow already did. Paid by folds in
stat, at and openFile and the xdgDir fold of PARKED line 78 (cmd/workcell/data.go, every caller branches on the error first): product
14999 of 15000, net -1. TestGrowthCapEntries, moved from escape/_pending/S-F11/ to internal/fileserve/c18_test.go with a third arm
CREATE added by the redteam (reqCreate with O_RDWR, same judge), fails on main 463b7ee in all three arms (200 accepted, 0 ENOSPC, want
at most 26) and passes at 98cc62a under -race with TestGrowthCap and TestGrowthCapAppend; TestGrowthCap's table now creates both files
first (8192 charged) and fills to the cap with 31808, every assertion kept. The reviewer reproduced fail-on-main and pass-at-HEAD in a
worktree and checked that no other opcode makes an entry (LINK and MKNOD are ENOSYS, RENAME moves one), and that the parent
directory's own growth per entry is covered by the charge. Variants left for S-1013: a 255-byte name or a symlink target over 60
bytes costs the host more than one block; create-then-unlink churn should exhaust after limit/4096 creates (uncharged removal, by
design). Not ported.

C19. ID I7 (nothing a session writes is visible to another), I9 (the guest cannot forge a record and verify detects edits), I13
(widening needs user-level config); I14 and A6 are a stretch here, since the boot does no digest check but the replacement comes by
pull, not by update, so I7 and I9 carry the severity. Attacker: guest root, driven by a malicious repository or hostile model output,
doing nothing beyond reading and writing its own /workspace. Precondition the attacker does not control: the operator's cwd, or the
pull destination, is an ancestor of the product's own state, the data directory (XDG_DATA_HOME/workcell, by default
~/.local/share/workcell) or the config directory (~/.config/workcell), as in `cd ~ && workcell run claude`. Where:
cmd/workcell/run_vm.go session (cwd from Getwd; newSession; openAudit mints or loads the key before export; the export or the live mount
is cwd; boot), export and openMount; cmd/workcell/pull_vm.go pull (opens any destination) and put (unlinks and recreates any existing
non-directory); cmd/workcell/pull.go checkPath (refuses .git components and path tricks only, so `workcell/audit.key`,
`workcell/root.ext4` and `workcell/sessions/<id>/audit.log` pass); internal/workspace/workspace.go Export (skips only the image it is
writing); internal/fileserve/serve_linux.go Open; cmd/workcell/data.go. No code compares cwd or the destination with the data or config
directory (no Getwd or UserHomeDir check in cmd/workcell). Input: clone: with the data directory inside cwd, `workcell run <cmd>`;
then `workcell pull` in that cwd. Mount: `workcell run --mount <cmd>`. Effect: the export carries the audit signing key, every other
session's audit.log and workspace.ext4, root.ext4, vmlinux, initrd.cpio, the layers and config.toml into the guest's /workspace, and
pull writes the guest's versions back over them: the guest reads other sessions' workspaces and logs (I7), holds the key so a
rewritten log with a fresh seal passes verify (I9), widens the next session through config.toml (I13), and replaces root.ext4 or a
layer so the next session boots guest-chosen bytes (A6); mount mode does all of it live with no pull step. PARKED line 17 parked the
mount half as having no section-3 ID; I7, I9 and I13 name it, and the default clone mode has no labelled opt-in, unlike --mount (A5).
Reproducing test: escape/_pending/S-F12/c19_test.go TestC19RunRefusesAWorkspaceThatHoldsTheDataDirectory (arms clone, mount and
config directory; calls the real session() with t.Chdir and a test artifacts directory holding dummy firecracker, vmlinux, initrd.cpio,
root.ext4 and a prior session's marker audit.log and workspace.ext4) and TestC19PullRefusesADestinationThatHoldsTheDataDirectory
(XDG_DATA_HOME under the destination; pull must exit 1 with the refusal before any boot) (redteam; package main, run by overlay): on
2b03762 all four arms fail: `session failed with "start firecracker: invalid argument", want a refusal naming .../workcell`,
`.../workcell/audit.key was minted inside the directory the guest gets (I9)`, `a session directory ... was made inside the directory
the guest gets (I7); it holds audit.log audit.seal lock repo vmm workspace.ext4`, and for pull `the session reached boot:
.../workcell/sessions/<idOld>/vmm was written`. Outcome: CONFIRMED, medium, by the verifier, who reproduced the effect itself in the
scratchpad (session() with cwd holding the data directory, then debugfs on the produced workspace.ext4): `ls -p /workcell` lists
audit.key firecracker initrd.cpio root.ext4 sessions vmlinux, the image's /workcell/audit.key is byte-identical to the host's (64
bytes, cmp), the other session's audit.log and workspace.ext4 markers are present, and root.ext4 and vmlinux bytes are present; the
write-back path is real from the code (checkPath admits the paths, put replaces); nothing in README.md ("The directory you run
`workcell run` in is copied into the guest as /workspace"), docs/threat-model.md, policy.md or migrating-from-v1.md warns against the
home directory; SPEC section 2 excludes host root, same-user malware and later human use of pulled code, not the operator's choice of
directory; medium under S6, not high, because the ordinary `cd repo && workcell run` is unaffected. Weak points the verifier named:
the redteam test's assertions are indirect (the key is minted and the session directory made inside the exported tree) and prescribe
the refusal's shape; its own debugfs run supplies the direct effect. Fix unit: S-F12, below S-1008 in PLAN.md; it should compare
resolved paths (EvalSymlinks) and refuse the data directory itself as cwd, not only an ancestor. Not ported.

C19 FIXED by S-F12, commit 8a2e7d4 (PR #234). holds(dir) in cmd/workcell/data.go is the one rule: it resolves dir and the data
directory (dataDir) and the config directory (xdgDir XDG_CONFIG_HOME) with resolved, which follows the longest existing prefix with
EvalSymlinks and re-appends the rest, so a held directory that does not exist yet behind a symlinked parent is still caught (the one
review finding, I13); it refuses when filepath.Rel(dir, held) is local, so the held directory itself or any descendant, with a
separator boundary, naming the held directory as xdgDir spells it. session() calls it right after Getwd in both modes, before the
session directory, the key and the export; fetch() calls it on the destination before opening the root, so pull and diff refuse
before any boot. Paid by folding newSession and openAudit into one, inlining export, dropping the rand.Read check (crypto/rand
cannot fail since Go 1.24), and one-line error branches in boot and doctor: product 15000 of 15000, net +1. The test moved from
escape/_pending/S-F12/ to cmd/workcell/c19_test.go unchanged and gained a fourth run arm (config directory behind a symlink, not
made yet); all arms fail on 7933eac and pass at 8a2e7d4 under -race. One sentence in docs/policy.md, Where it lives.

C20. ID: no invariant directly; I12's "confuse the host" and the spirit of I8 at most, so low under S6 (hardening: the product's
own rule, stated at shown in cmd/workcell/pull.go and followed by lastLines in run_vm.go, that a guest string is quoted before it
reaches the operator's terminal, is bypassed on one path). Attacker: guest root, or hostile model output naming files in the clone.
Where: cmd/workcell/pull_vm.go put and sameBytes name the destination os.NewFile(uintptr(fd), e.Path) with the raw guest path, so
f.Write's or ReadFull's PathError carries the raw name, which write wraps after a quoted shown prefix, and pull prints that error
with Fprintln to os.Stderr. Input: a manifest entry whose path is valid UTF-8 without NUL but holds terminal control bytes, such as
ESC ] 0 ; owned BEL ESC [ 2 J ESC [ 3 1 m README (manifest.add and checkPath admit it), and a write that fails after the open: the
test uses RLIMIT_FSIZE 0 (EFBIG) as a deterministic, unprivileged stand-in; in use the guest claims any Size up to the image's size
(1 GiB by default, more with --disk), so ENOSPC or EDQUOT on a near-full operator disk is an environmental precondition the attacker
can await, not a power it needs. Effect: the operator's terminal receives the raw bytes (title set, screen cleared, colours, and OSC
52 clipboard reads where the terminal allows them); the auditor's probe on a 64 KiB tmpfs showed the same with ENOSPC. Reproducing
test: escape/_pending/S-F13/c20_test.go TestC20PullWriteErrorQuotesGuestPath (redteam; package main, run by overlay; calls the real
write with a manifest judged by the real manifest.add): on 2b03762 it fails with `the error carries a raw control byte 0x1b at 45,
which the terminal would obey: "\"\\x1b]0;owned\\a\\x1b[2J\\x1b[31mREADME\": write \x1b]0;owned\a\x1b[2J\x1b[31mREADME: file too
large"`, the prefix quoted and the PathError raw; the redteam showed it passes with shown(e.Path) at both os.NewFile sites. Outcome:
CONFIRMED, low, by the verifier: the real writer and judge are exercised, only the Data source is a double for frames guest root
controls anyway; the error reaches the terminal unquoted; Fchmod returns a bare errno and sameBytes discards ReadFull's error, so this
is the one gap; not an I12 break (the host neither crashes, hangs nor is confused) and not a literal I8 break (workcell obeys nothing,
the terminal does), so exactly S6's hardening with no demonstrated break, and a reproducing test plus the I8 and I12 reference
satisfies R2 enough to list it under S7 rather than park it. Fix unit: S-F13, below S-1008 in PLAN.md, net 0 product lines, as C3, C6
and C11 before it. The diff read path (sameBytes) has the same shape and no deterministic unprivileged trigger was found; the same
change covers it. Not ported.

C20 FIXED by S-F13, commit 128d5aa. put and sameBytes in cmd/workcell/pull_vm.go now name the destination
os.NewFile(uintptr(fd), shown(e.Path)), so the PathError that f.Write or ReadFull returns after the open carries the quoted name, as
write's "%s: %w" prefix already did: each occurrence of the path is quoted by one layer, never doubly, and no byte below 0x20 reaches
the terminal. Two in-place edits, net 0 product lines: product 15000 of 15000 before and after. The test moved from
escape/_pending/S-F13/ to cmd/workcell/c20_test.go unchanged; it fails on 2b03762 with the raw ESC at offset 45 and passes with the
fix under -race, as do the existing pull tests. The T5 fuzz target S-1001 asked for landed as FuzzPath in cmd/workcell/pull_test.go,
seeded with the paths checkPath, fold and manifest.add must agree on.

Handoffs: S-1013 takes the unbounded pull duration (per-frame stall limit only), the export-failure-removes-session_start gap (I9) and
the C19 chain through a reflinked prior workspace.ext4; S-1016 the APFS case-fold lead on checkPath's .git test; the T5 fuzz target for
checkPath, fold and manifest.add landed with S-F13 as FuzzPath in cmd/workcell/pull_test.go; S-1013 also takes the walk.go
raw-name error of the S-F13 review (PARKED), the same class as C20 on the diff path. The
real-VM rows the auditor designed for C17 and C18 (mount-disk-append-flood through a stolen 5002 socket, mount-entry-flood with ln -s
and mkdir judged by host free blocks and inodes) are the first rows that would exercise fileserve's protocol tables from a real guest;
they are parked for the fix units or the maintainer, since each needs a control-adapter twin for T2.

Delivery: the unit is blocked by the SPEC section 7 test budget (BLOCKED.md); the four pending tests are on the claim branch named there until the maintainer makes room.

## S-1009: policy loading and merge, CLI parsing, `--allow`, adapter data files (I13), as built at main 01501b5

Trust boundary. Row 17 (repo-local workcell.toml): the malicious repository owns every byte of `<cwd>/workcell.toml`; they enter at
cmd/workcell/policy.go loadPolicy, then internal/policy/policy.go ReadRepo (O_NOFOLLOW, fstat of the opened fd, regular file, 1 MiB
cap), Parse (the project's own TOML subset) and Narrow. Authority: the supervisor as the operator's uid before any VM boots, and the
CLI under `explain`. Narrow keeps only the user's own allow entries whose text a repository entry equals exactly and the user's own
secret rows whose name a repository row names; a repository string reaches nothing else but the quoted `asked` note. Row 39 (CLI
arguments): hostile model or tool output that a host-side tool turns into argv; `--allow` values enter at caps.go parseRun and are
judged by policy.go allowlist and internal/proxy/allowlist.go ParseAllowlist; `--cpus`, `--memory` and `--disk` by parseRun's bounds;
`--cache` by cache.go's regexp; session ids by session.go validID; the command argv goes verbatim into guest.Exec. The allowlist
becomes the proxy's sni and forward maps, the resolver's name set, the session CA's name constraints and the kernel cmdline
`workcell.ports=`. Row 40 (environment): XDG_CONFIG_HOME, XDG_DATA_HOME and HOME at cmd/workcell/data.go xdgDir choose the user
config file and the data directory, which holds the VMM binary, kernel, initrd, root image, layers, caches, audit key and sessions;
TERM goes into the guest env; TMPDIR places the VMM socket directory. The operator sets them, but a relative value hands the choice to
the repository (C21). Row 41 (user config.toml and embedded provider TOML): read by the same reader; cmd/workcell/policy.go bindings
fills a user row that has neither host nor header from provider.FindSecret after Narrow; grants go to secret.NewBroker and the
terminate rules to proxy.Terminate. Lenses worked in order: parsing and resources, logic and state, concurrency and check-to-use,
cryptography and identity, failure modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real cmd/workcell and internal/policy packages,
nothing in the tree changed; every target a file or process of this session; the one end-to-end run held the update channel, so no
network; nothing here needed a VM):
- Can a repository widen anything? No, short of C21. Network: Narrow keeps a user entry only when a repository entry equals its text
  exactly, so a respelling (case, `:443`, trailing dot) keeps nothing and lands in `asked` (TestNarrow; probe with user
  `API.anthropic.com` and `api.anthropic.com:443` against repo `api.anthropic.com`: kept nothing). Secrets: only the user's rows that a
  repository row names survive, as the user wrote them; a repository row's host, header, source, env, method, path and repos are never
  read (TestNarrow; rows repo-policy-rebinds-secret, -lifts-secret-binding, -rewires-secret). Forward ports: the same exact-text rule.
  Workspace mode and resources: Parse reads past [workspace] and [resources] in every file and only the flags set them (rows
  repo-policy-mounts-workspace, repo-policy-lifts-memory-cap). [update]: ReadRepo refuses a repository file that carries the table
  (TestReadRepo). Provider or agent choice: argv alone; layers come from the data directory's markers. Guest env: PATH, HOME, LANG,
  trust, cache and placeholder variables are host-built, and env names come only from the user's rows or the provider file.
- Does Narrow compare names as the proxy and resolver match them? Narrow compares text with text; whatever survives is the user's own
  string, which allowlist then canonicalises (lower case, trailing dot dropped, :443 default) for the proxy maps, the resolver set and
  the CA constraints, so a repository can only shrink the set and never select a wider spelling. The secret-drop rule compares a
  secret row's host text with the allow texts, so a row whose host the user spelled differently or left to a provider survives
  narrowing and is then refused by bindings for want of its host: fail closed (PARKED line 32 confirmed, developer experience only).
- Fail-open paths: none. A missing workcell.toml leaves the user's grants (I13 speaks of narrowing); a symlink, FIFO or directory is
  ErrNotRegular, ignored with a stderr line, never beyond the user's own config (docs/policy.md; rows repo-policy-through-symlink,
  repo-policy-is-a-pipe); a unix socket fails open(2) with ENXIO, a hard refusal; over 1 MiB, invalid UTF-8, control bytes, an unknown
  table or key, a repository [update] table and a row without name or source each refuse before anything boots; an unreadable user
  config refuses; HOME unset with no XDG refuses. The parser cannot hang and is bounded by the cap: 209,704 allow entries parse in
  35 ms and Narrow in 43 ms; 33,824 [[secret]] rows in 58 ms.
- `--allow`: an IP literal is refused, bracketed, zoned and IPv4-mapped included (netip.ParseAddr); an octal-looking name such as
  01.02.03.04 is a DNS-shaped name, resolved as one and vetted by blockedAddr at connect (S-1004, S-1006); a port range or sign is
  refused by ParseUint; control bytes never reach `explain` (it prints the canonical hosts, ports and forwards) or the audit log (the
  proxy records the allowlist's canonical host), and errors quote the entry. One value admitting two endpoints is C22.
- Resource flags: `--cpus` 1..32 by flag.Int (Go base-0 syntax, so 0x20, 1_0 and +2 are read; -1 refused); `--memory` 128 MiB to
  2147483647 MiB; `--disk` 1 MiB to 2147483647 MiB, 0 refused; the export image is a sparse file whose EFBIG beyond 16 TiB on ext4
  refuses the session. Only the operator sets them (PARKED line 15 has the oversubscription note); no in-scope attacker.
- Provider defaults and user rows: FindSecret fills host, header and env into a user row only after Narrow and only when the row has
  neither host nor header; repository rows contribute names only; the embedded files are build-time content and provider_test.go
  checks their names.
- validID is an anchored regexp of fixed shape applied by rm, stop, log, verify, attach and ls's filter; no traversal; attach dials the
  socket path from the host-written vmm file. Writes outside the data directory: the VMM socket directory under TMPDIR and the
  operator's cwd in mount mode only.
- Concurrency and check-to-use: ReadRepo fstats the fd it opened; the policy is fixed before boot; run and startup read the user's own
  file twice. Cryptography and identity: only the [update] key hex and ca pool, the operator's. Downgrade and replay: cooloff "0s" is
  the default and a negative value is refused; a repository [update] table and an http channel are refused; the client side is
  S-1011's. PARKED line 25 answered: repository bytes never reach allowlist(), argv is the only route (C22). PARKED lines 29 and 71
  (bareHost's leading newline, duplicate names, dead `file` and `field` keys) concern build-time data files only.

Observations (R3, not candidates): allowlist() re-parses the whole joined list per entry, so 1000 flags cost 0.16 s and 5000 flags
4.0 s, operator argv only, and one ParseAllowlist call would be less code since its errors already quote the entry; a relative TMPDIR
puts the VMM socket directory under cwd, where a mount-mode guest sees it live, and C21's IsAbs rule would cover it; a repository
[[secret]] row must carry `source` although only `name` is read, so a hostile repository can only refuse the session; a mount-mode
guest can replace the repository's own narrowing workcell.toml, and the next run returns to the user's grants or refuses; `explain`
and `run` take cwd from os.Getwd, so the workcell.toml path may run through the operator's own symlinked cwd with the last component
still O_NOFOLLOW; the `asked` note escapes control and format characters with strconv.Quote and a homoglyph name copied into
`--allow` is refused by dnsName; log.go ignores configFile's error and names "config.toml" in its remedy; Narrow's note invites the
operator to allow exactly what the repository asked, the designed approval path, so its wording matters.

Coverage. Examined in full: cmd/workcell/policy.go, caps.go, data.go, cache.go, session.go, main.go, explain.go, log.go, update.go,
layer.go, cache_vm.go, relay.go, run_vm.go, policy_test.go, caps_test.go, data_test.go, explain_test.go; internal/policy/policy.go
and policy_test.go; internal/provider/provider.go, provider_test.go and the four TOML files; internal/proxy/allowlist.go and
proxy.go; internal/resolver/resolver.go; docs/policy.md; escape/suite/repo.go and the repo-policy-* rows of tests.go;
escape/sandbox/workcell.go policyTOML. In part: internal/proxy/terminate.go and signin.go heads, internal/secret/broker.go and
source.go heads, internal/guest/guest.go, internal/wire/wire.go WriteFrame, internal/vmm/firecracker/firecracker.go start, the
S-1001 map and C19, PARKED.md in full. Not opened: the rest of terminate.go and signin.go (S-1005), internal/channel and
internal/artifact (S-1011), the guest init (S-1002), internal/fileserve and internal/workspace (S-1008), the vz and darwin backends
(S-1003), pull.go and ocsf.go (S-1008, S-1010). Tools: go test only; FuzzParse exists and the long run is S-1014's. No file on this
surface is ported, so nothing carries also in v1 main and nothing is private.

### S-1009 candidates

C21. ID I13 (workspace content can only narrow policy; widening needs user-level config or an interactive approval on the host); I14
where the config home is relative, since the repository then supplies the [update] table; A6 and host integrity where the data home is
relative, since the repository then supplies the VMM binary the host execs. Attacker: a
malicious repository, with a hostile tree holding a directory literally named `~`, `.config`, `data`, or whatever the variable's
relative value is. Precondition the attacker does not control: the operator's XDG_CONFIG_HOME, XDG_DATA_HOME or HOME holds a
relative path, such as the literal `~/.config` that /etc/environment, ~/.pam_environment and environment.d leave unexpanded; the XDG
base directory specification says a relative value must be ignored, and the product does not. Where: cmd/workcell/data.go xdgDir
joins the variable with "workcell" with no IsAbs check, and os.UserHomeDir returns HOME as it is; used by policy.go configFile and
data.go dataDir, then run_vm.go loadPolicy, loadArtifacts, findLayers and session, and internal/vmm/firecracker/firecracker.go
exec.Command with the binary path as given (no PATH search). Input: (a) XDG_CONFIG_HOME=~/.config (literal) and a repository holding
`~/.config/workcell/config.toml` with `[network] allow = ["evil.test"]` and a `[[secret]]` row whose source is `cmd:/bin/sh -c ...`
on a host of its choosing, then `workcell run <anything>` or `workcell explain` in the repository; (b) XDG_DATA_HOME=data and a
repository holding data/workcell/{firecracker,vmlinux,initrd.cpio,root.ext4}, then `workcell run -- true`; (c) HOME relative with the
XDG variables unset, both at once. Effect: (a) the repository's file is the user-level policy: its network allow stands, and a
secret binding of its choosing whose source is a host program and argv it chose runs on the host under the broker when the guest,
which the repository's code drives, sends the placeholder; `explain` prints `from ~/.config/workcell/config.toml`, the same text
as the real path; (b) `workcell run` execs the repository's data/workcell/firecracker on the host as the operator's uid before any
sandbox exists, mints audit.key and the session directory inside the repository tree, and attaches
data/workcell/layers/<agent>/current as a layer; every verb that uses the data directory (update, log, verify, ls, rm, doctor,
explain) reads the repository's tree as the product's state. The auditor's overlay probes showed (a) for `~/.config`, `.config` and
`cfg` (loadPolicy granted evil.test from a relative file while the real $HOME config granted nothing), (b) in loadArtifacts and
findLayers, (c) with HOME=h, and end to end: run([--, true]) with the channel held exited 125 after the repository's script ran as
the VMM with `--no-api --config-file`, and data/workcell/audit.key and a session directory appeared inside the repository. Relation
to C19 (S-F12), not a re-report: C19's precondition is a cwd that is an ancestor of the real data or config directory; here cwd is
an ordinary repository and the relative variable moves the product's state into every cwd; S-F12's check closes this only if it
makes the directories absolute first, and it runs after loadPolicy, startup and findLayers and not at all for explain, update, log,
verify, ls, rm and doctor. Reproducing test: escape/_pending/S-F14/c21_test.go TestC21RelativeXDGDirs (redteam; package main, run
by overlay; HOME an empty TempDir, XDG_CONFIG_HOME `~/.config`, XDG_DATA_HOME `data`, cwd a repository holding
`~/.config/workcell/config.toml` that allows evil.test; asserts loadPolicy grants nothing and names an absolute file, and dataDir is
absolute): on 01501b5 it fails with `loadPolicy: file="~/.config/workcell/config.toml" err=<nil> allow=&{map[evil.test:true] map[]}`
and `dataDir: "data/workcell" err=<nil>`; the redteam showed it passes under a scratch fix (xdgDir takes the variable only when
filepath.IsAbs and errors when the home directory is not absolute) with the whole cmd/workcell package green. Outcome: CONFIRMED, medium, by the verifier, who ran the test on 1c6e96f (the same two failures), then the real binary: in a scratch repository holding `~/.config/workcell/config.toml` with `allow = ["evil.test"]` and a `[[secret]]` row whose source is `cmd:/bin/echo pwned`, `env -i HOME=<abs> XDG_CONFIG_HOME='~/.config' XDG_DATA_HOME=data workcell explain` exits 0 and prints `network: from ~/.config/workcell/config.toml`, `https://evil.test` and `secrets: x: in x-api-key to https://evil.test`, the claimed effect and not a look-alike; the claimed fix as a scratch overlay makes the test pass with the package green, so the test's shape is sound; no IsAbs, Abs, EvalSymlinks or UserHomeDir check exists in cmd/workcell product code beyond the unchecked UserHomeDir call. Scope: the repository supplies only files in its own tree (section 2, hostile config); the precondition is a plausible operator mistake that a conforming product ignores, so medium under S6, not high and not low. The verifier adds that update.go newInstaller reads the same configFile(), so the repository's file also supplies the [update] table (key, channel, ca) and `workcell update` in the hostile repository would install attacker-signed artifacts: I14 as well, and S-F12 does not touch update.
Fix unit: S-F14, below S-1009 in PLAN.md. For S-F14 to carry: the test cut the loadArtifacts arm and the end-to-end run arm for the
test budget, and does not express relative HOME with XDG unset or the session directory and audit.key landing inside the repository;
the fix covers all three by construction, and the same rule should reach TMPDIR if a line is spare. Not ported.

C21 FIXED by S-F14, commits 82a0c71 and 1d8947e (PR #214). xdgDir in cmd/workcell/data.go takes XDG_CONFIG_HOME or XDG_DATA_HOME
only when filepath.IsAbs holds, else falls back to the home directory as the XDG base directory specification says, and returns an
error when os.UserHomeDir fails or its answer is not absolute, so configFile and dataDir, and through them run, explain, update, log,
verify, ls, rm, doctor, pull and bench, never name a tree under cwd; boot in cmd/workcell/run_vm.go refuses a relative TMPDIR before
MkdirTemp, so the VMM sockets cannot land under a directory a mount session exports (the "if a line is spare" clause: untested, the
test budget had no room, and TestC21RelativeXDGDirs does not cover it). The lines were paid by deleting the five dead Count lines
PARKED line 68 named (audit.Record.Count, ocsfEvent.Count and its copy, the "overloaded" case in log.go): product 14999 of 15000.
The pending test became cmd/workcell/c21_test.go TestC21RelativeXDGDirs, unchanged but for its head comment: it fails on 70e1c8e
(loadPolicy grants evil.test from "~/.config/workcell/config.toml", dataDir is "data/workcell") and passes on 1d8947e with cmd/workcell
green under -race. The builder also ran the real binary under strace in a scratch tree holding ~/.config/workcell/config.toml and an
executable data/workcell/firecracker with HOME absolute, XDG_CONFIG_HOME the literal ~/.config and XDG_DATA_HOME data: explain read
the home config, run reported the home data directory's firecracker missing, update listed the channel, and no syscall named a path
under ~ or data; with HOME relative, explain and log exit 2 with the error home directory "home" is not an absolute path. One sentence in
docs/policy.md. Not ported.

C22. ID I13 (the `--allow` flag is the host-side approval of one endpoint; cmd/workcell/policy.go states that one flag value is one
host) and the product's own one-entry rule. Attacker: hostile model or tool output that becomes argv of `workcell run` or `workcell
explain` through a host-side tool that shows the operator the command line. Where: cmd/workcell/policy.go allowlist guards each
entry with `strings.ContainsAny(e.Text, " \t#")` before internal/proxy/allowlist.go ParseAllowlist, which splits on "\n" and
strings.Fields, every unicode.IsSpace rune. allowlist.go is ported (`// Ported from v1: egressproxy/allowlist.go`) and its
whitespace split is that file's documented text format; the weakness is the unported caller's guard, so no `also in v1 main` line
applies. Input: one value `--allow "evil.example:443<SEP>api.anthropic.com:443"` with SEP any of \r \n \v \f U+0085 U+00A0 U+2028
U+3000; the hidden half may be a forward port such as `b.example:22`; both halves need an explicit port, since ":443" is appended
once to the whole string; a terminal renders the \r form with the first half overwritten. Effect: one approved value admits two
endpoints: a second TLS name or a raw TCP forward port joins the session's allowlist, resolver set and CA constraints. The proxy,
resolver, CA, audit log and `explain` all hold and show the canonical names of both endpoints, so the only thing hidden is the second
endpoint in a raw argv display outside the product: low under S6 (hardening with no demonstrated break). PARKED line 25 answered:
repository bytes never reach this path, since Narrow passes only the user's own entries to allowlist(); argv is the only in-scope
route. Reproducing test: escape/_pending/S-F15/c22_test.go TestC22AllowFlagWhitespace (redteam; package main, run by overlay; one
entry `a.example:443\rb.example:22` must be refused with "invalid endpoint"): on 01501b5 it fails with `err=<nil>, want invalid
endpoint`, two endpoints accepted, one a forward port; the redteam showed it passes under a scratch fix (refuse
strings.ContainsFunc(e.Text, unicode.IsSpace) or "#") with the whole cmd/workcell package green. Outcome: CONFIRMED, low, by the verifier, who ran the test on 01501b5 (the same failure), then a probe through parseRun and loadPolicy for each separator \r \n \v \f U+0085 U+00A0 U+2028 U+3000: one argv `evil.example:443<SEP>b.example:22` gave Hosts [api.anthropic.com b.example evil.example], TLSHosts [api.anthropic.com evil.example], Ports [22 443] and Forward(22) b.example, since flag.Func keeps the value verbatim; the real binary `workcell explain --allow $'evil.example:443\rb.example:22'` prints both endpoints; run_vm.go hands Ports, Hosts and TLSHosts unfiltered to the adapters, proxy.New, NewSessionCA and resolver.New, so nothing later refuses them. The test takes no extra power: it calls allowlist() with the one Entry loadPolicy builds from one flag value. Low is right: I13 is literally satisfied, since the operator approved the whole byte string, and every product display shows both canonical names; the \r disguise is weaker than claimed, since CR returns to column 0 of the whole line, and the U+00A0 and U+3000 forms, which render as a space, are the convincing ones. The scratch fix is net +1 product line (the `unicode` import), not zero, and a ContainsAny list without it would miss the Z-category runes, so keep the import. Fix unit: S-F15, below
S-1009 in PLAN.md. For S-F15 to carry: the test has one row (\r) for the test budget, and the fix must cover every unicode.IsSpace
rune. Not ported.

C22 FIXED by S-F15, commit aca6678 (PR #215). allowlist in cmd/workcell/policy.go refuses an entry when strings.ContainsFunc(e.Text,
unicode.IsSpace) holds or it carries "#", before ParseAllowlist, in the one loop that both a --allow value (Line 0) and a config-file
row (Line > 0) pass through; ParseAllowlist splits only on "\n", "#" and strings.Fields, every one of which that guard now refuses, so
one entry is one endpoint. The unicode import was paid by folding allowlist's doc comment from four lines to three: product 14999 of
15000. The pending test became cmd/workcell/c22_test.go TestC22AllowFlagWhitespace, grown from one separator to three (\r, U+00A0,
U+3000) in a loop, two test lines: it fails on e1e5b98 (err=<nil> for all three, two endpoints accepted, one a forward port) and
passes on aca6678 with cmd/workcell, internal/proxy and internal/policy green under -race. The reviewer loaded config.toml rows
carrying \r, U+00A0, U+3000, \n, \t, \f, U+0085 and U+2028 through policy.Parse and each is refused as config.toml:2 has an invalid
endpoint, so there is no second path; a plain name, name:port and a trailing-dot name take the same path as before. Not ported.

Handoffs: S-1013 takes the chain of C21 with C19 (a relative data home and S-F12's cwd check) and the relative TMPDIR observation;
S-1010 the audit log's canonical-host recording that C22 relied on; S-1016 nothing. The allowlist() re-parse and the `source` key a
repository row must carry are less-code and developer-experience notes for the fix units in cmd/workcell.

## S-1010: audit log, seal, key storage, `verify` (I9), as built at main eef4b5c

Trust boundary. Row 23 (log volume) and row 25 (audit.log, audit.seal, audit.key on disk), with row 9's I9 share. Attacker bytes
that reach a record: the raw SNI of a refused 443 connection (internal/proxy/proxy.go route returns it unchanged; crypto/tls refuses
only a trailing dot), the name of a refused DNS query (internal/resolver/resolver.go: lower-case [a-z0-9.-] or ""), the relay
header's port (uint16, 0 admitted), the command's exit status (one byte), and the rate and timing of every attempt. Everything else
in a record is a constant, a config string, or the allowlist's canonical host (an allowed line carries the sni or forward map's
key, never the SNI as sent, which answers S-1009's handoff). Entry: audit.Log.append (internal/audit/audit.go) clips the host to 253
bytes and json.Marshals; Verify and ParseLine, and cmd/workcell/log.go feed, read the host-written file; denyMessage and
ocsf.go ocsfLine pass the one free-form field through SafeHost. Authority: the supervisor, as the operator's uid, owns
sessions/<id>/audit.log and audit.seal and signs with <data>/audit.key; log and verify read as the same uid. Every writer (proxy
Deny, the resolver callback, relay deny, broker record, supervisor lifecycle) goes through one *audit.Log under one mutex. Lenses
worked in order: parsing and resources, logic and state, concurrency and check-to-use, cryptography and identity, failure modes,
downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (overlay tests from the scratchpad against the real internal/audit, internal/proxy and
cmd/workcell packages, and the real binary's log, log --format ocsf, log -f and verify over generated sessions; nothing in the
tree changed; every target a file or process of this session; no VM needed, env:any):
- PARKED line 34 (seal rewritten per append): 300 Verify runs against a live writer gave 272 intact and 28 "it was changed", never
  a false intact; a log one line ahead of its seal (a crash between write and sign) gives the same "changed" wording, misleading but
  fail-closed. The rollback consequence of the in-place seal is C25's untested variant.
- PARKED line 35 (seal not bound to the session id): confirmed, C25.
- PARKED line 36 (verify mints a key): with audit.key removed, verify wrote a new 64-byte 0600 key and then printed "the seal is not
  signed with this host's key", exit 1; fail closed, the side effect is what the next run would do anyway. R3.
- PARKED line 37 (redteam ideas): a whole-file swap verifies (C25); a seal edited alone is "unreadable" or "not signed" (torn, empty,
  one byte changed); no site copies guest stdout or stderr into audit.log; no record site carries a value or placeholder (Record has
  no field for one; broker.record passes host, header, name, result); a killed supervisor's log verifies intact (C25, completeness);
  log --format ocsf gave 9 valid JSON lines for 9 records with hostnames sanitised; a policy name cannot carry control bytes (dnsName
  refuses them, the resolver maps them to "").
- PARKED line 41 (makeKey's O_EXCL create then write): an empty audit.key, and one with a trailing newline, fail every use with
  "does not hold a key" until deleted; fail closed, developer experience only. R3.
- FINDINGS line 92 (T5): ParseLine is fuzzed inside FuzzEachLine; feed, denyMessage and ocsfLine consume only records ParseLine
  accepted and pass the one free-form guest field through SafeHost's anchored regexp; the guest's own bytes are parsed by crypto/tls
  (FuzzPeekSNI) and the resolver (FuzzAnswer) before any writer. No fuzz target added (R5); no defect found.
- FINDINGS line 95 (Note not fsynced): Note's write(2) completes before Note returns, so a process death loses nothing; only a host
  power loss loses the unsynced tail, after which verify says "cut inside a record" or "changed" (closed). The splice path dials the
  upstream before its Allowed line (proxy.go handle) while the terminated path records before the dial; with C23's fix the record
  should precede the dial on both.
- FINDINGS lines 454, 582 and 743 (the SoftLimit fill as the one suppression path, 57,000 refusal records per second): C23 and C24.
- Guest-chosen bytes: ESC, OSC and CSI sequences, a C1 CSI as UTF-8, an embedded newline followed by a forged session_end object, a
  quote-and-comma injection, U+202E and U+2028, 300 bytes of 0xFF, 200 'e-acute' (clipped mid-rune) and NUL each gave one parsing
  line and one record, zero bytes below 0x20 in the file, verify intact, and (invalid) in both log and --format ocsf with no control
  or C1 byte in either output. Secret-use records and deny messages carry no credential bytes or placeholder mappings.
- Seal and key: the seal is bound to the host key (another host's key, a short key, a torn or empty seal all fail) and to the record
  sequence through the chain, not to the session id or to completeness (C25); a missing or regenerated key fails closed. Verify on a
  running session gives false negatives only; on a crashed session or with a lagging seal it says "changed", "cut inside a record" or
  "unreadable", never a false intact, except that a cleanly cut log is intact (C24, C25).
- Concurrency: writers share one mutex, so no record is lost or reordered without a returned error; a late Deny during teardown lands
  after session_end or gets ErrClosed; a SIGKILL mid-append cannot split a write(2).
- After the SoftLimit fill: connection records stop on every path (splice, terminated, DNS refusal, relay port refusal), secret-use
  records continue until HardLimit and then the broker withholds values (fail closed), lifecycle records always continue, and the
  fill itself is one durable log_full marker that verify accepts and log prints (C23).

Observations (R3, not candidates): verify's wording blames an edit for a crash between write and sign; under eight concurrent
writers 7% of records carry a time earlier than their predecessor (the clock is read before the lock; verify ignores order); the raw
file keeps U+009B and U+202E unescaped, which JSON allows, so only cat audit.log on an xterm would obey them; relay.Decode admits
port 0, giving a record with no port and the remedy host:0; the Sscanf seal reader ignores bytes after its two tokens; attach, pull
and diff boots leave no record (pull's nil log, U-600); an empty or newline-terminated audit.key bricks every use until deleted;
log reads the whole file with io.ReadAll and feed has no pending-line cap, host-written only. The escape suite has no row that
floods audit.log (log-flood measures the output relay), so C23 is unproven on a real VM and its Go test is the evidence (env:any).

Coverage. Examined in full: internal/audit/audit.go, key.go, lines.go (ported), audit_test.go; cmd/workcell/log.go, ocsf.go,
verify_test.go, log_test.go, run_vm.go, session.go, relay.go, main.go; internal/proxy/proxy.go (ported); internal/resolver/
resolver.go; internal/secret/broker.go (ported); escape/suite/audit.go; SPEC sections 2, 3, 6, 8 and 11 to 13; FINDINGS.md and
PARKED.md whole; the I9 block of docs/threat-model.md and the docs grep for audit, verify and seal; go1.27 crypto/tls SNI parsing.
In part: internal/proxy/terminate.go (every Deny site, serveTerminated, the transport's DialContext), signin.go (140 to 200),
allowlist.go (30 to 90), proxy_test.go fixtures; escape/suite/tests.go I9 rows; escape/sandbox/workcell_vm.go (430 to 525 and 695
to 706) and control_linux.go (95 to 256); escape/suite/floods.go logJudge; internal/guest/guest.go and internal/relay/relay.go by
grep. Not opened: internal/secret/source.go, cmd/workcell pull, update, policy and explain, the init, the VMM backends, the rest of
terminate.go and signin.go. Tools: go test only; the long fuzz run is S-1014's. Ported files opened: internal/audit/lines.go
(nothing found), internal/secret/broker.go (nothing found), internal/proxy/proxy.go (C23 and C24 live in its Deny and handle, so
they carry also in v1 main). Nothing concerns someone else's project: no NEEDS-YOU. No model declined and no safeguard re-ran a
request; one tool permission was denied to the redteam (fetching a third-party checker), which wrote a stdlib one instead.

### S-1010 candidates

C23. ID I9 (every connection attempt is recorded on the host; the guest cannot suppress a record), against I10 (log volume).
Attacker: guest root, no precondition; hostile model output does it in a few lines. Where: internal/audit/audit.go SoftLimit (8 MiB)
and append, which after one log_full marker returns ErrFull for every later Note; internal/proxy/proxy.go Deny discards the
recorder's error (`_ = p.rec.Note(...)`) and handle splices or serves the connection whatever the Allowed Note or Deny returned.
Input: the guest fills the log to SoftLimit. One kept-alive terminated connection pipelining `GET / HTTP/1.1` requests with a foreign
Host writes one 121-byte host_mismatch record per request with no upstream dial: 69,391 records fill 8 MiB, the writer alone takes
1.6 s and S-1005 measured 57,000 such requests per second through the proxy, so about 2 s end to end; every refusal and every
allowed connection pays into the same budget (DNS refusals alone take about 4.5 minutes, S-1006). Effect: from then on every
connection attempt on every path, allowed or refused, gets ErrFull, Deny drops it, and the connection is served: a forward-port guest
connection is spliced and the upstream reads the guest's bytes; a 443 connection completes the handshake with the session leaf and
is served, secrets injected. The file holds exactly one log_full marker, verify says intact, log prints "log full, later connections
were not recorded". Secret-use records continue to HardLimit, then the broker withholds values; session_end is always written. Lost:
which allowed hosts the guest reached and which refused names it tried for the rest of the session. audit.go documents SoftLimit as
the point where connection records stop (I10) and three earlier audits treated it as design, but no file in docs/adr/accepted/
adopts it and I9's letter is broken. Reproducing test: escape/_pending/S-F16/unrecorded_test.go TestUnrecordedConnectionIsNotServed
(redteam; package proxy, run by overlay; a two-row table of recorders returning audit.ErrFull and a plain write error, set on
p.rec of the testProxy fixture for an allowed forward port; asserts the guest's read is io.EOF and the upstream was dialled 0 times):
on eef4b5c it fails with `recorder failing with "audit: the log is full": the guest read read tcp ...: i/o timeout and the upstream
was dialled 1 times; want EOF and no dial`; the redteam showed it passes under a scratch fix (handle takes the Allowed Note before
connect and returns when it errs) with internal/proxy green under -race. Outcome: CONFIRMED, high, by the verifier, who ran the
test on 5be6450 (the same failure), checked with TestVolumeIsBounded that a real *audit.Log returns ErrFull from every Note after
SoftLimit so the stub recorder is a faithful stand-in and no extra power, and judged it high and not critical because only
policy-allowed destinations are served unrecorded (I2 and I5 hold). Fix unit: S-F16, below S-1010 in PLAN.md. For S-F16 to carry:
the smallest fix is the I11 shape, fail closed when the record cannot be taken: Deny returns Note's error (net 0 lines) and the
two Allowed sites in handle close the connection on a non-nil result (about 4 lines), paid by folding Note and Record in audit.go
into one-liners with the nil check moved into append; the terminated path (Deny then serveTerminated), the relay's and the
resolver's Deny callers need the same rule, and the record should precede the dial on both paths; a legitimate session needs about
76,000 connections to reach the limit, so a flooding guest loses its network instead of its trail. also in v1 main:
egressproxy/proxy.go (Deny's discarded error).

C24. ID I9. Attacker: guest root, with a precondition it does not control: a write error on the data directory's volume (ENOSPC
when the volume's free space is below --disk plus the log's headroom, which the guest consumes through its own export by design;
EIO; a quota). doctor warns under 4 GiB; run does not refuse. Where: internal/audit/audit.go append, where one failed write sets
failed for the rest of the session and the marker cannot be written either; proxy.go Deny (discarded); cmd/workcell/run_vm.go
session, `_ = log.Record(session_end)` with no stderr line; cmd/workcell/log.go verify has no completeness check. Effect: every
later record fails, session_end included, no marker, nothing printed, connections continue (C23's path), and verify prints intact
because the file ends at a line boundary; unlike C23 the suppression is invisible. Evidence: the auditor's overlay with a read-only
descriptor under the log for one write: every Note and Record after it, session_end included, returned "audit log failed; no
further records", the file held 2 lines and no marker, Verify nil; the real binary's verify on a session whose last record is a
secret use printed intact, exit 0. Reproducing test: the second row of S-F16's table (a recorder returning a plain write error),
which the verifier judged the same defect through the same two lines (Deny discards, handle serves), so it stands as a row of S-F16
and not as its own finding. Outcome: CONFIRMED, medium, by the verifier, as part of S-F16. For S-F16 to carry: C23's fail-closed
change covers the connections; print session_end's Record error on stderr in session() (2 lines) so that the operator can tell
records stopped from the log alone. also in v1 main: egressproxy/proxy.go.

C23 FIXED by S-F16, commit 34882ee (PR #217). Deny in internal/proxy/proxy.go returns the recorder's error, and handle takes the one
Allowed record before the terminate check and before connect, so the record precedes the dial on the forward path and precedes
serveTerminated on the 443 path; when the record cannot be taken, handle half-closes the guest connection, drains what the guest
sent until it closes or peekTimeout, and returns, so the guest reads EOF (not a reset) and nothing is dialled. A connect refusal after
an Allowed record is still recorded as a refusal. The refusing callers (route and connect refusals in handle, terminate.go's dial
callback and handler refusals, signin.go, the relay's port_not_allowed and the resolver's name_not_allowed through one closure in
cmd/workcell/run_vm.go boot) drop the error explicitly, since each already refuses or closes whatever the record did. Paid by folding
Note and Record in internal/audit/audit.go into one-liners with the nil check first in append, clip into one line, and New's literal
into a return: product 14998 of 15000. The pending test became internal/proxy/unrecorded_test.go TestUnrecordedConnectionIsNotServed,
grown from two rows to four (ErrFull and a write error, each on forward port 5432 and terminated 443; a TLS client dials the listener
and wants the handshake error to be exactly io.EOF and zero upstream dials; the dial count is read under the fixture's lock): it fails
on ce9ae18 (5432 rows: the upstream is dialled; 443 rows: the handshake completes, served) and passes on 34882ee 300 of 300 under
-race, with internal/proxy, internal/audit and cmd/workcell green. The reviewer re-ran it on a worktree of main (all four rows fail)
and on HEAD (50 of 50 pass), traced every Deny caller, and found the broker's secret record (acts only on nil) unchanged. A nil
*audit.Log as Recorder now refuses every connection; bench_vm.go and pull_vm.go pass one only with a nil allowlist, so no listener.
Ported: proxy.go carries the fix; also in v1 main: egressproxy/proxy.go.

C24 FIXED by S-F16, commit 34882ee (PR #217), as the second and fourth rows of the same test (a recorder returning a plain write
error): the fail-closed change above covers the connections, and session() in cmd/workcell/run_vm.go prints session_end's Record
error on stderr with the workcell: prefix, so the operator can tell that records stopped. also in v1 main: egressproxy/proxy.go.

C25. ID I9's last clause (`workcell verify` detects any offline edit) and lifecycle completeness. Attacker: none in section 2
directly; an offline editor of the session directory, or a rollback or copy of the host's own files, the same power the suite's own
I9 offline rows use (offlineJudge writes the record on the host), so a valid I9 finding and not R3 material; the guest reaches the
data directory only through C19 (S-F12), where it also holds the key and no seal scheme helps. Where: internal/audit/audit.go sign
overwrites the seal in place, so every earlier (log, seal) pair stays valid; sealed signs "workcell-audit-seal-v2" and the chain
head, never the session id; Verify checks neither identity nor completeness; cmd/workcell/log.go verify. Input: (a) copy session A's
audit.log and audit.seal over session B's, or rename A's directory to B's id; (b) restore a (log, seal) pair snapshotted
mid-session; (c) a session ended by SIGKILL or by C24; (d) every session's initial seal is byte-identical, so an empty log with any
session's initial seal verifies. Effect: verify B prints intact for A's record under B's id; a log missing its secret uses,
refusals and session_end prints intact; verify never says incomplete; "intact" means "what this host wrote at some moment", not
"this session's" or "complete". Reproducing test (in this record only, for the budget: the test budget held 29 lines after the
redteam's deletions and S-F16's test took them, so the fix unit's redteam re-creates it): package main in cmd/workcell,
TestVerifyBindsTheRecordToItsSession, 22 lines: auditSession(t) to make the session testID, os.Rename of its directory to a
sibling id (testID with its last character replaced by 'e'), then verify([]string{that id}, io.Discard, io.Discard) must not return
0. On eef4b5c it fails with `verify exit 0, want 1: another session's record passed under this id`; the redteam showed it passes
under a scratch fix (sealed signs the prefix, filepath.Base(dir) and the head, and Verify checks the same) with TestVerify still
green. Outcome: CONFIRMED, low, by the verifier, who ran the test on 5be6450 (the same failure), traced the cause to sealed and
Verify, and noted that only the cross-session swap is tested: the rollback variant is inherent to the in-place seal and untested,
while log-only truncation is already caught (verify_test.go "truncated at a record"). Fix unit: S-F17, below S-1010 in PLAN.md.
For S-F17 to carry: bind the seal to the session by signing filepath.Base(dir), which Create and Verify both have (net 0 lines);
have verify refuse a session that is not running whose last record is not session_end (Verify returns the last record it parsed,
verify checks running(dir) and prints "incomplete: the session's end was not recorded", about 4 lines), keeping the check out of
audit.Verify so a running session still verifies; the suite removes sessions/ after every row, so crashed sessions of I11 rows do
not collide; the test can be the rewrite of TestVerifyRefusesAnotherHostsKey into two arms. Not ported.

C25 FIXED by S-F17, commit 7a468eb (PR #218). sealed in internal/audit/audit.go signs "workcell-audit-seal-v2", the session id
(filepath.Base(dir), kept on the Log) and the head, and Verify checks the seal under dir's id, so A's two files copied over B's, or
A's directory renamed to B's id, fail with "the seal is not signed with this host's key for this session" (inputs (a) and (d)).
Verify returns the last record it read, and verify in cmd/workcell/log.go refuses a session that is not running (running(dir))
whose last record is not session_end with "incomplete: the session's end was not recorded", so a session cut by SIGKILL or C24
(input (c)) no longer prints intact, while a running one still verifies. Paid for by folding the seal reader to one Sscanf of
"%x %x" (the same seals pass and fail). The rollback variant (b) stays S-1018's residual. Test: TestVerifyRefusesAnotherHostOrSession
and TestVerify's "cut before session_end, not running" arm in cmd/workcell/verify_test.go.

Handoffs: S-1013 takes the chain of C23 with S-1005's pipelined host_mismatch rate and with the EMFILE-starves-audit-log line, and
the C24 with C19 chain (a guest that fills the host volume through its export); S-1016 nothing; S-1018 the residual that attach,
pull and diff boots leave no record and that the in-place seal cannot name a rollback. The out-of-order times, port 0 and the
seal reader's trailing bytes are less-code notes for the fix units in internal/audit and cmd/workcell.

## S-1011: pins, selector, verification, bump tool, channel manifest, update client (I14, section 10), as built at main a74e3d3

Trust boundary. Rows 2, 27 to 30 and 32 to 35 of the S-1001 map. Attacker bytes enter at: (N) channel.json and artifact bodies,
only through TLS to the pinned host or the user's own [update] ca, so N holds availability alone, since no byte is used without the
manifest's signature or the pin's digest; (hostile upstream) npm packuments, GitHub release listings, vendor manifests, OCI tags
and manifests, Sigstore bundles, npm attestations and OSV answers into cmd/bump on the runner, dry-run only until H-905; (hostile
PR content) pulls, files and check-runs JSON into bump.merge; (G) one Exit frame driving installer.fail, gated by fresh since S-F1;
(R) the repo-local workcell.toml, whose [update] table ReadRepo refuses, and cwd, which is C19's route (S-F12 pending). Fields the
channel key holder K signs (Pin.Version, Released, pin names) and the operator's [update] table are out of scope except where they
mix with attacker bytes. Authority: update and the start-up goroutine run as the operator and write layers/<agent>/{*.ext4, current,
previous, failed}, channel.{serial,day,next} and updates.log; findLayers turns the current marker into a read-only block device the
next guest gets. Lenses worked in order: parsing and resources, logic and state, concurrency and check-to-use, cryptography and
identity, failure modes, downgrade and replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (go test of the eleven surface packages, -race over the update tests, 20 s local runs of
FuzzVerify, FuzzTarMember, FuzzProvenance, FuzzParse, FuzzAnswer and FuzzLayer with no crasher, and a loopback TLS channel harness
in the scratchpad driving the real `workcell update` and `workcell run` with XDG_CONFIG_HOME and XDG_DATA_HOME in the scratchpad,
every request to 127.0.0.1; `bump` built but not run, since its only non-test mode reads live upstreams (S12, T8); nothing in the
tree changed; env:any):
- PARKED line 10 (Rekor v2, intoto 0.0.2, FuzzParse's oracle): a v2 entry has no inclusionPromise, so verifyEntry refuses it, plan
  says verify-failed, Run opens the B5 issue and pins nothing: fail closed, refuted as a weakness. For P7 only: when a provider moves
  its .sigstore assets to Rekor v2, its bumps stop until a v2 path exists. The oracle note stays R3.
- PARKED line 22 (budget regex, a checks:write app, recorded responses): the regex ruling is the maintainer's; a check run posted by
  another app needs installation rights, out of scope. Observation.
- PARKED line 23 (B14 gives no issues:write): observation, with one ordering fact for H-905: bump.Run opens the B5 issues before the
  merge loop and before propose, and any issue-API failure stops the run, so under a token without issues:write one upstream whose
  release fails verification stops every merge and proposal of that run until the maintainer acts. P7 availability, not an
  invariant; dry-run only today; reasoned from code.
- PARKED lines 39 and 40 (B6 rows bound 15 min, pinSmoke's Hosts[0] assumption, the fake API speaks Anthropic alone, --version
  unverified for codex and copilot): escape rows and workflow strength, S-1012's and the report's; observations.
- PARKED line 42 (fast-lane lag understated, red nightly before cutover, versions-list fallback gone): advisory.go matches only
  closed SEMVER and ECOSYSTEM ranges (the safe direction) and verify.go refuses integratedTime <= 0; the reporting notes are B12,
  observation.
- PARKED line 44 (redteam ideas without a row), each tried: cooloff "0s" adds nothing and a negative value is refused by updateTable
  (TestParseErrors), and the project's cool-off is applied by bump before pinning while Released is bump's selection time, so the
  client cannot shorten it (B10): refuted; a pin released under 48 h ago can only come from K. channel = "hold" made zero requests
  (the harness counted 17 before and after a run; no channel.day written): refuted. channel.json at 65536 bytes verified and
  installed, at 65537 refused "over the size cap" with the serial untouched: refuted. A 3xx on channel.json: manifest sets
  ErrUseLastResponse (TestChannel "channel.json redirected"): refuted. A refused manifest (two days ahead) left the serial at the last
  verified value, a lower but above-floor serial then installed and one below the floor was refused: refuted, the floor is right.
  --to a previous version installed from disk with no fetch; --to a withdrawn one printed "is in neither pins nor previous":
  refuted. A manifest pinning only the other arch falls back to previous (TestUpdate "no artifact for this arch"), K-signed:
  refuted. [update] in a repo-local workcell.toml: ReadRepo refuses (policy_test errUpdate): refuted. channel = "http://":
  updateTable refuses: refuted. A tar with ../ or symlink members: memberPath refuses "..", a symlink is a guest-side node never
  followed on the host (FuzzLayer, TestUnpack): refuted. A key past NotAfter, and two signatures with only the second trusted:
  channel_test rows: refuted.
- FINDINGS line 89 (Pin.Version unconstrained): C26, the marker side of it is the half that outlives S-F12.
- FINDINGS line 92 (T5 for internal/pins/sources.go): BearerParams is strings.Cut over upstream bytes, no guest bytes and no panic
  possible; the vendor "latest" line goes through ParseVersion. No fuzz target requested (R5); no defect.
- C1 and S-F1: what remains is the honest B9 self-rollback of a layer applied in this very start when the guest's first frame is an
  Exit with Err; the precondition (a fresh layer this start) is not the attacker's, previous was installed under a valid manifest, and
  `update <agent>` restores it. Residual by design, no candidate.
- Parsing and resources: the envelope is strict and the payload lenient, duplicate keys last-wins under the signature, int64 forms
  refused by encoding/json, the 64 KiB cap consistent between Fetch and Verify (observed at the edge), artifacts 512 MiB on disk and
  1 GiB of tar in memory (upstream-chosen, digest-pinned), the ext4 writer bounded by ErrTooLarge, memberPath and split refuse
  traversal, NUL and names over 255; no in-scope attacker reaches the tar or ext4 parsers with bytes of its choice.
- Logic and state: the serial is written only after a verified manifest and only by verify; expiry is re-checked at apply; the
  failed, current and previous transitions traced for install, --to, --rollback, fail and apply (TestUpdate, TestFail, TestChannel
  and the probes above); choose applies the user's cooloff on top of Released and --to bypasses it by design.
- Concurrency and check-to-use: the daily goroutine is never awaited (a 1 B/s channel.json left a session start at 0.046 s);
  markers are tmp-plus-rename; images are renamed complete before any marker names them; the unlink of a replaced image leaves a
  running VMM's descriptor intact; two operator verbs at once can cross (A installs while B rolls back and removes A's image), the
  operator's own race; -race clean.
- Cryptography and identity: DSSE PAE as the spec; key id the SHA-256 of the raw key; ed25519.Verify behind the 32-byte check;
  sigstore binds leaf, signature and hash through the SET's canonical JSON; identity compared byte for byte with the version
  restricted by versionRE; the chain verified at integrated time against the embedded root, a stale root fails closed.
- Failure modes: no error path installs, names a half-written image or advances the serial; a failed newInstaller yields a zero
  installer whose fail is gated by fresh; bump never turns a verify failure into a skip (verify-failed token, an issue, -newest
  exits 1).
- Downgrade, rollback and replay: the replay window is 14 days plus 24 h skew per data directory, by design (B7); --rollback reads
  no manifest and may go to a withdrawn on-disk image, and the next apply re-applies the pin (observed): B10 semantics.
- Interaction: HTTP(S)_PROXY is honoured by DefaultTransport for update and bump only (the operator's environment); a relative
  [update] ca resolves against cwd (works from the directory holding ca.pem, refused elsewhere) and yields nothing against I14
  because the signature still holds; the data directory under cwd is C19 (S-F12).

Observations (R3, not candidates): apply blocks a session start for the whole artifact download, bounded by channelBound (17 s for
17 bytes at 1 B/s); apply writes one "refused" record and one stderr line per start for every provider with a row the manifest does
not pin; a killed download leaves layers/<agent>/.download-* for ever, since point globs *.ext4 only; bump.class identifies a bump
pull request by branch prefix, base and same-repo non-fork alone, never by author, so a same-repo pusher on bump/<class>-* with
rows only is merged by the tool when green (push access is out of scope; forks are refused, tested); more than 1000 open pull
requests or 100 check runs on a head make the tool wait or stop (availability); before H-905 channel.Keys is empty, so a default
configuration installs from the compiled row with no manifest, as section 10 intends, and `hold` installs from the row too
(docs/providers.md says so; ADR-004 is a proposal).

Coverage. Examined in full: cmd/workcell/update.go, layer.go, data.go, policy.go, run_vm.go, main.go; internal/policy/policy.go
30 to 290 (Policy, Update, Read, ReadRepo, Narrow, Parse, updateTable); internal/channel/channel.go; internal/artifact/verify.go;
internal/sigstore/verify.go and root.go; internal/pins/pins.go and sources.go; pins/pins.go and the four rows; internal/bump/bump.go
and github.go; cmd/bump/main.go; internal/advisory/advisory.go; internal/rootfs/layer.go, tree.go, ext4file.go, ext4.go;
internal/version/version.go; internal/provider/provider.go and the four TOMLs; bump.yml and nightly.yml as callers; docs/policy.md,
docs/providers.md, docs/adr/004-channel.md (a proposal, nothing in it counted); the tests of every package above and
escape/suite/update.go, update_test.go, channel.go, channel_linux.go, channel_test.go, layer.go, rollback.go and
escape/sandbox/control_channel_linux.go; FINDINGS S-1001 and the C19 record, the handoffs naming S-1011 or S-1013; PARKED lines 10,
22, 23, 39, 40, 42 and 44. In part: internal/policy/policy_test.go ([update] rows), policy.go 1 to 29 and 290 to 658 (the lexer,
S-1009's), internal/audit/key.go LoadKey, escape/suite/tests.go update, layer and rollback rows, escape/sandbox/sandbox.go
signatures, internal/rootfs/oci_test.go. Not opened: internal/sigstore/trusted-root.json (TestPublicRoot proves it parses),
internal/pins/testdata, internal/rootfs/build.go and oci.go (S-1012), escape/sandbox/workcell*.go, cmd/workcell/pull*.go and
internal/workspace (S-1008), _legacy/. Ported files: none on this surface carries `// Ported from v1`, so nothing carries also in
v1 main and nothing is private; nothing concerns someone else's project: no NEEDS-YOU. No model declined and no safeguard re-ran a
request.

### S-1011 candidates

C26. ID I1 and I7 through the layer marker, with I14 hardening on the manifest side. Attacker: guest root, only through C19's
precondition (the operator's cwd or pull destination lies above the data directory, so pull writes layers/<agent>/current back,
which checkPath admits as content) until S-F12 lands; afterwards only the channel key holder K, out of scope, so hardening. Where:
cmd/workcell/layer.go findLayers joins the marker's text to the layer directory with only an os.Stat and no bare-name check;
cmd/workcell/update.go builds the image name from pin.Version and point compares Base of images with the raw marker; internal/
channel/channel.go checks a pin's sha256 and url but not its version. Input: (a) a signed manifest whose pin has
"version":"../evil"; (b) layers/claude/current holding ../../../../../../../../../../etc/hostname, then `workcell run claude`.
Effect: (a) the image lands at <data>/layers/evil-<sha>.ext4, outside layers/claude, current and previous hold "../evil-<sha>.ext4",
and point never removes it (observed with the real binary against the loopback channel); (b) findLayers accepts the path and the
session boots with the host file as the claude layer's drive: run_vm.go passes it into vmm.Config.Layers, the Firecracker backend
makes it a read-only drive, and the init treats a failed ext4 mount as non-fatal, so guest root reads /dev/vdX, any user-readable
host file of 512 bytes or more (Firecracker exposes whole sectors). Reproducing test (in this record only, for the budget: the test
budget stands at 27497 of 27498 and the file is 27 lines, so the fix unit's redteam re-creates it): package main in cmd/workcell,
TestC26LayerMarkerIsABareName (I1, I7, I14): dir := t.TempDir(); sub := filepath.Join(dir, "layers", "claude"); for each m in
{"../../outside.ext4", "sub/x.ext4"}: os.MkdirAll(filepath.Join(sub, "sub"), 0o700), os.WriteFile(filepath.Join(sub, m), nil,
0o600) and writeMarker(sub, "current", m) must succeed (the target exists, so only the name decides), then findLayers(dir) must
return an error. On d953790 it fails with `marker "../../outside.ext4": findLayers accepted [{claude <dir>/outside.ext4}]; want a
refusal` and the same for sub/x.ext4; the redteam showed it passes under a scratch fix (the extra condition
`|| name != filepath.Base(name)` on findLayers' refusal) with cmd/workcell green. Outcome: CONFIRMED, low, by the verifier, who ran
the test on d953790 (the same failure), traced the marker to the drive list and the init's non-fatal mount, noted that the test's
power (writing current) is the operator's and that the only in-scope writer is the guest through C19, under which it can already
replace the layer image itself, so medium would re-report C19's precondition; not intended behaviour, since the marker is
documented as naming an image, but no independent break. Fix unit: S-F18, below S-1011 in PLAN.md. For S-F18 to carry: refuse
in findLayers a marker that is not its own filepath.Base (one edited line, net 0 product lines; product stands at 14999 of 15000)
and, if a line can be folded, refuse a pin whose Version holds "/" or "\\" beside channel.Verify's sha256 and url checks, so a
key-holder-signed manifest cannot re-create the marker; the "previous" marker on the rollback path is read the same way, and a
marker naming a symlink to a host file passes a Base check (an Lstat regular-file check would close it, the redteam's variant (b)).
Not ported.

C26 FIXED by S-F18, commit 00c549e (PR #220). findLayers in cmd/workcell/layer.go refuses a marker whose text is not its own
filepath.Base, on the same line as the missing-image check, with "the <agent> layer <marker> is not a bare name; run workcell update
<agent>", so input (b) exits 125 before any boot (the real binary under strace made no execve beyond itself); the rollback path
writes the previous marker into current, which the same reader then judges. channel.Verify in internal/channel/channel.go refuses
with errPin a pin whose Version holds "/" or "\", over Pins and Previous alike, so input (a) is refused at the manifest and never
reaches fetch or point; errPin now says "a bare version" too. Net +1 product line (the strings import; product 15000 of 15000),
test 27495 of 27500. Test: the two C26 rows of TestFindLayers in cmd/workcell/layer_test.go (markers ../../outside.ext4 and
sub/x.ext4 with their targets present) and the two C26 rows of TestVerify in internal/channel/channel_test.go (Version ../evil in
Pins, ..\evil in Previous); all four fail on a74e3d3 and pass on 00c549e. Variant (b), a marker naming a symlink, and the
markers ".", ".." and "/" that resolve to a directory, are parked (no I1 reach, same C19-only attacker).

Handoffs: S-1013 takes the chain of C26 with C19 and C21 (a relative data home or a cwd above the data directory, through which
the guest writes the marker), the half-written .download-* residue with C24's volume fill, and the two-verbs-at-once race on the
layer directory; S-1012 takes the bump.class author question and the B6 row bounds (PARKED lines 22, 39, 40); S-1018 the residual
that before H-905 channel.Keys is empty and `hold` installs from the compiled row, and that --rollback can reach a withdrawn
on-disk image; H-905 the issues:write ordering fact of bump.Run.

## S-1012: workflows, release, signing, image build and dependencies as a supply chain (section 9), as built at main 9ea0dcc

Trust boundary. Rows 31, 34, 36, 37 and 38 of the S-1001 map. Attacker bytes enter in four places. (1) The hosted runner RUN (a lent
machine, passwordless sudo, a contents: read token, no secret): ci.yml runs the pull request head's own loop/gate.sh under
pull_request_target, so a pull request author's free-path code, tests, escape/ and spikes/ run there; the only authors are
collaborators, because pull_request_creation_policy is collaborators_only (loop/settings.sh:39, "does not expire"; REFERENCE.md:784)
and the Actions policy (loop/github-actions-policy.json) lets only pull_request_target and schedule start a workflow, always from
main. S-1001's observation that this rests on the six-month interaction limit is corrected: the interaction limit covers issues and
comments; pull request creation is the non-expiring setting. Both are repository settings outside the tree, verified by
`settings.sh check` at each checkpoint and by nothing in the repository. (2) Network bytes into the runner: mkimage pulls Debian
from mirror.gcr.io by digest (internal/rootfs/oci.go), the escape adapter and spikes/install fetch Firecracker and a kernel by pinned
URL and SHA-256 (escape/sandbox/workcell_linux.go:25, spikes/install/install_test.go:33), bump -newest and -dry-run read upstream
listings, OSV and the GitHub API, and setup-go, cosign-installer and attest-build-provenance fetch their tools; all over TLS, so N
holds availability only, and a hostile upstream is an allowlisted provider's own service, out of scope, whose bytes bump parses only
after B5 verification (S-1011). (3) The maintainer's signature chain: guard.yml runs main's loop/guard.sh over the pull request's
objects with gpg against .github/maintainer.asc, whose issuer-fingerprint subpacket decodes to the 40 hex digits in maintainer.fpr
(key created 2023-01-16, expires 2028-01-15). (4) The user's machine: scripts/install.sh (curl over TLS from the release URL,
SHA256SUMS from the same origin, sha256sum -c, --version, then mv), and at run time cmd/workcell/data.go, which stats vmlinux,
initrd.cpio, root.ext4 and firecracker in the data directory with no digest or signature check. Authority: gate runs pull request
code as the runner user with sudo; merge holds contents: write and pull-requests: write and runs no pull request code; release.yml's
sign holds id-token: write and attestations: write and publish holds contents: write (W11); nightly's issue job holds issues: write
and checks nothing out; bump.yml reads only. Every build and release runs on exactly go1.27.0: go.mod says `go 1.27.0`, all nine
setup-go uses take go-version-file: go.mod, and GOTOOLCHAIN=auto never upgrades a satisfied requirement. Lenses worked in order:
parsing and resources, logic and state, concurrency and check-to-use, cryptography and identity, failure modes, downgrade and
replay, interaction with other surfaces.

Leads refuted or bounded, with evidence (reads of every file named under coverage; `go mod verify` clean, `go list -m all`,
`go mod tidy -diff`, `go mod graph`; loop/guard.sh run locally on two refs; zizmor and actionlint run twice; govulncheck on the
hosted gate-arm64 job of the claim through a spike test, since this session's network policy refuses vuln.go.dev; the workflows
were not executed, no GitHub API call was made, and the full gate was not run here because it fetches Firecracker and a kernel
from hosts this session may not reach; nothing in the tree changed; env:any):
- PARKED line 22 (budget regex, a checks:write App): a check run from another App needs installation rights, out of scope;
  release.yml filters on app 15368 and settings.sh:108 detects a foreign check suite. Bounded, observation.
- PARKED line 39 (B6 rows bound at 15 min against the gate's 900 s): a bump pull request with a slow 100 MB download fails the
  gate by time while nightly's upstream job has 45 min; availability for P7, an observation for H-905.
- PARKED line 40 (the fake API speaks Anthropic alone): B11 strength; codex and copilot are smoked by --version plus the probe's
  own call. Observation.
- S-1011's bump.class question (a bump pull request identified by branch prefix, base and same-repo non-fork, never author):
  dry-run only until H-905; a same-repo pusher has push access, out of scope; the App is the intended pusher; main's ruleset still
  demands the three checks. Bounded.
- PARKED lines 87 and 88 (S-F18 notes on findLayers markers): cmd/workcell, not this surface; they stay with S-1013.
- Parsing and resources: oci.go caps the manifest at 64 KiB and hashes it against the requested digest before JSON, re-checks every
  descriptor digest, bounds blobs by declared size under 512 MiB with the stream hashed and counted, 128 layers, 2 GiB raw across
  layers, 400 MiB of image (build.go limitWriter); the Bearer realm must be https and the token goes only to URLs built on the
  registry base, dropped on a cross-host redirect (TestPullRefusals, TestPullTokenStaysWithRegistry, TestApplyLayerBomb,
  FuzzLayer); layer.go refuses absolute names, "..", names over 4096, components over 255 or with NUL, unknown tar types, and
  hard links to anything but an existing non-directory; ext4.go is deterministic (TestDeterministic) with every overflow closed
  by errNoFit or ErrTooLarge, over the host's own bounded tree. gate.sh's flat unrolls go.mod blocks and refuses replace, exclude
  and ignore (a replace smuggled into a require block is refused by Go itself, so nothing builds); hidden refuses underscore
  directories, nested go.mod or go.work, vendor/, odd bytes and leading dashes; nightly's fuzz matrix takes Fuzz names through a
  strict sed and package paths from go list, both through env, so nothing is injected into go test -fuzz; fuzz-minutes.txt is
  digits only, at most 240. install.sh greps a fixed asset name, checks one SHA256SUMS line, runs under set -eu and removes tmp
  and new on EXIT; spikes/install proves the wrong-checksum, missing-sums and broken-asset refusals against a loopback server.
- Logic and state: the required checks are gate, gate-macos and guard (github-main.json), strict up to date, squash only, no bypass
  actors; merge runs only for claude/* heads from the same repository by the owner, re-reads the title each attempt and pins sha
  (ci.yml:100-124), and a `try:` title never merges; no required job has an `if` (W3). release.yml's verify accepts a commit only
  with completed, successful gate and gate-macos check runs from app 15368, and a squash commit with none only when a pull request
  whose merge_commit_sha is this commit has a head whose tree equals HEAD's tree and that head is green (lines 32-41), which the
  strict up-to-date rule makes sound; a page over 100 check runs fails closed (W7). guard.sh: free-only changes pass on any
  shape; a locked change must be one commit whose only parent is the live tip, signed by the pinned key with `Locked-paths:
  reviewed` as the signed message's last line, at most 2 h old and at most 10 min ahead; run here, `loop/guard.sh 9ea0dcc
  48adeba` printed GUARD PASS and the reverse printed GUARD FAIL (not built on the current tip). The crafted-commit experiment
  (locked edit, symlink, case twin, docs/codex.md, dot component, two commits, a ticked human gate, a RESUME heading) was refused
  by this session's permission system, so those refusals are reasoned from lib.sh:117-165 and :255-273 only. bump -newest
  rewrites only guest rows, only when newest is eligible and not in dry run, and exits 1 on verify-failed (B5); nightly's fresh
  step turns a missed P7 into an output and keeps the step's exit (B12).
- Concurrency and check-to-use: gate.sh reads the tree (sections 1 and 2) before anything from it runs and runs the VM suite before
  the unit tests; zizmor's five concurrency-limits findings are W4 by design while the loop runs; a push after a merge run started
  fails the merge call on sha and the ruleset re-judges the head; the two-hour signature window is REFERENCE.md:809's known
  residual, whose attacker is the App or the loop, out of scope; pull_request_target edited re-runs on the same head, and results
  are per commit; nightly's GATE_BASE: HEAD after the in-tree pin rewrite lets changedPin see the rewritten row through the embed.
- Cryptography and identity: the maintainer key is EdDSA, VALIDSIG is matched against the pinned fingerprint on one line
  (lib.sh:287-296), an expired key fails closed, the signed time comes from the hashed subpacket, and the parent rule stops a
  replayed signed commit. Release: keyless cosign over SHA256SUMS with the identity release.yml@<ref> and the GitHub OIDC issuer,
  verified in publish under the same identity, one attestation with the checksums as subjects (W10); SHA256SUMS covers workcell-*
  and guest-*. Dry runs sign as refs/heads/main, which the documented tag identity (install.sh:11-13) rejects. mkimage: Debian's
  registry publishes no signature, so the digest pin is the identity (B5 "wherever one exists"). Modules: go.sum covers every
  module in the build graph, GOSUMDB sum.golang.org, GOPROXY proxy.golang.org; actions are pinned by SHA with version comments
  (SHA-to-tag not confirmed offline); runner labels are version labels (ubuntu-24.04, macos-15, ubuntu-24.04-arm), the float
  ci.yml:15-16 admits.
- Failure modes: every run step is bash -e with pipefail; verify's green() turns a gh api failure into not green and exit 1; ci's
  KVM step exits 1 with an infrastructure annotation and GATE_REQUIRE_VM=1 makes a missing hypervisor a failure in the Linux
  gate (gate.sh:166), so the VM suite is never silently skipped; guard.sh dies with exit 4 on every error and treats only grep 1
  and cmp 1 as "no"; budget fails on an unmeasurable number; mkimage removes a half-written output; install.sh installs nothing
  on any failure. No fail-open path found. By design: nightly's fresh step lets a missed P7 exit 0 (B12).
- Downgrade, rollback and replay: the toolchain pin never moves (C27); pins never move backwards (S-1011); the enforced lists
  ratchet from origin/main (gate.sh:50-61); nobody can create, move or delete a tag until H-905 (github-tags-all.json), and
  `gh release create --verify-tag` plus the release-exists error keep a re-run closed; install.sh's default tag v2.0.0 is
  hand-bumped (observation).
- Interaction: nightly's B6 smoke runs upstream's newest provider binary in a real VM on the runner with Isolated: true and
  judgeResolver, so the binary reaches only the loopback canary (T8, S12); the runner's sudo uses (unshare -n, nsenter, a /32 on lo,
  losetup, a private mount namespace for resolv.conf, setpriv to drop back) are local to the runner. The A6 promise (one signed
  prebuilt guest image pulled by digest) has no client half: data.go:62-78 only stats the four files, `workcell update` installs
  provider layers only, and the release ships guest-*.img and raw workcell-init-* while the client loads root.ext4, initrd.cpio,
  vmlinux and firecracker that no product code fetches (README:51-53 says so); the only in-scope writer of the data directory is
  the guest under C19 (S-F12 pending), already recorded by S-1008, so observation and handoff, not a candidate.

Tool passes (S10). zizmor 1.32.0 (--persona=pedantic --no-online-audits, and again under the auditor persona): 21 findings, 2
ignored, 0 medium or high: five concurrency-limits (bump, ci, guard, nightly, release) are W4 by design while the loop runs,
refuted; three undocumented-permissions (bump.yml:22, release.yml:23 and :80) and eleven anonymous-definition (job names) are
style, R3; the two ignored dangerous-triggers (ci.yml, guard.yml) rest on .github/zizmor.yml's rationale, which holds:
definitions load from main, guard runs no pull request code, ci's token reads a public repository and only collaborators open
pull requests. No candidate. actionlint v1.7.12: 0 errors in 5 files (its shellcheck and pyflakes integrations were off, neither
installed here). No candidate. govulncheck v1.9.0 on the hosted gate-arm64 job of commit 48adeba (go1.27.0 linux/arm64, live
database; the spike test spikes/govulncheck ran it with -v and was deleted before delivery): "Your code is affected by 11
vulnerabilities from the Go standard library", plus 2 package-level and 2 module-level ones not called, every one found in
go1.27 and fixed in go1.27.2, go1.27.3 or go1.27.4. Triage: GO-2026-6859 (net/http server crash, MaxBytesReader header race,
fixed 1.27.4; trace #10 is proxy.Proxy.serveTerminated calling http.Server.Serve) reachable by G, and GO-2026-6809 (crypto/x509,
fixed 1.27.3; trace #1 is sigstore.chain calling x509.Certificate.Verify, and the proxy's upstream transport verifies the same
way) reachable by N: both C27. GO-2026-6617, 6612, 6611 and 6603 (HTTP/2 server) not reachable: the terminated server offers
http/1.1 alone by ALPN and no cleartext HTTP/2, and the transport has h2 off. GO-2026-6613 (server desync after a 2xx CONNECT)
not reachable: CONNECT is refused (terminate.go:400). GO-2026-6605 (client desync after a CONNECT rejection) not reachable: the
product transport uses no proxy, and HTTPS_PROXY on DefaultClient is the operator's. GO-2026-6610 (h2 transport) only through
DefaultClient to pinned or operator-configured hosts, a desync with that same host, low at most. GO-2026-6608 (textproto memory
limit) bounded: the server bounds header bytes at the connection reader (MaxHeaderBytes 64 KiB), the client side reads an
allowed upstream's answer, and the single trace is the suite's canary client. GO-2026-6607 (ECH outer extension references) not
reachable: no ECH keys are configured, so the inner hello is never decrypted, and no transport sets an ECH config list.
GO-2026-6609 (Range), 6604 (os.Root on Windows), 6600 and 6599 (html/template) are not called. Coverage gap: the pass ran on
linux only; the darwin binary links vz, go-infinity-channel and x/mod, which were not scanned. shellcheck: not installed, not run.
`go mod tidy -diff` reports github.com/ebitengine/purego v0.11.2 as an unused direct requirement; `go mod graph` shows x/crypto
only through vz's go.mod, not linked.

Observations (R3, not candidates): gate.sh:77 lets a free go.mod carry godebug and toolchain directives, and godebug can relax
TLS and x509 defaults for every binary (tlsrsakex, x509sha1, tls10server) while toolchain can pick any toolchain; the only writer
is the loop, out of scope, and a proposal could narrow the regex to module, go, require, retract and tool. The S-1001
interaction-limit observation is corrected above; settings.sh check is the only detector, and REFERENCE.md:822 records that the
Actions policy could only be read, not tried. OPTIONS * on a terminated connection is answered by net/http's own handler before
the product's judge, whatever the toolchain (C27's product-side half; harmless alone, nothing goes upstream). W6 drift: the
Firecracker v1.17.0 and kernel pins are written twice (escape/sandbox/workcell_linux.go:26 and spikes/install/install_test.go:33-37).
`gh attestation verify --repo` without a ref accepts the daily dry-run builds, which are public workflow artifacts for a day; the
cosign line with the tag identity does not; pin --source-ref in the documentation at H-905. dependabot.yml's docker entry covers
no Dockerfile, and W12 names Dependabot for the base image while the base image is cmd/bump's OCI row: wording for the
maintainer. purego is an unused direct dependency, one of 15 under the budget. The pinned maintainer key expires 2028-01-15, after
which guard fails closed on every locked change until a new key lands. install.sh: curl -L follows a redirect to any scheme (no
--proto =https --proto-redir =https), and release.yml does not codesign the darwin binary with the virtualization entitlement
(escape/sandbox/workcell_darwin.go does it for the suite), so `workcell doctor` on a Mac would refuse the released binary: P6,
for H-905.

Coverage. Examined in full: .github/workflows/ci.yml, guard.yml, release.yml, nightly.yml, bump.yml; .github/dependabot.yml,
zizmor.yml, maintainer.asc, maintainer.fpr; loop/gate.sh, guard.sh, lib.sh, settings.sh, free-paths.txt,
github-actions-policy.json, github-main.json, github-tags-all.json; scripts/install.sh; spikes/install/install_test.go;
cmd/mkimage/main.go; internal/rootfs/oci.go, build.go, layer.go, ext4.go, tree.go, ext4file.go; internal/artifact/verify.go;
internal/version/version.go; pins/pins.go and the four rows; internal/pins/pins.go and sources.go; internal/bump/bump.go;
cmd/bump/main.go; escape/cmd/escape/main.go; escape/sandbox/workcell.go, workcell_vm.go, workcell_linux.go; escape/suite/smoke.go;
cmd/workcell/data.go; go.mod, go.sum; docs/threat-model.md, CONTRIBUTING.md, README.md to line 70; SPEC sections 2, 3, 4, 6, 7, 9,
10, 11, 13; FINDINGS S-1001 and S-1011; PARKED in full; REFERENCE.md section 9; the three tool outputs. In part:
internal/proxy/terminate.go (the server literal, transport and CONNECT refusal), loop/PROMPT.md, loop/adopt.sh and land.sh (the
signing lines), escape/suite/tests.go (row registration), escape/sandbox/workcell_darwin.go (codesign lines), and the go1.27.0
GOROOT's net/http server.go, request.go, textproto reader.go, crypto/tls handshake_server.go and ech.go. Not opened: the
*_test.go of rootfs and mkimage beyond their function names, internal/sigstore, internal/channel, cmd/workcell/update.go beyond
its client lines, loop/checkpoint.sh, preflight.sh, baseline-ci.sh, setup-*.sh, loop/test/, _legacy/. Not run: the workflows,
the full gate here, any GitHub API call, the crafted-commit guard experiment and the gpg verification of recent locked commits
(both refused by this session's permission system). Ported files: none on this surface; C27's reachable path passes through
internal/proxy/terminate.go, which is ported, so its record carries also in v1 main. Nothing concerns an undisclosed weakness in
someone else's project: the Go advisories are published and fixed upstream. No NEEDS-YOU. No model declined and no safeguard
re-ran a request; two tool permissions were refused to the auditor (a crafted-commit experiment in a scratch clone and gpg
verification), reasoned from the scripts instead, no request rephrased.

### S-1012 candidates

C27. ID W12 (the toolchain has no updater), with B2 and B4 (trusted class, security fast lane); invariants claimed I12 by G on the
terminated-HTTP path and I5 and I6 by N on upstream certificate verification. Attacker: guest root on a terminated connection;
a network attacker answering an allowed name's TLS. Where: go.mod line 3, `go 1.27.0`, from which every setup-go in the five
workflows takes its version (go-version-file), so every gate run, nightly, dry run and, after H-905, every release binary is built
with go1.27.0; nothing moves the directive: .github/dependabot.yml's gomod entry updates require lines (and sits at
open-pull-requests-limit 0 until cutover), cmd/bump's source types are NPM, GitHubReleases, VendorManifest and OCI
(internal/pins/sources.go:42), and gate.sh:77 even admits a toolchain directive. Reach: internal/proxy/terminate.go's http.Server
literal (serveTerminated calls http.Server.Serve, trace #10 of GO-2026-6859) and its upstream transport, and
internal/sigstore/verify.go's chain (x509.Certificate.Verify, trace #1 of GO-2026-6809). Input: (a) over a terminated connection
`OPTIONS * HTTP/1.1` with a 64 KiB body, which net/http's own globalOptionsHandler wraps in MaxBytesReader, the function
GO-2026-6859 names; (b) N answering an allowed name with a chain through an intermediate that go1.27.3's crypto/x509 distrusts.
Effect claimed: (a) the supervisor dies or hangs on guest bytes; (b) the real secret to a wrong party; structurally, eleven
standard-library advisories against go1.27.0, fixed in go1.27.2 to go1.27.4, ship in every build. Evidence: govulncheck v1.9.0 on
the hosted gate-arm64 job of 48adeba (above). The redteam tried (a) for real on terminateFixture: the go1.27.0 to go1.27.4 diff
of net/http/server.go shows GO-2026-6859 is response.requestTooLarge setting a header from whatever goroutine reads a
MaxBytesReader, and the only MaxBytesReader on the terminated path, the OPTIONS * handler, reads on the serving goroutine, while
terminate.go never wraps r.Body: `OPTIONS *` with a 64 KiB body, with Expect: 100-continue, with a half-closed body and with a
pipelined second request, twenty repetitions each with and without -race, got 200 and a fresh connection was served, identically
on both toolchains. Reproducing test delivered (in this record only, for the budget: 27495 of 27500 and the file is 31 lines):
package proxy, TestC27 (I12 in the comment): addr, ca, _, _ := terminateFixture(t, &fakeBroker{value: "real-secret"}); a
tls.Dial to addr with ServerName example.com and RootCAs caPool(t, ca), a 3 s deadline, one Write of
"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\nGET /v1 HTTP/1.1\r\nHost: example.com\r\n\r\n", then
got, err := io.ReadAll(c); it fails unless strings.Count(string(got), "HTTP/1.1 ") == 1, err == nil and got starts with
"HTTP/1.1 405 ". On go1.27.0 (the tree's toolchain) it fails with "after a refused CONNECT got 2 responses, read error i/o
timeout, want one 405 and then the connection closed" and the 405 is followed by a 200 (the pipelined GET served on the same
connection); under GOTOOLCHAIN=go1.27.4 it passes (the 405 carries Connection: close and the server closes), 5 of 5 under -race;
the orchestrator and the verifier reproduced both results. Outcome: DOWNGRADED to low by the verifier. The test demonstrates a
toolchain fingerprint, not a break: go1.27.4's change is "don't reuse a connection after a CONNECT, even if we reject it"
(hardening), while GO-2026-6613 itself needs a 2xx to CONNECT and terminate.go always writes 405, so the pipelined GET is parsed
as an ordinary request and passes the whole handler (sameHost, admits, broker, carriesPlaceholder); nothing in SPEC forbids
keep-alive after a 405. Of the eleven advisories none is reachable by G or N on this tree: 6859 needs an application
MaxBytesReader on another goroutine; 6613 a 2xx CONNECT; 6605 a client that sends CONNECT (ReverseProxy never does); 6617, 6612,
6611 and 6603 an HTTP/2 server, while serveTerminated offers http/1.1 alone; 6610 an HTTP/2 transport, while p.transport sets
TLSClientConfig and DialContext without ForceAttemptHTTP2; 6607 runs only after HPKE decryption with server ECH keys, none
configured, and peekSNI aborts any ECH hello first; 6608's accounting slip is bounded by MaxHeaderBytes plus 4096 per request and
maxConns. GO-2026-6809 would let N pass the upstream check only with the private key of one of the eight distrusted
intermediates and a host root store that still chains them, a precondition N does not control (S6 ceiling medium), and no
reproducing test can exist without those keys, so under S4 it is undemonstrated. The structural half stands: a build tool pinned
at the .0 patch with no updater is a W12 and B2 gap, hardening with no demonstrated break, low. Fix unit: S-F19, below S-1012 in
PLAN.md. For S-F19 to carry: go.mod line 3 `go 1.27.4` (a free path, one line, no proposal; every workflow follows, go.sum
unchanged; the redteam's and verifier's runs show go1.27.4 downloads from proxy.golang.org under GOTOOLCHAIN=auto), under B4's
fast lane since published advisories affect the pinned version; re-create TestC27 from this record in internal/proxy after
folding its 31 lines (the verifier notes it asserts standard-library behaviour, T5, so the reviewer may park it; S4 says the
test stays); and, if a product line can be folded, DisableGeneralOptionsHandler: true in terminate.go's http.Server literal, so
OPTIONS * meets the product's judge like every other request (the redteam saw it answered 200 before the judge, with no host
check and no deny line; harmless alone, nothing goes upstream). The updater for the go directive is the maintainer's: dependabot.yml
is locked and cmd/bump has no product room, so S-F19 proposes nothing and S-1018 reports the gap. Ported: the toolchain pin is
this repository's go.mod; the product-side half is in the ported literal, also in v1 main: egressproxy/terminate.go (the
http.Server literal). Not someone else's undisclosed weakness: the advisories are published and fixed upstream.

C27 FIXED by S-F19, commit f54bf9e (PR #222). go.mod line 3 says `go 1.27.4`, with no toolchain directive and go.sum unchanged, so
every workflow's setup-go (go-version-file) built that commit with go1.27.4: the hosted gate, gate-arm64 and gate-macos logs each
print `go version go1.27.4` for their platform, and the gate took 263 s on linux/amd64 with the VM suite. Product side:
DisableGeneralOptionsHandler: true in serveTerminated's http.Server literal (internal/proxy/terminate.go, ported, header kept), paid
by folding the Rewrite closure's two Host assignments to one line, net 0 (product 15000 of 15000); OPTIONS * now runs the handler's
judge like every other request: with a foreign Host it is answered 421 with a host_mismatch deny record, under a rule bound to
POST /v1/ it is answered 403 with binding_mismatch, and with the SNI host and an admitted placeholder it reaches the bound upstream
over the verified chain, where the parent answered 200 before the judge with no record (builder and reviewer each drove the real
listener). Test: TestC27 in internal/proxy/terminate_test.go, re-created from this record in 13 lines, fails on the parent
(go1.27.0: a 405 then a 200 for the pipelined GET, i/o timeout) and passes 20 of 20 under -race on the fix; paid by five plain folds
in the same file (callCount, the rules literal, a blank line, two map literals), test 27497 of 27500. The reviewer accepted the
test under S4 and T6 and noted (R3) that it asserts net/http behaviour, so what it guards is a future move of the go directive.
The toolchain still has no updater (W12): dependabot.yml is locked and cmd/bump has no toolchain source type, so nothing was
proposed and S-1018 reports the gap. The macOS job of the first push failed on TestRelayDropsAnIncompleteHeader, a measurement
gap in that test (its start time was taken after the relay's accept, which sets the deadline), fixed in the same pull request by
taking the start before the dial. Also in v1 main: egressproxy/terminate.go (the http.Server literal).

Handoffs: S-1013 takes the A6 client gap through C19 (guest-written root.ext4, vmlinux or firecracker in the data directory)
with S-F12 and C26, and PARKED lines 87 and 88; S-1016 takes govulncheck with GOOS=darwin over vz, go-infinity-channel and x/mod
on the Mac; S-1018 takes the residual lines for the unverified guest image on the client, the dry-run attestations, the godebug
and toolchain directives a free go.mod may carry, the key expiry, the install.sh notes, the toolchain updater gap and the
corrected pull-request-creation statement; H-905 takes the released artifact set against what the client loads, darwin
codesigning, --source-ref in the verification docs, and the B6 bound against the gate budget.

## S-1014: the four-hour fuzz run (S10), on the scheduled nightly.yml run of 2026-11-16T04:54Z at main a0a5991

Scope. S10 asks four hours of fuzzing per target. S-1014a set escape/fuzz-minutes.txt to 240, and the first scheduled nightly.yml
run after its merge (a0a5991, 2026-11-15T17:22Z) ran on 2026-11-16T04:54Z and completed success in 14499 s. Its plan job listed
every `Fuzz` target of every package without a `Ported from v1:` marker, 18 targets in 12 packages, and started one fuzz job per
target with `-fuzztime 240m`. The five targets in ported packages (internal/audit FuzzEachLine; internal/proxy
FuzzCarriesPlaceholder, FuzzHide, FuzzPeekSNI and FuzzSwapRefresh) are H-1015's, on the Mac (S14), and S-1016 triages them.

Evidence. Each fuzz job's log ends with `fuzz: elapsed: 4h0m0s` or `4h0m1s`, then `PASS` and `ok <package> 14400.0xx s` to
14401.1 s; no log holds `Failing input`, `FAIL` or a `testdata/fuzz` path, and the `if: failure()` step that prints a crasher's
input ran in none of them. The orchestrator fetched all 18 logs (C6) and read their heads and tails by search, not whole.

| target | execs in 4 h | corpus (new interesting, total) |
|--------|-------------|---------------------------------|
| escape/suite FuzzParseDNSQuery | 461,659,047 | 14, 17 |
| escape/suite FuzzParseDNSReply | 472,589,028 | 109, 111 |
| escape/suite FuzzQUICDCID | 288,397,485 | 2, 4 |
| escape/suite FuzzParseResult | 291,617,935 | 24, 27 |
| escape/suite FuzzFormat | 364,996,572 | 30, 33 |
| internal/advisory FuzzAnswer | 432,957,936 | 761, 778 |
| internal/artifact FuzzTarMember | 374,796,425 | 301, 305 |
| internal/artifact FuzzProvenance | 309,350,462 | 783, 790 |
| internal/channel FuzzVerify | 360,763,902 | 803, 807 |
| internal/fileserve FuzzRequest | 1,053,247,232 | 184, 238 |
| internal/guest FuzzDecode | 1,032,757,466 | 873, 881 |
| internal/policy FuzzParse | 788,431,439 | 354, 361 |
| internal/relay FuzzDecode | 2,060,314,883 | 3, 7 |
| internal/relay FuzzReadFrame | 2,000,808,279 | 2, 5 |
| internal/resolver FuzzAnswer | 2,215,594,740 | 29, 34 |
| internal/rootfs FuzzLayer | 571,707,232 | 230, 232 |
| internal/sigstore FuzzParse | 994,043,024 | 743, 752 |
| internal/wire FuzzReadFrame | 1,405,399,617 | 31, 35 |

### S-1014 candidates

None. Zero crashers in 18 targets over 72 target-hours and about 15.5 billion executions, so nothing to minimise, and nothing to
confirm or refute under S4. No redteam or verifier ran. escape/fuzz-minutes.txt is back at 10, so the next nightly.yml run fuzzes
each target for ten minutes again.

Observations (R3, not findings). The relay and resolver targets reach about 140,000 execs a second and the parsers of signed or
structured input (sigstore, channel, artifact, advisory) between 21,000 and 69,000, with corpora of 750 to 880 entries, so a
longer run of those four would add the most coverage per hour if S8 asks for a second sweep. The new corpus entries live only on
the runner: the fuzz job saves nothing, so each run starts from the seed corpus in the tree and the grown corpus is lost. That
is the job's design, since nothing in the tree lists what a run found, and it costs nothing at the gate.

Handoffs: S-1016 takes the five ported targets from H-1015's four-hour Mac run, and S-1018 reports 18 targets at four hours
with no crasher, plus the five on the Mac, as the S10 fuzzing line of the public report; S-1013 has nothing from this unit.
## S-1013: chains across surfaces, and the start-up, shutdown, crash and upgrade windows, as built at main d998add

Trust boundary. The chained surface has no new entry point of its own: its attacker bytes are those of the earlier
surfaces (guest frames on 5000 and 5002, relay streams on 5001, the guest-written workspace and cache images, the
repository tree and its workcell.toml, hostile model output as argv, the network attacker as the host's DNS and TLS
peer), and what is new is where they meet host state that outlives one session and the operator's own environment.
That state is the data directory (artifacts, audit.key,
sessions/<id>/{audit.log,audit.seal,lock,repo,vmm,workspace.ext4}, layers/<agent>/{images,current,previous,failed},
caches/*.{ext4,lock}, channel.{serial,day,next}, updates.log), the VMM socket directory under os.TempDir() (vsock,
vsock_5000, vsock_5001, vsock_5002, firecracker.json, attach), and the operator's cwd, TMPDIR, SSL_CERT_FILE and XDG
variables, which choose where that state lies and which tree the guest gets. The handling code is the supervisor and
the other verbs as the operator's uid: cmd/workcell/run_vm.go run, session, boot and client; session.go stop, rm,
running and supervisor; update.go apply, daily, fail, point and fetch; data.go holds and xdgDir; pull_vm.go fetch, put
and compare; internal/fileserve (the live export, which serves whatever lies under cwd); internal/audit (the record);
internal/proxy terminate.go upstreamRoots (the trust store); the Firecracker backend, which connects to
<dir>/vsock_<port> by path on the guest's behalf; and the guest init only for liveness. Windows examined: start-up
(loadPolicy, startup's apply and daily, findLayers, openCaches, then holds, newSession, Export, boot, the Exec frame),
shutdown (the LIFO defers: attach listener, terminal, VM kill and wait and RemoveAll, session_end, lock; the stop
ladder; rm), crash (SIGKILL of the supervisor with Pdeathsig on the locked forking thread, the VMM dying, torn seals,
lock files, half-written markers and .download-* files) and upgrade (apply's serial floor and expiry re-check, point's
marker order, fail's fresh gate, --to and --rollback).

Lenses (S9). Parsing and resources: no new parser on this surface; the S-F11 entry-cost variants were measured through
the real Server (a 255-byte-name MKDIR and a 4000-byte-target SYMLINK cost the host 1.10 times the charge in st.Blocks
and in free blocks, CREATE 0.10 times; RENAME reuses freed directory slots), so the cap holds within the row's slack;
audit.Create opens log and seal once and never reopens them, so descriptor pressure cannot reach a record. Logic and
state: holds() compares resolved paths one way only (held below dir), so a cwd below the data directory passes (C29);
boot()'s TMPDIR check is IsAbs only, so an absolute TMPDIR under a mounted directory passes (C28); upstreamRoots has
no IsAbs check and x509.SystemCertPool reads SSL_CERT_FILE against cwd first (C30); apply re-verifies channel.next
with the floor the daily check wrote (equal passes), expiry re-checked; point writes previous then current then clears
failed then removes the rest, and a crash between any two steps recovers at the next update by a re-fetch. Concurrency
and check-to-use: findLayers' Stat against a concurrent point is availability only (the image is open by the VMM or
refused before boot); rm during pull removes unlinked inodes the VM keeps; two first uses of audit.key race to an
empty file that fails closed; the stop ladder's pid-reuse window is not attacker-timed, except through C29, where the
guest writes the pid text itself. Cryptography and identity: the seal binds id and head (S-F17); the manifest
signature and digest make a repository-chosen [update] ca worthless (S-1011); the only trust-store input the
repository can reach is a relative SSL_CERT_FILE (C30). Failure modes: every boot failure runs closeAll; an export
failure removes the session directory and its start record, which no in-scope repository can trigger (git cannot check
out a name over 255 bytes, a 4096-byte link target, a mode-0 directory or a 32 GiB blob); session_end bypasses both
log limits and its error is printed (S-F16); the fail of a zero installer is gated by fresh (S-1002). Downgrade,
rollback and replay: --rollback reaches a withdrawn image by design (S-1018's residual); channel.next is removed
before use; the serial floor is per data directory. Interaction: the live export and the VMM socket directory (C28),
the live export and the data directory (C29), the repository tree and the trust store (C30), the guest-written tree
and the operator's terminal through two unquoted error paths (C31).

Refuted by the auditor before any candidate was raised. C26 with C19 and C21: S-F12 refuses every ancestor of the data
and config directories and S-F14 makes the directories absolute first, so no guest reaches audit.key, root.ext4,
vmlinux, firecracker or config.toml, and the A6 client gap through C19 is closed with it; the markers ".", ".." and
"/" name a directory, which Firecracker reads as EISDIR with no sector; a marker naming a symlink needs a writer of
layers/<agent>/, which only C29's cwd gives, so it stands inside C29. C21 with the relative TMPDIR: S-F14 refuses a
relative value before MkdirTemp (shown with the real binary: TMPDIR "tmp" is not an absolute path, exit 125); the
absolute form under a mounted directory is not refuted, it is C28. C23 with S-1005's pipelined host_mismatch rate and
EMFILE: after S-F16 a guest that fills the log loses its network (every later Allowed record is ErrFull and the
connection is drained and closed), audit.log and audit.seal are descriptors opened at Create and written in place, so
no later EMFILE can reach a record, and the one path that continues, a kept-alive terminated connection admitted
before the fill, records each secret use durably until HardLimit and then the broker withholds, so I9 holds. The
caches row: a NAME:rw image is guest-written ext4 the next guest of any repository mounts, which is the feature's own
contract (cacheLine says so), the host never parses it, the flock keeps one writer, and a read-only attach plus an
overlay keeps a ro session from writing it. The S-F19 pipelining variants: net/http parses every pipelined request
itself and the handler judges each, a refused TRACE, a 403 and a 502 leave the connection open as a 405 did in C27,
go1.27.4 closes it after any CONNECT, and a CONNECT body is read as that connection's body, so nothing crosses
unjudged. The S-1005 Upgrade tunnel and the S-1007 residuals (echoing bound hosts, re-encoded tokens, id_token):
provider traits of the trusted destination, by design. A reflinked prior workspace.ext4 in the repository is the
operator's own copy; a bind mount of the data directory into a repository needs host root (out of scope), and holds()
cannot see one, which stays residual. Start-up: apply and daily run before holds but write only under the absolute
data directory; a relative [update] ca resolves against cwd and yields nothing under the signature (S-1011); a SIGINT
during apply's download leaves one .download-* file, operator-triggered and bounded by MaxArtifact. Shutdown and
crash: the defers run attach listener, terminal, VM (Kill, wait for the reaped child, RemoveAll), session_end, lock in
that order; Kill can fail only for a process that is not our child; SIGKILL leaves the tmp directory for rm (recorded
in vmm before Start) and an unended log that verify refuses (S-F17); rm during pull and ls during rm are operator
races with no residue. The export-failure gap: no record was owed, since no guest ran and no connection was attempted.
The C14 relative (a malformed UDP-53 frame leaves no record): the frame's only author is the forger, as C14 held.
Pull's unbounded total time: Ctrl-C ends it and one VM at its caps is all it costs.

Coverage. Read in full: loop/SPEC.md, CLAUDE.md, loop/state/FINDINGS.md (S-1001 to S-1014 entire) and
loop/state/PARKED.md;
cmd/workcell/{run_vm,session,update,data,layer,cache,cache_vm,pull_vm,pull,log,policy,relay,caps,main,explain,bench_vm,backend_linux,mount_linux,term_vm,pull_linux,ocsf}.go
and the tests update_test, c19_test, verify_test and session_test;
cmd/workcell-init/{main,root,exec,pull,net,mount}.go; internal/vmm/vmm.go, firecracker/firecracker.go, vz/vz.go;
internal/audit/{audit,key,lines}.go; internal/proxy/{proxy,terminate,signin,allowlist}.go;
internal/resolver/resolver.go; internal/channel/channel.go; internal/relay/relay.go; internal/wire/wire.go;
internal/guest/{guest,walk,trust}.go; internal/workspace/workspace.go; internal/secret/{broker,source}.go;
internal/artifact/verify.go; internal/fileserve/{serve_linux,ops_linux,codec}.go, harness_linux_test.go and
c18_test.go; internal/rootfs/{ext4file,tree}.go; internal/policy/policy.go lines 1 to 330;
escape/suite/{lifecycle,rollback,update,layer,suite,tests,channel,channel_linux,audit,floods,helpers,files}.go;
escape/sandbox/{sandbox,workcell,workcell_vm,workcell_linux,control_linux}.go; docs/threat-model.md and
docs/policy.md; the pinned Firecracker v1.17.0 vsock muxer (fetched into the session's scratch directory, read as data
at Listen and the per-port connect); the git log of main from S-1001 to S-F13. Skimmed: internal/rootfs/ext4.go
constants (blockSize, maxImage). Not opened: cmd/bump, cmd/mkimage, internal/pins, internal/bump, internal/advisory,
internal/sigstore, internal/provider, internal/rootfs/{build,layer,oci}.go and the ext4 writer body, internal/policy's
lexer (lines 330 to 658),
cmd/workcell/{bench,run_other,backend_darwin,mount_darwin,term_linux,term_darwin,pull_darwin}.go, the remaining
*_test.go, the remaining escape/suite files (dns, dnstests, resolver, rebind, relay, repo, gitdir, secrets, signin,
https, terminate, smoke, device, packets, icmp, priv, addr, host_*), escape/sandbox control_channel, control_relay and
control_resolver, the workflows, _legacy/. Ran: go test ./cmd/... ./internal/... on the unchanged tree (all green);
seven overlay tests in packages main, fileserve, proxy, guest and workspace; the real binary six times in mount and
clone mode against a stand-in VMM in a short-lived directory; debugfs on a produced image; no VM (none exists here),
nothing left the session, every listener a unix socket of the probe's own (S12, T8). Ported files on this surface:
internal/proxy/terminate.go carries C30, so its record says also in v1 main: egressproxy/terminate.go; proxy.go,
allowlist.go, lines.go, broker.go and source.go hold nothing new. Nothing concerns someone else's project:
Firecracker's connect by path is its documented design and the kernel's connect(2) following a symlink is standard, so
no NEEDS-YOU. No model declined and no safeguard re-ran a request.

Evidence gaps and residual risk (for S-1018). C28's last step, a running Firecracker following the guest's symlink, is
shown with the kernel's connect(2) through fileserve and with the pinned muxer source, not with a VM. C29's mount-mode
variants (the lock pid, the vmm list, the repo file) are reasoned from session.go and fileserve's write path; the
clone-mode effect is measured. C31's test skips on a root runner. Unchanged gaps from earlier audits: no escape row
exercises workcell stop or rm on a running session (S-1002), none floods audit.log itself (S-1010; after S-F16 the
fill is a loss of network, proven by a Go test), the vz backend's reset path and the Mac in general are untested here,
and holds() cannot see a bind mount of the data directory into a repository (host root, out of scope). Residual by
design: a NAME:rw cache is a guest-to-guest channel across repositories the operator opted into; --rollback can reach
a withdrawn image; an operator kill during apply's download leaves one .download-* file; a relative [update] ca
resolves against cwd and changes nothing under the signature; before H-905 channel.Keys is empty, so a default
configuration installs from the compiled row. The toolchain pin still has no updater (S-F19).

### S-1013 candidates

C28. ID I1 (the guest cannot read or write any host path outside its export) and I4 (the guest cannot reach host-local services),
with I7 when the directory holds another session's sockets; A5's --mount is the mode. Attacker: guest root, driven by a malicious
repository or hostile model output. Precondition the attacker does not control: the operator runs a mount session in a directory
that holds os.TempDir(), as in `cd /tmp && workcell run --mount -- <cmd>` with TMPDIR unset, or with TMPDIR set to a path under
the repository, as a repository's .envrc does once the operator has allowed it (direnv). Where: cmd/workcell/run_vm.go boot (the
S-F14 check is filepath.IsAbs(os.TempDir()) alone, then MkdirTemp("", "wc") and Listen of vsock_5000, vsock_5001 and vsock_5002 in
it, then openMount(cwd), so the sockets lie inside the live export; the comment there says they must not land under a mountable
directory, so this is a gap, not a design); internal/fileserve/ops_linux.go opSymlink (Symlinkat with any target) and opUnlink
(any name under the export); internal/vmm/firecracker/firecracker.go Listen and the unjailed exec as the operator's uid; the
pinned Firecracker's vsock muxer, which connects to <uds_path>_<port> by path on each guest CONNECT (ADR-001 and
internal/vmm/vmm.go record it). Input: the operator runs `cd /tmp; workcell run --mount --allow api.example.com -- claude`. Guest
root: `p=$(find /workspace -name vsock_5001); rm "$p"; ln -s /var/run/docker.sock "$p"` (or any unix socket the operator's uid may
connect to: ssh-agent, gpg-agent, the session bus, another session's attach or vsock socket), then any connect() to an allowed
port, which the init relays to CID 2 port 5001, or a direct AF_VSOCK dial. The guest finds the directory because the whole of cwd
is its /workspace, and firecracker.json beside the sockets names the uds_path. Effect: Firecracker connects to <dir>/vsock_5001,
connect(2) follows the guest's symlink, and the guest's bytes reach the host socket as the operator's uid: docker.sock is root on
the host, ssh-agent and gpg-agent sign with the operator's keys. I1 and I4 broken; the relay listener lives for the whole session,
so every later CONNECT is redirected. Lesser variants: rm of vsock_5001 ends the guest's own network, rm of attach breaks workcell
attach. Evidence: the auditor ran the real binary in a mount session with TMPDIR equal to cwd and below it against a stand-in VMM
that listed its directory: both runs passed every refusal into boot and the stand-in listed <cwd>/tmp/wcNNN holding
firecracker.json and the three sockets with uds_path inside the export; an overlay test against the real fileserve Server answered
0 to UNLINK of a listening socket and SYMLINK of its name to a victim socket, after which a host dial of the export path reached
the victim; the muxer source of the pinned v1.17.0, fetched as data, builds the per-port path and connects by it. Reproducing
test: escape/_pending/S-F20/c28_test.go TestC28TempDirInMountExport (redteam; package main in cmd/workcell, arms cwd and cwd/tmp):
drives the real session() in mount mode with cwd as the export and TMPDIR equal to cwd and a subdirectory of it, with c19Data's
dummy artifacts, and wants an error naming os.TempDir(), no new session directory with a vmm boot record, and no wc* left under
TMPDIR. On d998add both arms fail in 0.02 s: `session failed with "start firecracker: invalid argument", want a refusal naming the
temp directory ... inside the export` and `the session reached boot: the VMM's sockets were made in .../wcNNN, inside the mount
export ... (I1, I4)`. Outcome: CONFIRMED, medium, by the verifier, who ran the test (both arms fail the same way), traced the
chain by code (Symlinkat with an arbitrary target and Unlinkat for any name under the export, sockets visible to the guest as row
21 of the adversarial fileserve table shows; Firecracker execs unjailed as the operator with uds_path <Dir>/vsock; the per-CONNECT
connect by path in ADR-001 and vmm.go), and found no escape mount row that places TMPDIR in the export, so nothing contradicts it;
the test takes only the operator's step and no attacker power; the precondition is operator-chosen, so medium under S6, not high;
not S14, because Firecracker's connect by path is its documented design and the defect is the socket placement here. Fix unit:
S-F20, below S-1013 in PLAN.md: boot() refuses an os.TempDir() that lies inside the mount export, comparing resolved paths as
holds() does, before MkdirTemp; clone mode needs nothing, since the export is taken before the sockets are made. Variants the
redteam could not express without a VM: the symlink-and-dial itself against vsock_5001, vsock_5000 and vsock_5002, TMPDIR that is
a symlink resolving under cwd, a trailing slash or .. components, the attach socket redirected to a guest-chosen socket, and
racing the unlink against the init's first CONNECT. Not ported.

C28 FIXED by S-F20, commit fa0dc82 (PR #237). session() in cmd/workcell/run_vm.go refuses a mount session when within(cwd,
os.TempDir()) holds, right after holds(cwd) and before newSession, so no session directory, socket or boot exists when the error
names the temp directory and run exits 125; within(dir, p) in data.go is the one resolved-path compare (filepath.Rel local, "." or
below), which holds() now calls and S-F21 can reuse. Clone, pull and bench are unchanged: their guests see no host directory where
the sockets lie, and the S-F14 IsAbs check in boot stays. Test: cmd/workcell/c28_test.go TestC28TempDirInMountExport, moved by git
mv with a third arm (TMPDIR a symlink resolving under cwd) and a negative arm (TMPDIR elsewhere, mount runs on into boot); the
three refusal arms fail on d998add and 36859b1 and pass at fa0dc82 under -race. Paid by two literal folds in data.go and ocsf.go,
product 15000 of 15000. Not ported.

C29. ID I7 (nothing a session writes is visible to another, and rm leaves nothing behind), with the operator's stop and rm verbs
turned against the host; I9 and I13 hold, because no cwd strictly inside the data or config directory contains audit.key or
config.toml. Attacker: guest root, by a malicious repository or hostile model output. Precondition the attacker does not control:
the operator's cwd, or the pull destination, lies strictly inside the data directory, as in `cd ~/.local/share/workcell/sessions
&& workcell run --mount -- <cmd>`, or layers/<agent>, caches or sessions/<id>. S-F12's holds() asks whether the held directory
lies below cwd and never whether cwd lies below it, so this is the half of C19 that S-F12 left open. Where: cmd/workcell/data.go
holds (filepath.Rel(resolved(dir), resolved(held)) one way); run_vm.go session and pull_vm.go fetch, its callers; session.go
supervisor (trusts the pid text in lock), removeSession (RemoveAll of every existing absolute wc* directory that vmm names),
stopSession (the SIGTERM, SIGTERM, SIGKILL ladder while running() is true) and newest (trusts repo); layer.go findLayers (trusts
layers/<agent>/current, no digest check). Input: clone: `cd <data>/sessions && workcell run -- true`. Mount: the same with
--mount, then guest root under /workspace reads any <id>/workspace.ext4 and <id>/audit.log, writes "<victim pid>\n" to its own
<id>/lock, appends another running session's /tmp/wcNNN to its own <id>/vmm, rewrites another session's repo or workspace.ext4, or
in a layers/<agent> cwd writes current and a new image. Effect: clone: the new guest's image carries every other session's image
and record (I7). Mount: all of that live, and afterwards `workcell stop <id>` signals the pid the guest wrote (the real
supervisor's flock keeps running() true, so the ladder reaches SIGKILL), `workcell rm <id>` removes the other session's socket
directory, a later `workcell pull` boots the guest's chosen image, and a layers cwd lets the guest choose the next session's
/opt/<agent>. Evidence: the auditor's overlay test showed holds(<data>/sessions), holds(<data>/layers/claude) and
holds(<data>/caches) returning nil, and session() with cwd <data>/sessions in clone mode ran to boot and left an image in which
debugfs listed the other session's audit.log, repo and workspace.ext4 and returned its marker bytes; the mount variants are read
from session.go and fileserve's write path. Reproducing test: escape/_pending/S-F21/c29_test.go
TestC29RefusesACwdInsideTheDataDirectory (redteam; package main in cmd/workcell; arms clone_in_sessions, mount_in_sessions,
mount_in_layers and pull_into_sessions): with XDG_DATA_HOME under a temp directory, c19Data's dummy artifacts and an earlier
session, the real session() with cwd <data>/sessions (clone and mount) and <data>/layers/agent (mount) must return an error naming
both cwd and the data directory, and pull into <data>/sessions from a repository elsewhere must exit 1 with one stderr line naming
both; then no new session directory and no vmm boot record. Naming cwd in the message matters, because the boot error already
names <data>/firecracker. On d998add all four arms fail in 0.04 s: `session failed with "start firecracker: invalid argument",
want a refusal naming .../workcell/sessions inside .../workcell`, `a session directory ... was made inside the directory the guest
gets (I7)`, and for pull `the session reached boot: .../workcell/sessions/<idOld>/vmm was written`. Outcome: CONFIRMED, medium, by
the verifier, who ran the test (all four arms fail the same way), showed the clone effect follows from Export copying everything
under cwd (the log proves Export of <data>/sessions succeeded, since boot was reached) and the mount effects from supervisor,
stopSession, removeSession, newest and findLayers trusting guest-writable bytes; the test takes only the operator's step; the
precondition is a cd into the product's private state, not attacker-controlled, so not high, and a break of I7 is shown by
mechanism, so not low: medium by S6's letter, as C19, though its precondition is far less ordinary than C19's `cd ~`. One
correction: the test's first draft reported audit.key as minted inside the directory the guest gets, a leftover of c19Untouched,
where for these cwds the key lies at <data>/audit.key above the export; the redteam reworded that judge before the file was
parked, and the candidate's own I9-holds statement stands. Fix unit: S-F21, below S-1013 in PLAN.md: holds() refuses both
directions, with one message saying the directory lies inside or holds the held one, which also refuses `workcell pull
<data>/sessions` through fetch. Variants the redteam could not express without a VM: the live stop, rm, repo, workspace.ext4 and
layers consequences above; cwd reaching <data> through a symlink that resolves inside sessions/; cwd <data>/caches; cwd strictly
inside the config directory (nothing there to reach, but the fix should mirror it). Not ported.

C29 FIXED by S-F21, commit 5d96419 (PR #238). holds(dir) in cmd/workcell/data.go refuses when within(dir, held) || within(held,
dir) for the data and the config directory, with one message naming both: `<dir> lies inside or holds workcell's own directory
<held>, which no session may see: use another directory`; session() in run_vm.go and fetch() in pull_vm.go call it as before, so run
(clone and mount) exits 125 and pull and diff exit 1 with one stderr line, before any session directory, key, export, socket or boot.
The second direction fits the existing if line and the new message replaces the old, so net 0 product lines, product 15000 of 15000,
no fold needed; docs/policy.md says holds, or lies inside. Test: cmd/workcell/c29_test.go TestC29RefusesACwdInsideTheDataDirectory,
moved by git mv with a fifth, negative arm (sibling <parent>/workcell2, not refused); the four refusal arms fail on f03f1ea (each
reaches firecracker, a session directory and audit.key are made, pull writes vmm) and pass at 5d96419 under -race. The reviewer probed
the data and config directories themselves, a not-yet-existing <data>/sessions/x/deeper, <config>/sub, symlinks to and through
<data>/sessions, relative ../workcell/sessions, and found each refused, with <parent>/workcell2, ../workcell2 and <parent>x not
refused. Not ported.

C30. ID I6 (on a terminated connection the upstream certificate matches one allowed name under the host's trust) and through it I5
(the real secret is injected only into a verified connection). PARKED line 77, the S-F14 reviewer's finding, now with a
reproducing test. Attacker: a malicious repository supplying ca.pem, a CA the attacker made whose leaf key it keeps, completed by
the network attacker as the host's DNS for an allowed name (the rebind position of the rebind-* rows) or on path. Precondition the
attacker does not control: the operator's environment holds a relative SSL_CERT_FILE, such as `SSL_CERT_FILE=ca.pem` or a literal
`~/ca.pem` left unexpanded by /etc/environment or environment.d, the same class as C21's relative XDG value. Where:
internal/proxy/terminate.go upstreamRoots (os.ReadFile(certFile) with no IsAbs check), called from Terminate with
os.Getenv("SSL_CERT_FILE") as it is; and x509.SystemCertPool there, whose Linux loader reads SSL_CERT_FILE against cwd too, before
the product does, so a check after the pool is built is too late. cmd/workcell/run_vm.go session takes the repository as cwd from
Getwd and boot builds the proxy in-process, and nothing in cmd/workcell touches SSL_CERT_FILE or changes directory, so the proxy
reads the file from the repository. Input: the repository holds ca.pem. The operator, with SSL_CERT_FILE=ca.pem in the
environment, runs `workcell run --allow api.anthropic.com -- <cmd>` with a [[secret]] row bound to that host. The network attacker
answers the host's lookup of api.anthropic.com with its own address and presents a leaf for api.anthropic.com signed by the
repository's CA. Effect: the terminating proxy's upstream transport verifies the attacker's leaf against a pool that holds the
repository's CA, forwards the request with the real secret swapped into the bound header, and the secret reaches the attacker: I6
and I5 broken for every terminated name of the session. Evidence: the auditor's overlay test in package proxy, with cwd a
directory holding a NewSessionCA certificate as ca.pem, saw upstreamRoots("ca.pem"), ("./ca.pem") and ("../<dir>/ca.pem") each
return a pool and a nil error, and a leaf that CA issued for example.com verified against each pool. Reproducing test:
escape/_pending/S-F22/c30_test.go TestRelativeSSLCertFileIsRefused (redteam; package proxy in internal/proxy, two arms in one
test): with cwd a temp directory holding a ca.pem the test made, upstreamRoots must return an error for "ca.pem", "./ca.pem" and
"../<dir>/ca.pem"; then end to end, with SSL_CERT_FILE=ca.pem through t.Setenv, a real Proxy from testProxy with the roots left to
Terminate, a loopback TLS upstream presenting a leaf for api.example.com issued by that CA and echoing X-Api-Key, a fake broker
holding "real-secret" and a client request carrying the placeholder, the response must be 400 or more and carry no "real-secret",
or Terminate must refuse. On d998add it fails in 0.01 s: the three spellings `read the repository's file against the working
directory without error; want a refusal`, and `through a relative SSL_CERT_FILE the attacker's upstream answered (200,
"real-secret"); want the secret withheld`. Outcome: CONFIRMED, medium, by the verifier, who ran the test (the same four lines; the
package is green with this one test skipped), checked the fixture against the real path (boot builds the proxy in-process and bind
calls Terminate; session's cwd is the repository; Terminate passes the environment value straight to upstreamRoots; Go 1.27.4's
loadOnDiskRoots also reads the file against cwd), found that the test gives itself only the repository's ca.pem, the shared lookup
and dial seams that stand for the MITM I6 exists to defeat, and the environment precondition, and held medium under S6 as C21 was:
a demonstrated break with one uncontrolled precondition, where low would mean no demonstrated break. Fix unit: S-F22, below S-1013
in PLAN.md: upstreamRoots refuses, not ignores, a relative certFile with one error naming SSL_CERT_FILE before x509.SystemCertPool
runs, so termination fails closed as it does for an unreadable file. Variants the redteam could not express: a relative
SSL_CERT_DIR (Go's own loader reads it against cwd too; the product never reads it, and the process-wide pool cache makes a unit
test order-dependent), a relative SSL_CERT_FILE that is a symlink or a directory in the repository, a bundle with a hostile CA
appended after a legitimate operator one, a CLI-level arm, and the macOS platform verifier, where only the product's own read
matters. Ported: also in v1 main: egressproxy/terminate.go.

C30 FIXED by S-F22, commit 9577f31 (PR #239). upstreamRoots in internal/proxy/terminate.go refuses a non-empty certFile that does not
start with / before x509.SystemCertPool runs, with one error `SSL_CERT_FILE "<value>" is relative: set an absolute path`, so Terminate
returns it before p.ca or p.transport are set, bind in cmd/workcell/run_vm.go returns it through fail(0, err) before any VM boots, and
run prints it as one line; an absolute file or an unset variable behaves as before. HasPrefix("/") equals filepath.IsAbs on Linux and
macOS, the only hosts, and saves the import; the four-line doc comment folded to one, so net 0 product lines, product 15000 of 15000.
Test: internal/proxy/c30_test.go TestRelativeSSLCertFileIsRefused, moved by git mv unchanged; its four arms fail on 5e4fec8 (the
three spellings return a pool and nil, and the attacker's upstream answered 200 with "real-secret") and pass at 9577f31 under -race
with the rest of internal/proxy, including the absolute-file and missing-file cases of terminate_test.go. The reviewer confirmed the
failure in a worktree at 5e4fec8 and considered "~/ca.pem", "//x", "/./x", NUL, a directory and a symlink (refused, absolute,
absolute, read error, read error, the operator's own). Also in v1 main: egressproxy/terminate.go.

C31. ID none directly: I12's "confuse the host" in spirit and the product's own rule, set by C20 and S-F13, that a guest-chosen
name is quoted before it reaches the operator's terminal; hardening, as C20. Attacker: guest root in a mount session, since
fileserve honours Mkdirat's mode (codec.go takes Mode and Name from the guest, checkName refuses only "", ".", "..", "/" and NUL,
and ops_linux.go opMkdir applies Mode&0o777, so a mode-0 directory owned by the operator with ESC and BEL bytes in its name is
left in the operator's tree); hostile model output naming the directory. A malicious repository alone cannot carry the trigger:
git stores no directory mode and pull creates directories 0o755, so a cloned tree carries the hostile name but not the open
failure that prints it. Where: internal/guest/walk.go lines 31, 44, 50 and 57 (`%s` with the raw entry name; compare in
cmd/workcell/pull_vm.go returns it unwrapped and diff prints it with Fprintln) and internal/workspace/workspace.go lines 91, 109,
119, 131 and 152 (`%s` with the raw host path; run prints `copy <cwd> for the guest: ...` with it); only shown in pull.go and the
guest-side Walk error in pull_vm.go quote. Input: in a mount session the guest runs `mkdir -m 0 "/workspace/$(printf
'\033]0;owned\a\033[2J\033[31mREADME')"`; later the operator, not root, runs a clone-mode `workcell run` in that tree, or
`workcell diff` where the newest session is a clone one and the mount session ran in a subdirectory. Effect: run prints `copy
<cwd> for the guest: open <cwd>/\x1b]0;owned\a\x1b[2J\x1b[31mREADME: permission denied` and diff prints `open \x1b]0;owned...:
permission denied` raw: the terminal's title is set, the screen cleared and recoloured, OSC 52 where the terminal allows it. No
crash, hang or confusion of the process itself. Evidence: the auditor's overlay tests in packages guest and workspace, run with
CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH dropped from the bounding set so the mode-0 directory refuses as it does for an operator,
failed with a raw 0x1b at offset 5 (Walk) and 58 (Export). Reproducing tests: escape/_pending/S-F23/guest_c31_test.go
TestC31WalkErrorQuotesName (for internal/guest) and workspace_c31_test.go TestC31ExportErrorQuotesPath (for internal/workspace)
(redteam): each makes a mode-0 directory named "\x1b]0;owned\x07\x1b[2J\x1b[31mREADME" under a temp root, calls Walk on the root's
descriptor or Export to a fresh image, skips with a reason if the open succeeds (a root runner), and otherwise fails if the error
carries any byte below 0x20 or 0x7f. On d998add, under `setpriv --bounding-set -dac_override,-dac_read_search go test`, both fail:
`the error carries a raw control byte the terminal would obey: "open \x1b]0;owned\a\x1b[2J\x1b[31mREADME: permission denied"` and
the same with the host path; as plain root both skip; the hosted gate runs as a normal user, so there they fail without any trick
(the redteam also ran the compiled test binaries as uid 65534 with the same two failures). Outcome: CONFIRMED, low, by the
verifier, who ran both tests both ways, traced walk.go's error through compare and fetch to diff's Fprintln and workspace.go's
through run_vm.go's copy error to run's Fprintln with nothing quoting on the way, confirmed the mount guest's mode-0 directory
from codec.go and ops_linux.go, refuted the repository arm on its own (no directory mode in git, 0o755 on pull), and held low
under S6: no invariant breaks, the effect is control of the operator's screen, not of the host process; FINDINGS.md's S-1008
handoff already parked the walk.go site as the C20 class. Fix unit: S-F23, below S-1013 in PLAN.md: `%s` to `%q` at the four
walk.go sites and the five workspace.go sites, net 0 product lines. Variants the redteam could not express: the other sites in the
same functions (an unlistable but readable directory, a readlink failure, tree.Put's rejection) and the end-to-end run and diff
prints, which need a VM. Not ported.

C31 FIXED by S-F23, commit 9170094 (PR #240). `%s` became `%q` at the nine sites the record names:
internal/guest/walk.go lines 31, 44, 50 and 57 and internal/workspace/workspace.go lines 91, 109, 119, 131 and 152,
so Walk's and Export's errors now carry the guest-chosen name or the host path quoted once, as `open
"\x1b]0;owned\a\x1b[2J\x1b[31mREADME": permission denied`. Line 42 of workspace.go (the operator's own cwd) is unchanged, as the
record asks. Nine in-place edits, net 0 product lines: product 15000 of 15000 before and after, test 28085 of 28500 with the two
tests now under internal/. Inner errors at the nine sites: Fstatat, Openat and Readlinkat return a bare unix.Errno and tree.Put
returns ErrPath, ErrNotDir or ErrBadNode with the path already %q-quoted, so no path is printed a second time raw. Residual, not
reachable by the finding's attacker: the two `read %q` sites wrap the *os.PathError that Readdirnames returns on a readdirent
failure, whose Path is the raw rel passed to os.NewFile; an unreadable directory fails at Openat, not at readdirent, so a mode trick
cannot reach it, and only an I/O error on an already-open directory would. Tests: internal/guest/c31_test.go
TestC31WalkErrorQuotesName and internal/workspace/c31_test.go TestC31ExportErrorQuotesPath, moved from escape/_pending/S-F23/ by
the redteam unchanged; both fail on d998add and pass after the fix under `setpriv --bounding-set -dac_override,-dac_read_search go
test -run TestC31 -count=1 ./internal/guest/ ./internal/workspace/`, skip as plain root, and the two packages pass under -race.

Handoffs: four fix units, S-F20 to S-F23, below S-1013 in PLAN.md, each starting with the move of its parked test. The sweep count
question is S-1017's: this sweep confirmed C28, C29 and C30 at medium, so by S8 a second sweep follows once the fixes land. For
S-1018's report: the two medium findings in cmd/workcell (C28, C29) are each the other half of a check an earlier fix drew one way
(S-F14's TMPDIR rule and S-F12's holds), which argues for the report to name "a compare drawn in one direction" as the class, with
C19, C21, C28, C29 and C30 its members. The redteam variants that need a VM (the symlink-and-dial itself, the live stop and rm
consequences, the end-to-end raw prints) are the first escape rows to add if test lines are freed after the freeze. Product is at
15000 of 15000 and test at about 28050 of 28500 with the four parked files, which already count under escape/, so the moves cost
nothing and every product line of the fixes must be paid by a fold.
