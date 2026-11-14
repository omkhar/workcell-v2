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
| 11 | TLS ClientHello on 443 | proxy.go:263 peekSNI (crypto/tls, 128 KiB, 10 s); :199 case and ECH check | G | crypto/tls ClientHello parser | SUP | I2 I6 I12 | yes | S-1004 | FuzzPeekSNI | sni-host-mismatch-h1, sni-authority-mismatch-h2, ech-hidden-sni, rebind-*-sni |
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
