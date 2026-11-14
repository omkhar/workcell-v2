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

S-1004: needs the maintainer, see the run's transcript
