# B-820 spike: channel manifest format and signing

Input for ADR-004 (channel manifest format and signing). Facts and numbers only, no recommendation.
"Local" numbers come from the authoring session (linux/amd64, 4 vCPU, go 1.27.0), run 2026-11-01.
Every number is printed as a `channel <key>=<value>` line by `go test -count=1 -v ./spikes/channel/`.

CI numbers: ORCHESTRATOR FILLS IN: commit `<sha>`, run `<id>`, runner `<image>`, linux and macOS lines.

## What the tests do (pure Go, no network beyond servers the test starts, about 1 s)

- `manifest.go` (150 lines incl. comments): DSSE-shaped envelope `{payloadType, payload (b64), signatures:[{keyid, sig}]}`
  signed over PAE (`DSSEv1 <len> <type> <len> <body>`), so payload and signature are one file and cannot come from
  two CDN cache generations. Payload: `serial` (publication unix seconds), `expires` (RFC 3339), `pins` and `previous`
  (name, then arch, to `version, url, sha256`), `withdrawn` (digests). `Verify(env, keys, now, lastSerial)` with
  `Key{ID, Public, NotAfter}`: keys, clock and state are parameters (A11). Order: size cap, strict JSON (unknown fields
  refused), one valid signature by a key whose `NotAfter` is after `now`, then serial no lower than last seen (equal
  accepted), serial at most 24 h ahead of `now`, `expires` at most serial + 14 days, not expired, every pin a 64-hex
  lowercase sha256 and an `https://` URL. `Select` returns the current pin unless withdrawn, else `previous`.
- `TestVerify`, one row each: good; unknown key; tampered payload byte; expired; expiry beyond serial + 14 days (added:
  without it a single signed manifest can live forever); serial lower (refused); serial equal (accepted); serial over
  24 h ahead (refused); digest absent (refused); two signatures, only the second key trusted (accepted, rotation
  overlap); key past `NotAfter` (refused); installed digest withdrawn with `previous` present (selects `previous`);
  empty; garbage.
- `TestSizeAndSpeed`: 8 providers x 2 arches with `previous`; p50 of 1000 sign and of 1000 verify.
- `FuzzVerify`: seeds are a good envelope, empty, `{}` and an unsigned envelope. CI runs seeds only.
- `check.go` + `TestStart` (B9): `Checker.Start(now)` re-verifies the stored manifest (returns nil if it no longer
  verifies, so the caller keeps what is installed), and if the last check is 24 h old or more, writes the stamp first,
  then fetches in a goroutine (bounded read, `max_manifest_bytes`), verifies, stores manifest then serial, and returns
  at once. The new manifest is applied at the next start. Servers (`httptest`): hung, valid, garbage, oversize; plus a
  stored expired manifest.
- `keyless.go` (132 lines, `wc -l`) + `TestTrustedRoot`, `TestKeyless`: stdlib Sigstore bundle check (v0.3
  `certificate` only): leaf chains to a Fulcio CA from `trusted_root.json` whose `validFor` holds the leaf's NotBefore,
  verified at NotBefore with code-signing EKU; `messageDigest` equals the pinned digest; `ecdsa.VerifyASN1`; SAN URI
  equals the identity; issuer extension 1.3.6.1.4.1.57264.1.8 (DER UTF8String) equals the issuer.

## Fixtures

| File | Source | Bytes | SHA-256 |
|------|--------|-------|---------|
| `testdata/trusted-root.json` | `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`, fetched 2026-11-01 | 6787 | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |

- The codex `.sigstore` bundle was NOT fetched: the session's proxy refused `github.com/openai/codex/...` (HTTP 403,
  "GitHub access to this repository is not enabled for this session"); `gh api` was refused the same way. Not
  retried by another route. URL pattern (from `_legacy/bump/verify-upstream-codex-release.sh`):
  `https://github.com/openai/codex/releases/download/rust-v<V>/codex-<arch>-unknown-linux-musl.sigstore`, identity
  `https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v<V>`, issuer
  `https://token.actions.githubusercontent.com`. So `TestKeyless` builds a Fulcio-shaped chain (root, intermediate,
  10-minute leaf) and bundle itself, rows: good, other identity, other issuer, digest not the pinned one, signature
  over another digest, CA not yet valid at signing, unknown CA, garbage. The real Fulcio CAs are only parsed and
  chained (intermediate to root, code-signing EKU), not used to verify a real leaf.
- `tuf-repo-cdn.sigstore.dev` was refused by the proxy (CONNECT 403); the GitHub copy of `targets/` was used.

## Numbers (local)

| Key | Value |
|-----|-------|
| `manifest_bytes` / `envelope_bytes` (8 x 2 with previous) | 7212 / 9815 |
| `max_manifest_bytes` | 65536 |
| `sign_us` / `verify_us` p50 of 1000 (verify includes JSON decode of 9.8 kB) | 72 / 138 |
| `start_hung_ms` / `start_ok_ms` / `start_garbage_ms` / `start_oversize_ms` | 0.23 / 0.09 / 0.08 / 0.06 |
| `check_ok_ms` (fetch + verify + 2 file writes) | 2.25 |
| `check_hung_ms` (= the 300 ms timeout the test sets) | 301.6 |
| `check_requests_second_call_same_day` | 0 |
| `expired_keeps_installed` (installs nothing, rolls back nothing, no error) | true |
| `keyless_verify_us` p50 of 200 (synthetic bundle, 1009 B) | 331 |
| `keyless_lines` | 132 |
| `trusted_root_bytes` | 6787 |
| `fuzz_crashers` (`-fuzz=FuzzVerify -fuzztime=30s`) | 0 (7,499 execs with default minimisation, which stalls the counter; 843,301 execs with `-fuzzminimizetime=0`, 0 crashers) |
| whole package `go test` | about 1.0 s |

Trusted root contents (`channel fulcio|tsa|log` lines): Fulcio 2 CAs (`2021-03-07..2022-12-31`, 1 cert;
`2022-04-13..open`, 2 certs), Rekor 2 keys (`rekor.sigstore.dev` ECDSA P-256 `2021-01-12..open`;
`log2025-1.rekor.sigstore.dev` Ed25519 `2025-09-23..open`, the Rekor v2 log), CTFE 2 keys (`/test`
`2021-03-14..2022-10-31`; `/2022` `2022-10-20..open`), TSA 1 (`timestamp.sigstore.dev`, 2 certs, `2025-07-04..open`).

`keyless_missing`: SCT check against CTFE keys, Rekor v1 SET and inclusion proof, Rekor v2 tile checkpoints,
TUF refresh of `trusted_root.json`, RFC 3161 timestamp. Without a log entry or timestamp the verifier cannot
know when the leaf signed, so any leaf Fulcio ever issued for the identity verifies forever.

## Outside the repository (throwaway modules in the scratchpad, never committed)

linux/amd64, go 1.27.0, `CGO_ENABLED=0`, `-trimpath -ldflags='-s -w'`, cold build = fresh `GOCACHE` (modules
pre-downloaded), each module in its own directory. "Linked" = modules in `go list -deps` of the binary.

| Option | `go list -m all` | `go.sum` lines | require lines added to go.mod | direct (gate count) | linked modules | binary bytes | cold build s | licences of linked modules |
|--------|---|---|---|---|---|---|---|---|
| (a) stdlib ed25519 | 1 | 0 | 0 | 0 | 0 | 1,900,704 | 5.6 | BSD (Go) |
| (b) sigstore-go v1.4.0 | 377 | 754 | 67 | 1 | 67 | 18,526,368 | 23.4 | 48 Apache-2.0, 12 BSD, 7 MIT |
| (c) go-tuf/v2 v2.4.2 client (build only) | 83 | 164 | 12 | 1 | 12 | 10,502,304 | 12.9 | 6 Apache-2.0, 4 BSD, 2 MIT |
| (d) aead.dev/minisign v0.3.0 | 7 | 12 | 3 | 1 | 3 | 1,999,008 | 5.3 | 2 BSD, 1 MIT |

- (b) offline verification passed: `root.NewTrustedRootFromPath` + `bundle.LoadJSONFromPath` +
  `verify.NewVerifier(tr, verify.WithCurrentTime())`, policy `WithArtifactDigest` + `WithCertificateIdentity`, on a
  synthetic bundle and trusted root (the real bundle was refused, see above). First call 0.99 ms including root and
  bundle load; verify mean of 200 = 0.26 ms. `WithCurrentTime` is the only way to accept a bundle with no log entry
  or timestamp; sigstore-go's own comment says not to use it for short-lived certificates. sigstore-go go.mod: `go
  1.27.0`, 20 direct + 59 indirect requires, Apache-2.0, published 2026-10-29.
- (c) go-tuf v2.4.2 (2026-05-19, Apache-2.0, `go 1.25.0`) links sigstore/sigstore, go-containerregistry,
  go-securesystemslib, protobuf.
- (d) minisign v0.3.0 (2024-05-19, MIT, `go 1.21`) links x/crypto v0.13.0 and x/sys v0.12.0 (our x/sys v0.49.0 wins).
- The gate counts direct modules only: each library option is +1 (budget 15, now 2). The `// indirect` lines still
  land in our go.mod and go.sum.

## Publication places (no code)

| Place | Publish job permission | Cache TTL | Hosts the client's GET touches | Unauthenticated limit | Client code |
|-------|------------------------|-----------|--------------------------------|-----------------------|-------------|
| Release asset on a rolling tag (`/releases/download/<tag>/<file>`) | `contents: write` | not measured (proxy refused `github.com`) | `github.com` then `release-assets.githubusercontent.com` | none published for downloads | one GET, follow redirect (as `check.go`) |
| GitHub Pages, branch build | `contents: write` (push to the branch; GitHub's own build deploys) | `max-age=600` (web) | `<owner>.github.io` | none published; 100 GB/month soft bandwidth | one GET |
| GitHub Pages, `actions/deploy-pages` | `pages: write` + `id-token: write` in the deploying job (W11: only the signing job may hold `id-token`) | `max-age=600` (web) | `<owner>.github.io` | as above | one GET |
| Raw file on a branch | `contents: write` | `max-age=300` (measured: `cache-control: max-age=300`, varnish `x-cache: HIT`) | `raw.githubusercontent.com` | none published (author's knowledge: GitHub tightened unauthenticated limits in 2025, unverified) | one GET |
| OCI artifact on ghcr.io (mutable tag) | `packages: write` | manifest by tag: registry-defined; blob content-addressed | `ghcr.io` (token, manifest), then the blob redirect host | none published for anonymous pulls | anonymous token GET, manifest GET with `Accept`, blob GET + digest check: about 60 to 80 lines |

Hand checks, one `curl -sI` per host: `raw.githubusercontent.com` answered (above); `ghcr.io/v2/` answered HTTP 405 to
HEAD; `*.github.io` refused by the proxy (403); `github.com` refused by the proxy for `openai/codex`. Web facts are
from the architect's check of 2026-11-01 and GitHub's docs.

## Per option

| | A: embedded ed25519 keys (this spike) | B: keyless (Fulcio + GitHub OIDC) | C: TUF (go-tuf v2) | D: minisign |
|---|---|---|---|---|
| Client lines | `manifest.go` + `check.go` = 262 | stdlib partial 132 (no log, no SCT, no refresh); with sigstore-go about 40 (the throwaway main is 45) | about 40 with go-tuf, plus our payload checks | about 15 plus our payload checks |
| Modules added | 0 | +1 direct, 67 linked | +1 direct, 12 linked | +1 direct, 3 linked |
| What rotates | our key, by a binary release that embeds the next key; overlap by two signatures in one envelope | Fulcio, CTFE, Rekor, TSA keys (Sigstore: a few times a year) through `trusted_root.json`; our identity string only if the workflow path or ref changes | root, targets, snapshot, timestamp roles; client walks signed root versions itself | our key, as A; one signature per `.minisig`, so overlap needs a second file and GET |
| How a client learns it | new binary | TUF refresh from `tuf-repo-cdn.sigstore.dev` (another host to allow) or a new binary with a new embedded root; a stale embedded root fails once Sigstore rotates | in-band, from the TUF repository | new binary |
| Leaked key or identity costs | signs any manifest until the key's `NotAfter` or a binary drops it; a serial up to 24 h ahead freezes legitimate manifests for up to 24 h; one manifest lives at most 15 days | anyone who can run that workflow at that ref can sign; visible in public Rekor only if the client checks it; minimal verifier accepts any old leaf (no time proof) | bounded per role; threshold and root rotation can revoke without a binary | as A |
| Section 10 dry run | full: job makes a key, signs, verifies with the same `Verify` | chain and signature only against a CA the job makes (as `TestKeyless`); a real Fulcio leaf needs `id-token: write` and writes a public Rekor entry | full: job makes all role keys | full |
| Files the client GETs | 1 | 1 (bundle can hold a DSSE envelope) plus TUF refresh | timestamp, snapshot, targets, target, root versions: several, across cache generations | 2 (file and `.minisig`) |

Other facts: strict decoding (unknown fields refused) means a new payload field needs a new `payloadType`. An expired
stored manifest also blocks B9 self-rollback to `previous`, because `previous` is read from that manifest. Sigstore
public-good serves public repositories; online signing of its TUF metadata at least every 3 days; Rekor v2 is GA with
v1 in parallel and no published SLO (architect, web, 2026-11-01).
