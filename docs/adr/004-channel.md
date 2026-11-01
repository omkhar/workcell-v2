# ADR-004: channel manifest format and signing

status: proposed

## Context

I14 lets the client install an upstream artifact only from a signed, unexpired channel manifest whose serial never goes
down, and B7 publishes that manifest after every merge that changes `pins/`. This repository holds no key (section 10),
so the scheme runs here with a key a job makes and discards, and is finished at H-829 (the key) and H-905 (its public
half). The B-820 spike built each scheme below as a throwaway module with the product's flags; "linked" counts its modules.

## Options

| | A: ed25519, stdlib (the spike) | B: keyless, Fulcio and GitHub OIDC | C: TUF, go-tuf v2.4.2 | D: minisign v0.3.0 |
|---|---|---|---|---|
| Direct modules added (linked) | 0 (0) | 1 (67, sigstore-go v1.4.0), or 0 with a 132-line partial verifier | 1 (12) | 1 (3) |
| Throwaway binary; verify p50 | 1.9 MB; 138 us on a 9.8 kB envelope | 18.5 MB; 260 us, partial 331 us, both on a synthetic bundle (the real one was not fetchable here) | 10.5 MB; not measured | 2.0 MB; not measured |
| Client lines | 262 measured: verifier 150, daily check 112 | about 40 plus root refresh; the partial verifier has no proof of signing time, so any leaf Fulcio ever issued for the identity verifies forever | about 40 plus payload checks | about 15 plus payload checks |
| Trust root, rotation | our key table in the binary; overlap by two signatures in one envelope | Sigstore's trusted root, rotated a few times a year: refresh over TUF from one more host, or ship a root that goes stale | role keys, rotated in band | as A, but overlap needs a second file |
| Section 10 dry run here | complete: the job makes a key, signs, verifies with the client's code | partial: a real leaf needs `id-token: write` and writes a public Rekor entry; a job cannot make and discard an identity | complete | complete |
| Client GETs per check | 1 | 1 plus the TUF refresh | 4 or more, across cache generations | 2: file and `.minisig` |

## Decision

- Option A. Format: one file, `channel.json`, a DSSE envelope (`payloadType` `application/vnd.workcell.channel+json`,
  base64 `payload`, `signatures` of `keyid` and `sig`) signed over the PAE, so payload and signature share one cache
  generation. Payload: `serial` (publication time, unix seconds), `expires` (serial plus 14 days, B7), `pins` and
  `previous` (name, then arch: `version`, `url`, `sha256`, `released` for B10's `cooloff`), `withdrawn` (digests). Checks,
  in order: size at most 64 KiB, strict envelope, one valid signature by a key whose `NotAfter` is after now, serial no
  lower than the last seen (equal passes) and at most 24 h ahead, `expires` at most serial plus 14 days, not expired,
  digests 64 lowercase hex, URLs `https://`. Unknown payload fields are ignored, so a field costs no release; a change old
  clients must not misread gets a new `payloadType`, which they refuse. Keys, clock and last serial are parameters (A11).
- Key: ed25519. The public half, with `NotAfter` two years from creation, is one entry in the key table in
  `internal/channel`, added at H-905; the private half exists only as an environment secret of `bump` in `omkhar/workcell`
  (H-829). The key ID is the hex SHA-256 of the public half, derived on both sides, so nothing about the key is written
  twice (W6). A client learns a key as it learns everything else: from a signed release (W10).
- Publication: the publish job of `bump.yml`, holding `contents: write` and nothing else (W11), commits `channel.json` to
  an orphan branch `channel` of `omkhar/workcell`; GitHub Pages serves it at `https://omkhar.github.io/workcell/channel.json`
  (cache 600 s; the soft 100 GB a month covers about 300,000 daily clients). It publishes after every merge that changes
  `pins/` and once per daily scheduled run, so the live manifest is never a day old and a quiet fortnight cannot expire it.
  Rejected: a rolling-tag asset (H-807 makes releases immutable), `actions/deploy-pages` (`id-token: write` in the publish
  job breaks W11), raw.githubusercontent.com (unauthenticated limits lowered in May 2025 with no published figure, so one
  shared egress address may be throttled), ghcr.io (60 to 80 lines and a token exchange).
- Client: one GET a day on the host, in a goroutine started after the day's stamp is written, capped at 64 KiB and never
  awaited (start 0.09 ms, 0.23 ms with a hung server; 0 requests on a second start the same day). A verified manifest is
  applied at the next start. `channel = "hold"` skips the check and applies nothing; a hand-run `workcell update` fetches once.
- Rollback: pins never move backwards (B3). `pins/` keeps each row's prior version, which the job emits as `previous`; the
  maintainer withdraws a bad digest in `pins/`, and the next manifest makes every client select `previous`, still under I14.
  B9 self-rollback and B10 `--rollback` swap to the artifact kept on disk, installed under an earlier valid manifest; they
  never read the stored manifest, so its expiry cannot block them. A digest that failed to run is marked locally and not
  retried until its pin changes. `--to <version>` installs only a version in the current manifest's `pins` or `previous`.
  One that does not verify is ignored, one whose artifact fails its digest installs nothing, and none is undone, only superseded.
- Freeze: expiry gates installs, not sessions. With an expired manifest and no successor the client keeps running what it
  has and `--rollback` still works, but a fresh install gets no provider CLI until the channel is live again. So a freeze
  is a deliberate act, stopping the schedule or deleting the secret, and reaches every client within 15 days.
- Rotation: at least 90 days before `NotAfter` a new key is made the same way, a release adds it to the table, and the job
  signs with both (tested: two signatures, only the second key trusted) until the old `NotAfter`, when its secret is
  deleted. A client older than a key's `NotAfter` refuses newer manifests and keeps what it has: two years is the forced
  upgrade horizon. A leaked key alone publishes nothing; an attacker also needs to write the `channel` branch or break TLS
  to github.io. With both, any guest content reaches clients not yet updated past the release that drops the key; section
  3 still holds (A10). Such a manifest may set a serial 24 h ahead and lives at most 15 days, so the honest channel is
  blocked for at most a day after the response release.
- Dry run: here `bump.yml` builds `channel.json` from `pins/`, makes a throwaway key, signs, verifies with the client's own
  `Verify` (good, tampered, expired, serial lower, two signatures) and publishes nothing; the escape I14 test does the same
  against a server it starts (T8). Only H-829 and H-905 exercise the real secret in `bump`, the public half in the key
  table, the Pages site, a released client fetching from github.io, a merge by the App token starting the publish run, and P7.

## Consequences

- Budget: 0 direct modules (still 2 of 15), no new linked module; about 260 lines in `internal/channel`, 40 in `cmd/bump`.
- `pins/` grows a prior version and a `withdrawn` list per row (B-821); each pin in the manifest carries `released`.
- H-807 enables Pages from the `channel` branch, which gains one commit a day, under 4 MB a year.
- A host clock off by more than a day installs nothing; every client needs a release within two years to keep receiving pins.

## Reversal cost

One package behind the same `Verify` signature and one release: clients learn a new scheme as they learn a new key, and pins
stay in `pins/`, so no data moves. The publication place is one URL constant and one release, both served during the overlap.
