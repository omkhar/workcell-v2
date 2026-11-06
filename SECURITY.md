# Security Policy

<!-- The maintainer removes this paragraph with the first v2 release. -->
This repository is Workcell v2 under construction: a building site that publishes no release, tag or
download. Nothing here is meant to be installed or relied on yet. If a release appears here, do not use
it, and report it. `loop/REFERENCE.md` section 9 explains what protects this repository and what does
not. The rest of this policy describes v2 as it will be released from <https://github.com/omkhar/workcell>.

## Supported versions

Workcell has a single maintainer, who applies security fixes to `main`. There are no long-lived release
branches and no backports. Only the latest release gets security fixes, and a fix ships in the next
release. Install the latest verified release to get it.

| Version | Security fixes |
| --- | --- |
| Latest v2 release | Yes |
| Any earlier release or pre-release | No. Install the latest release. |

Until v2.0.0 there is no supported version of v2. v1 is covered by v1's own policy, at
<https://github.com/omkhar/workcell/blob/main/SECURITY.md>.

## Reporting

Do not disclose a sandbox escape, a credential leak, a signing bypass or an update bypass in a public
issue. Use [GitHub private vulnerability reporting][pvr] on `omkhar/workcell`, whether the report
concerns the released product or the code in this repository. If that channel is unavailable, contact
the repository owner privately through GitHub first.

[pvr]: https://github.com/omkhar/workcell/security/advisories/new

## Response

The maintainer plans to acknowledge a report within 5 business days and to give an initial assessment
within 10 business days. Sandbox escapes and secret exposure come first. The reporter is credited in the
advisory unless they ask otherwise.

## Scope

A security report is a way for an attacker Workcell defends against to break one of its invariants.
[`docs/threat-model.md`](docs/threat-model.md) lists both, names the test that proves each invariant,
and says which invariants the test suite enforces today. In short: the attacker is root inside the
guest, a malicious repository, hostile model or tool output, or a network attacker off the allowlist.
The invariants cover host files, egress, DNS, private addresses, credentials, TLS termination, session
isolation, safe pull, audit, resource caps, failing closed, the host-guest channel, policy that only
narrows, and signed updates.

Also in scope: a regression in release signing or provenance, and any way to make the client install a
provider artifact that the channel manifest does not name. Both are described below.

Out of scope, and parked rather than fixed:

- Host root, and malware already running as the operator's own user.
- Hypervisor or CPU zero-days. The only mitigation is a minimal device model.
- Compromise of an allowlisted provider's own service.
- What a human later does with code they pulled out of a session.

## Verifying a release

Releases are published at <https://github.com/omkhar/workcell/releases>. Each one carries `SHA256SUMS`
over every asset, one keyless cosign signature over `SHA256SUMS` as the bundle
`SHA256SUMS.sigstore.json`, and one build-provenance attestation whose subjects are the same checksums.
There is no long-lived release signing key.

The installer, `scripts/install.sh`, downloads `SHA256SUMS` and the binary for the host, checks the
binary against `SHA256SUMS`, and installs nothing if any step fails. That catches a damaged or swapped
download. To check that the release workflow produced `SHA256SUMS`, download it and
`SHA256SUMS.sigstore.json` from the release and run:

```
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/omkhar/workcell/.github/workflows/release.yml@refs/tags/<tag> \
  SHA256SUMS
gh attestation verify <downloaded binary> --repo omkhar/workcell
```

Both commands are untested until v2.0.0, because nothing is released yet.

## The update channel

Provider CLIs, the agents that run inside the guest, are not part of a release. The client installs
them on the host from upstream, by a URL and SHA-256 digest pinned in `pins/`, and the project does not
redistribute them. [`docs/providers.md`](docs/providers.md) describes `workcell update` as it works
today, from the pinned URL and digest alone.

Released clients will learn new pins through a signed channel manifest, `channel.json`: a DSSE envelope
signed with ed25519 over a payload with a serial that never goes down and an expiry 14 days after the
serial. The client will verify it against a key table built into the binary, so a client learns a new
key the way it learns everything else, from a verified release. It will install an artifact only if the
manifest names its digest, and only from a manifest with a valid signature that has not expired and
whose serial is no lower than the last one seen.

The user stays in control. `workcell update --to <version>` and `workcell update --rollback` work
today. The `[update]` table of `config.toml`, with `channel = "stable"` or `"hold"` and a `cooloff`
that may lengthen the project's cool-off and never shorten it, is not read yet.

Not built yet: the manifest format and its verifier exist, with tests. The client's fetch of
`channel.json`, the daily background check, the self-rollback of a layer that fails to run, and the
key table, which stays empty until the first release, do not exist yet.

## Disclosure

The maintainer follows coordinated disclosure: a reasonable fix window before public disclosure, notice
to the reporter when a fix is ready, and agreement with the reporter on timing.
