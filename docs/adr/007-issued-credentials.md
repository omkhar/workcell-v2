# ADR-007: a credential the bound host issues to the guest

status: proposed

## Context

C89 (S-1007 sweep 4, I5 and A4, medium; FINDINGS.md from line 10598): the terminating proxy swaps the real value into any request to a bound host that an unnarrowed row
admits (internal/proxy/terminate.go, admits 112-124, the swap 399-406) and reads no answer of a host that has no sign-in rule (signin.go, tokenResponse 136-138). A provider
that issues or rotates a credential for the holder of the one presented (GitLab, `POST /api/v4/personal_access_tokens/self/rotate` with `Private-Token`) so mints a new, real
and durable credential of the operator's account straight into the guest. Every earlier ruling covers an echo of the value presented, never a value newly issued. The audit,
the redteam and the verifier found no patch: the product cannot tell which answer of a bound host is a credential, `path` parts the rotate endpoint from the rest of GitLab's
API only below `/api/v4/`, and a judge of answer text is what ADR-006 took out, here over answers that stream. Attacker (SPEC 2): guest root or hostile model output. The
precondition it does not control: the operator bound a credential whose provider has such an endpoint under the row's host and path, with a scope that allows it. Product is
14976 of 15000 as the unit line counts it; the parked test (49 lines) is in the test budget already. I5, I6, A1, A3, A4, sections 2, 5 and 7, T3, T5, T8, R5, W15, S4, S6, S7,
S8 and S14 apply; terminate.go is ported from v1's unreleased main, so this is handled in public, and a provider's rotate endpoint is its documented feature, not a weakness.

## Options

| | (1) no check; the duty in docs/policy.md and a row in SPEC section 2 | (2) as (1), plus a `path` in the compiled-in provider rows | (3) a swap only under a narrowed row | (4) judge a structure the host itself resolves or sends |
|---|---|---|---|---|
| Judged | nothing new: host, header, path and repos, as today | as (1); a row that takes host and header from a provider takes its path too | NewTerminateRule refuses a rule with neither `path` nor `repos`; admits loses its first branch | nothing fits: the request the host sends is a plain POST, and the answer is text the provider shapes and the guest reads, which the host neither resolves nor sends; the one such structure, tokenResponse's read-whole-and-refuse, is the sign-in host's today |
| Product lines | 0 | +1 to +3: bindings (cmd/workcell/policy.go 126-133) takes d.Path when the row has neither path nor repos; Path, "path" and k("path") fit on provider.go's lines 44, 119 and 153; 4 data lines, not counted | -3 +2 in terminate.go, and (2) first or every provider default is refused: about 0 to +2 | +8 to +15 and open-ended: a mark on the swapped request, a wider condition, a refusal arm and a key list (`token`, `value`, `name`, `api_key`, `client_secret`, ...); readToken's 256 KiB cap then refuses every streamed answer over it, and the chat APIs stream (FlushInterval -1 is for them) |
| Rows newly refused | none | none at load; under a default binding a request outside the prefix is 403, so a CLI route the prefix misses breaks silently, at the next automatic bump (A10; B6 drives one request) | every row with neither key: the four provider defaults without (2), every custom row, and the `anthropic` row of SPEC section 5 itself, which needs a maintainer edit of section 5 | none at load; answers refused by shape or size, model answers among them |
| The parked test | fails as today; deleted when the row is accepted, since no fix exists for S4's "passes after" | the same: its row is the operator's own, which no provider fills | its control (GET /api/v4/user served) fails, the row refused; with `path = "/api/v4/"` the rotate lies under the prefix and it fails again; it passes only under a prefix that excludes rotate, which is (1)'s duty spelled as a rule | passes for `token` in a JSON object; the redteam's unwritten variants (a header, a cookie, another media type, Gemini's token in `name`) fail in turn: ADR-006's chase |
| Reversal | docs lines from git; the SPEC row is the maintainer's: trivial | a key and 1 to 3 lines: low | about 5 lines, and every operator adds or drops `path`: medium-low, as `method` was | the lines, the cap and the streams: medium, and a part of ADR-006 undone |

## The four shipped rows

Whether the bound key reaches an endpoint on the bound host that issues or rotates a credential for its holder, from the providers' public documents alone (T8), checked on
2026-11-28. The hosts of OpenAI, Google, GitHub and GitLab do not resolve from this session, so those pages were read as search excerpts of the official text; Anthropic's in full.

| Row (internal/provider) | Bound | Finding | Document, site |
|---|---|---|---|
| claude.toml: anthropic | api.anthropic.com, x-api-key | No. The Admin API lists, retrieves and updates a key (`POST /v1/organizations/api_keys/{id}`: `name`, `status`), "never returns the key's secret value" and needs an Admin key; `POST /v1/oauth/token` exchanges an IdP JWT, not the bound key | "API Keys" and "Authentication", platform.claude.com |
| codex.toml: openai | api.openai.com, authorization (Bearer) | Yes, short-lived: `POST /v1/realtime/client_secrets` issues `ek_...` for 10 to 7200 s (default 600) to any key, and a session begun may run on. Durable only if the operator binds an Admin key: `POST /v1/organization/projects/{id}/service_accounts` "also returns an unredacted API key"; Admin keys "don't work with non-administration endpoints", so such a row serves Codex nothing | "Create client secret" and "Manage service accounts with Terraform", developers.openai.com |
| gemini.toml: gemini | generativelanguage.googleapis.com, x-goog-api-key | Yes, short-lived: `POST /v1beta/auth_tokens` with the key issues a Live API token, the `name` field of the answer (default 1 min to start a session, 30 min to send; the maximum is in a reference not reached), under the root the CLI uses, `/v1beta/models/...`, so only a prefix below that root parts them | "Ephemeral tokens", ai.google.dev |
| copilot.toml: github | api.githubcopilot.com, authorization (Bearer) | None documented: the one endpoint GitHub documents on the host is `POST /chat/completions`. "Reset a token" (`PATCH /applications/{client_id}/token`) returns a new token but authenticates with the app's client secret by Basic, at api.github.com, which the row does not bind | "Using Copilot's LLM for your agent" and "OAuth applications", docs.github.com |

GitLab, the model: `POST /personal_access_tokens/self/rotate` (16.10) needs the `api` scope, or the newer `self_rotate`, revokes the token presented and issues one that expires
in a week by default, a year at most ("Personal access tokens API", docs.gitlab.com). A `read_api` token cannot rotate itself, so the least-scope duty has teeth there.

## Decision

Option (1). The product does not change and no operator row is newly refused. docs/policy.md's closing sentence, "The guest never holds the value.", becomes: the guest never
holds the value you bound; what the host sends back is not read, so an echo of the value, or a credential the provider issues to the holder of the one you bound, reaches the
guest; bind a credential of the least scope and narrow `path` away from endpoints that issue one. docs/providers.md's table gains the Finding column above, so the duty is
concrete for each shipped row (openai: `/v1/realtime/`; gemini: `/v1beta/auth_tokens`). docs/threat-model.md's out-of-scope list mirrors section 2 once the row is there.
The row, which only the maintainer can add: "What an allowlisted provider sends back to the holder of a bound credential: an echo of the value, or a credential it issues or
rotates for that holder. The operator binds a credential of the least scope and narrows `path` away from endpoints that issue one (ADR-007)." It replaces the four echo rulings
(sweeps 1 and 2, S-1013, the PARKED line of S-1007) with one row (W15).
Why not (2): the two rows it could narrow (openai, gemini) mint tokens of minutes to two hours, good only at the bound host; the prefix is a bet on the CLI's routes that the
project measures with one request per provider (providers_test.go, escape/suite/smoke.go) and never re-measures at a bump (A10), so a wrong bet is a silent 403 (W8's
spirit); and the parked test's scenario, a row the operator wrote, is untouched. Why not (3): it refuses every unnarrowed row, the SPEC's own example among them, and still
mints under `/api/v4/`. Why not (4): there is no structure to judge; it is the text check ADR-006 took out, now over streams, and it does not fit in 24 lines.

## Consequences

- Product stays 14976 of 15000; Markdown about +6 lines, within 1444 of 2500. I5's letter is qualified by the row: a token the bound provider issues to the guest, short-lived
  (openai, gemini) or durable (an operator's GitLab row), may lie in guest memory; its use from the guest is recorded as a connection (I9), not as a secret use, and it may
  outlive the session. Nothing leaves the bound host on the request side (I6 holds). The duty is a sentence in docs, which T3 forbids any check to read.
- TestC89MintedCredentialReachesTheGuest: no change makes it pass while the bound API stays usable, so S4 has no "after". It waits in escape/_pending/S-F76/ until the
  maintainer moves this file to docs/adr/accepted/ and adds the row; the unit that builds the design then deletes the folder and the test (an accepted row has no arm, as
  ADR-006 ruled for C72), edits the three docs, and FINDINGS.md records C89 as accepted, with the reason here, not as fixed. An inverted test asserting the leak would be
  one that cannot fail (T2) and is not written. Until then C89 stays open with this ADR named.

## Reversal cost

Trivial: three docs edits return from git, the SPEC row is the maintainer's line, and the parked test returns from history if a later design closes the class. (2) can be
added later at 1 to 3 lines without touching this decision; (3) and (4) stay as the table describes, (4) only against ADR-006.

## For the maintainer

- The section 2 row above, or S-F76's line rewritten; S7 wants every medium fixed before cutover and the row moves C89 out of scope instead, which is S8's call to make.
- The unit that builds the design, added after acceptance as for ADR-006: delete escape/_pending/S-F76/, edit docs/policy.md, docs/providers.md and docs/threat-model.md,
  record C89 as accepted. If (2) is wanted for gemini or openai after all, the prefixes above are the ones to measure against the CLI's traffic before they are compiled in.
