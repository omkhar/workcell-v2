# Review of v1 workflows, automation and process

## 1. Scope and method

A static read of `main` at `21a8fc1` (2026-10-29). It covers all 14 workflow
files (3,708 lines), `dependabot.yml`, the git hooks, `scripts/ci/`, the local
validation scripts, the agent skills, the pull-request template, `AGENTS.md` and
`docs/releasing.md`.

**Not covered:** real run durations, failure rates and queue times. Those need
the Actions API. Run `loop/baseline-ci.sh` with a signed-in `gh` to capture them.
Unit U-003 turns the result into the "before" column. Timing statements below
come from `timeout-minutes` values and job dependencies, so they are upper bounds
and not measurements. The live repository settings were not visible either, so
statements about rulesets come from `policy/github-hosted-controls.toml`.

## 2. What is good and carries over

| Practice | Where |
|----------|-------|
| `permissions: {}` at the top, with scoped grants per job | every workflow |
| Every action pinned by commit SHA, `persist-credentials: false` on every checkout | every workflow |
| Build jobs hold no write scope; only `sign-release` holds `id-token: write`; only the publisher holds `contents: write` | `release.yml` |
| Release starts from `repository_dispatch`, so the workflow definition always comes from `main` | `release.yml:3-5` |
| Pull requests can read the trusted cache and never write it | `ci.yml:93-133` |
| Bump selection rule: newest release older than the cool-off, age counted from the later timestamp, never backwards | `internal/metadatautil/provider_bumps.go:312,1091,1106` |
| The bump bot is a GitHub App with no workflow permission, behind an environment | `upstream-refresh.yml:248-290` |
| Native arm64 runners instead of emulation | `ci.yml:439-441` |
| A `timeout-minutes` and a `concurrency` group on every job and workflow | every workflow |

## 3. Findings

Severity is about effect on users and on the maintainer's time, not style.

### High

| ID | Finding | Evidence | v2 rule |
|----|---------|----------|---------|
| F33 | **One required check has a deadline: 2 December 2026.** `pr-base-policy.yml` runs on `pull_request_target`, and its job "Allowed PR base" is a required check. From that date GitHub's default Actions policy blocks `pull_request_target` in a public repository that has no event policy of its own. The check would then never report, and no v1 pull request could merge without the administrator's bypass: not the daily pin refresh, not a security fix, not the cutover. Whether `omkhar/workcell` already has such a policy cannot be seen from outside. | `pr-base-policy.yml:9,30`; `policy/github-hosted-controls.toml:47`; `REFERENCE.md` section 2 | W3, W8 |
| F1 | **Bumps reach `main` and stop there.** Pins ship inside the release bundle, and the last release tag is dated 2026-08-04. There have been 1,545 non-merge commits since then, including a provider bump every day or two. A v1.0.2 user runs pins about 88 days old. | `git log v1.0.2..main`; `README.md:46` | B7, P7 |
| F2 | **The release pipeline fails more often than it publishes.** Three of the five 1.0-series tags (`rc.1`, `1.0.0`, `1.0.1`) never published. None of the recorded causes was a product defect. `rc.1` failed on a buildx flag in a probe job, and `1.0.0` failed on a token that could not read a repository setting. The pipeline first runs for real when a tag already exists, and tags are never reused. | `CHANGELOG.md:222,237-245,288-295` | W9 |
| F3 | **A release fails if any upstream published since the last bump.** Preflight runs `update-upstream-pins.sh --check`. The runbook calls this "a common release-preflight failure", and the remedy is to merge a refresh and burn another version number. One tracked upstream ships about every four hours. | `release.yml:535-542`; `docs/releasing.md:721-737`; `docs/github-workflows.md:220` | W8 |
| F4 | **No job runs the product's real boundary.** Hosted CI proves container flags and source-text invariants on Linux. The VM boundary is checked by hand on one workstation. | `docs/b6-disposition-options-draft.md` | P4, T1 |
| F5 | **A push to `main` cancels the previous commit's run.** All five cancelling workflows that run on a push to `main` (`ci`, `codeql`, `docs`, `hosted-controls`, `security`) use `cancel-in-progress: true` keyed on the ref. On busy days (32 merges to `main` on 2026-09-07) a merged commit can lose its run. The cache save is lost with it. | `ci.yml:34-36`, and the same block in the other four | W4 |
| F6 | **F5 combines badly with label-gated heavy checks.** CodeQL, mutation, reproducible build and install verification are skipped on a pull request unless it carries `approved-heavy-ci`. The required check `Reproducible build` reports success when it is skipped. The stated backstop is "every push to main still runs this job", and F5 can cancel exactly that run. A commit can therefore reach a release with those checks never completed for it until release preflight. | `ci.yml:310,422,458-480`; `codeql.yml`; `mutation.yml` | W3, W4 |
| F7 | **Every change runs CI twice.** Publishing needs fresh local `pr-parity` evidence for the exact head, and then hosted CI repeats the work. About 2,700 lines exist only to imitate hosted CI locally: `pre-merge.sh` 735, `ci-plan.sh` 624, `workflow-lanes.json` 1,028, `workflow-lane-policy.json` 313. | `scripts/repo-publish-pr.sh:137-161` | W2 |
| F8 | **The branch rule is bypassed on every human merge.** The policy mode is `review-gated`, which needs an approving review and a code-owner review. There is one maintainer, so every merge is an admin bypass. A control that is always bypassed trains the habit of bypassing. The policy file already defines an honest mode, `single-owner-public-pr`. | `policy/github-hosted-controls.toml:24`; `AGENTS.md` "single-maintainer admin merge" | W13 |
| F9 | **The process only grows.** `AGENTS.md` tells agents to turn every friction into a new rule, validator or runbook. Nothing ever removes one. Together with "continue until no actionable finding remains", this produces review rounds without a stopping point: 407 commit subjects mention "round N". | `AGENTS.md:31-44` | W15, R1 |

### Medium

| ID | Finding | Evidence | v2 rule |
|----|---------|----------|---------|
| F10 | **Everything is pinned except the runner.** 35 jobs run on `ubuntu-latest`. When it moved to 26.04 on about 2026-10-24 it broke container smoke and a self-test, and cost four fix commits in #965. | commits `db3cd89`, `11d7baa`, `956694d`, `227658b` | W5 |
| F11 | **Any label change restarts all of CI.** `labeled` and `unlabeled` are trigger types, and with `cancel-in-progress` they cancel the running jobs. The bots add labels. | `ci.yml:10-15` | W3 |
| F12 | **14 required checks on a serial critical path:** `pr-shape`, then `validate` (60-minute cap), then four `hostile-env` legs (60-minute cap each) that re-run repository validation. The hostile legs exist to catch shell quoting bugs. | `ci.yml:62-66,205-291` | A8, W3 |
| F13 | **The release repeats work it has just required.** `tag-policy` demands that six workflows already passed on the same commit. The pipeline then runs CodeQL, container smoke, validation, invariants, actionlint, zizmor and both reproducible builds again. The runtime image is built about eight times. There are ten serial stages, and the job timeouts add up to 700 minutes. | `release.yml:124-138,155-190,305-328` | W7 |
| F14 | **Nine `cosign sign-blob` steps and ten `actions/attest` steps.** One signature over `SHA256SUMS`, and one attestation using the checksum file as its subject list, give a verifier the same assurance. | `release.yml`, job `sign-release` | W10 |
| F15 | **The tag must point at the current tip of `main`.** Any merge after tagging, including an auto-merged bump, invalidates the release. | `release.yml:107-110` | W7 |
| F16 | **The release needs an exact set of six workflows for the commit, but `docs.yml` is path-filtered on push.** A release commit that touches none of the 27 listed paths can never qualify. It works today only because release commits edit the changelog. Scorecard, an external service, is also in the required set. | `release.yml:124-130`; `docs.yml` | W7, W8 |
| F17 | **Two updaters own the same files.** Dependabot is configured for `/runtime/container/providers`, and so is the custom refresher. Both have merged provider bumps (`d9240b1` by Dependabot, #932 by the refresher). No document divides the work. | `dependabot.yml:64` | W12 |
| F18 | **The bump machinery is about 15,400 lines** of scripts, Go and tests, around a selection rule that needs a few hundred. Part of that size exists because v1 must classify every new CLI flag before adopting a release (`unclassified-cli-surface`). That follows from enforcing policy by filtering arguments inside the guest. | `provider_bumps.go`, `pinnedinputs*.go`, `update-upstream-pins.sh`, `verify-upstream-*.sh` | A1, B15 |
| F19 | **No reuse mechanism.** There are no composite actions and no reusable workflows. Copies: BuildKit and buildx pins 6 each, cosign pin 5, zizmor install 3, actionlint install 2, the four-line token-to-file idiom 12, install verification about 62 lines twice. The duplication is what makes a pin validator necessary. | `.github/workflows/*` | W6 |
| F20 | **The job that reads upstream data also holds `issues: write`,** and carries 131 lines of inline bash to render an issue. Split it: a read-only job computes the plan, and a small job with the write scope posts it. | `upstream-refresh.yml:29-34` | B14 |
| F21 | **A long-lived token with administrative read runs on every push to `main`** and twice more in a release. Use a short-lived App token, and run the audit on a schedule. | `hosted-controls.yml:44`; `release.yml` | W11 |
| F22 | **The `pre-commit` hook calls the GitHub API on every commit and then always exits 0.** It adds latency and rate-limit exposure and gates nothing. | `.githooks/pre-commit:23,45` | W14 |
| F23 | **Process rules inflate history.** No force-push after publication, a new signed commit for each correction, and a wait for a policy run after every push, edit or state change. The lifecycle has 19 steps, the release runbook has 751 lines, and the pull-request template has 19 checkboxes. | `.agents/skills/workcell-pr-lifecycle/SKILL.md:29-30,69`; `docs/releasing.md` | W15 |
| F32 | **Not every commit is signed by the maintainer, although the docs say so.** All 1,545 non-merge commits since v1.0.2 carry a signature, but 7 of them are authored and SSH-signed as `Claude <noreply@anthropic.com>`, not with the published GPG key. `SECURITY.md` says commits are GPG-signed by the maintainer, and `AGENTS.md` requires the maintainer identity. A user who follows `SECURITY.md` cannot verify those seven. | `f327792b`, `db3cd898`; `SECURITY.md` "Signing key" | `main` takes squash merges, which GitHub signs; the maintainer signs checkpoints and release tags; `SECURITY.md` says which is which |

### Low

| ID | Finding | Evidence |
|----|---------|----------|
| F24 | The `zizmor` job holds `security-events: write` but only uploads an artifact. It never calls `upload-sarif`. It also runs the tool twice, and the `actionlint` job installs it a third time. | `security.yml:72,102,108` |
| F25 | CodeQL has no config file, so nothing excludes the 129,000 vendored Rust lines. A JavaScript lane with a 90-minute cap exists for a single `.mjs` file. | `codeql.yml` |
| F26 | The template still requires "The exact-head Codex marker is clean" after commit `4486bf6` dropped that requirement, and `async_reviewers` is empty. | `pull_request_template.md:42` |
| F27 | `validate-repo.sh` keeps a hand-written list of about 160 script paths to lint. | `scripts/validate-repo.sh:164` onward |
| F28 | `go run ./cmd/...` runs in release jobs with no pinned Go setup, so the toolchain named in `go.mod` may be downloaded in the middle of a release. | `release.yml:153,895,976,1090` |
| F29 | Fuzzing is weekly, 180 seconds per Rust target, and needs `RUSTC_BOOTSTRAP=1` plus a Python patch to the cargo config at run time. | `fuzz.yml` |
| F30 | `.agents/skills/commit` and `.claude/skills/commit` are byte-identical copies. | both files |
| F31 | 14 of 39 checkouts use `fetch-depth: 0`. Most of them need only the tip. | `.github/workflows/*` |

## 4. Upstream bumping: what to keep, what to change

Automatic bumping with a cool-off is a core feature. The v1 policy is right. The
delivery and the weight are the problems.

| Aspect | v1 today | v2 (SPEC section 10) |
|--------|----------|----------------------|
| Selection | Newest stable release older than 48 h, later-of timestamps, never backwards | **Keep unchanged** (B3) |
| Cool-off | 48 h for providers; no cool-off policy found for the custom toolchain refresh; 7 days for Dependabot | Two named classes: `guest` 48 h, `trusted` 7 days (B2) |
| Urgent fixes | No fast lane | An advisory on the pinned version drops `guest` to 12 h. `trusted` opens at once for a human (B4) |
| Reaches users | Only with the next binary release (F1) | A signed channel manifest on every `pins/` merge, read by the client (B7, B9) |
| Blocks releases | Yes (F3) | Never (W8) |
| Pre-adoption test | Static checks and a `--help` probe | Install the exact artifact in a real guest and drive a scripted session (B6) |
| Early warning | None | A nightly smoke test on upstream's newest release, non-gating (B11) |
| Measured | A tracking issue | Lag per pin against P7, with an issue when it is missed (B12) |
| New CLI flags | Held for manual classification | Irrelevant, because the guest is untrusted (A1) |
| User control | None | `hold`, a longer cool-off, `--to`, `--rollback`, automatic rollback (B9, B10) |
| Rollback and freeze attacks | Not applicable | Serial and expiry in the manifest (I14) |
| Redistribution | Provider CLIs are baked into a published image | The client fetches from upstream by pinned digest (B8) |
| Owners | Two overlapping updaters (F17) | One per path (W12) |
| Size | About 15,400 lines | 800 lines of product code (section 7) |

**Why 48 hours and 7 days.** A cool-off buys time for the community to notice a
compromised or broken release and for upstream to yank it. For guest-only tools
the exposure is small, because the guest is already assumed hostile and holds no
real secrets. There the cost of staleness dominates, and 48 hours is enough to
skip most same-day yanks and hotfixes. Anything in the trusted base runs with
host authority, so a bad release is far more costly than a week's delay. Both
numbers live in one data file. P7 makes the resulting lag visible, so you can
tune them from evidence.

## 5. Repository settings checklist (human gate H-807)

These are settings of `omkhar/workcell`, for the day v2 comes home. The loop has no access to that repository.
The order matters. `REFERENCE.md` section 8, "Bringing v2 home", gives it: required checks before the cutover pull
request, linear history and squash merges after it.

- [ ] Ruleset on `main`: pull request required, zero required approvals until a
      second maintainer exists, signed commits, linear history, no force-push,
      no deletion (W13).
- [ ] Required checks: `gate` only, plus one per extra architecture when it exists (W3).
- [ ] Allow auto-merge. Allow squash merges only.
- [ ] Mind how those two meet. With signed commits required, GitHub also judges the commits on a pull request's own branch, so
      unsigned ones can block a squash merge. The bump bot's commits must be made through the API, which signs them.
      An outside contributor must sign, or you land the work yourself.
- [ ] CodeQL default setup enabled for Go and Actions. Delete `codeql.yml`.
- [ ] Secret scanning and push protection enabled.
- [ ] Private vulnerability reporting enabled.
- [ ] Environment `release`: `main` and `v*` tags only, with a maintainer approval.
- [ ] Environment `bump`: `main` only. It is made here, in `omkhar/workcell`, at H-829, after the cloud task is
      deleted. Only then does it get the App credentials and the channel key. The building site never holds an
      App, an environment or a secret.
- [ ] Immutable releases enabled.
- [ ] Actions policy: GitHub-owned and listed actions only, SHA pinning required,
      default `GITHUB_TOKEN` read-only.
- [ ] Remove the `WORKCELL_HOSTED_CONTROLS_TOKEN` secret and revoke the token.
- [ ] Remove what v1's refresher leaves behind, once `bump` works: the `upstream-refresh` environment with its App
      credentials, that App's bypass entry in the review ruleset if it has one, and the App itself.
- [ ] Remove the old required checks as part of the cutover (H-905). Otherwise the
      cutover pull request waits for checks that no longer exist.

## 6. Quick wins on `main` now

These are worth doing only if v1 must stay healthy while v2 is built. They are
ordered by value for effort. Do them by hand or in one supervised session. They
are not part of the unattended loop, because v1's own process makes each change
expensive.

| # | Change | Fixes |
|---|--------|-------|
| 0 | **Before 2 December 2026:** under **Settings > Actions > Policies**, give `omkhar/workcell` a policy that allows `pull_request_target` for `pr-base-policy.yml`. Or take "Allowed PR base" out of the required checks. | F33 |
| 1 | **Cut a release**, so that users get three months of bumps. Then schedule one weekly. | F1 |
| 2 | Turn the preflight drift check into a warning. | F3 |
| 3 | `cancel-in-progress: ${{ github.event_name == 'pull_request' }}` in those five workflows. | F5, F6 |
| 4 | Replace `ubuntu-latest` with `ubuntu-24.04` or `ubuntu-26.04`. | F10 |
| 5 | Remove the `/runtime/container/providers` block from `dependabot.yml`. | F17 |
| 6 | Delete `.githooks/pre-commit`. | F22 |
| 7 | Set `branch_review.mode = "single-owner-public-pr"`, and match it in the settings. | F8 |
| 8 | Drop `security-events: write` from the `zizmor` job, or upload the SARIF file. | F24 |
| 9 | Remove the Codex line from the template, and cut the template to five lines. | F26 |
| 10 | Add a dry-run payload field to `release.yml` that stops before `sign-release`, and trigger it weekly. | F2 |
| 11 | Move heavy lanes to their own workflow triggered by the label, and drop `labeled` and `unlabeled` from `ci.yml`. | F11 |
| 12 | Add a CodeQL config with `paths-ignore: [runtime/container/rust/vendor]`. | F25 |

## 7. Target shape for v2

| Workflow | Trigger | Jobs | Line cap |
|----------|---------|------|----------|
| `ci.yml` | push to `main`, pull request | `gate` (amd64), one more per extra Linux architecture, and `gate-macos`. Each runs the whole of `scripts/check.sh`. On Linux that includes the VM suite | 120 |
| `release.yml` | `v*` tag, or manual with `dry_run` | `verify` (CI passed for this commit), `build`, `sign`, `publish` | 130 |
| `nightly.yml` | schedule | reproducibility compare, fuzz, install timing, early-warning smoke, freshness report | 80 |
| `bump.yml` | daily, and on a push that changes `pins/` | `plan` (read-only), `propose` (App token), `channel` (sign and publish) | 80 |

These are the triggers after cutover. While the loop runs, only `pull_request_target` and `schedule` can start a workflow
(`REFERENCE.md` section 2). Until then `ci.yml` also has the job `merge`, and the names `gate`, `gate-macos` and `merge` must
stay, because the rule on `main` requires the first two and the third lands the loop's work. Until then `bump.yml` does its
plan and a dry run only, with no App token and no key (H-829). The line caps are those after cutover too: with `merge` in it,
`ci.yml` may have 130 lines. `dependabot.yml` is capped at 30 lines.

| Measure | v1 | v2 target |
|---------|----|-----------|
| Workflow files / lines | 14 / 3,708 | 4 / at most 500 |
| Required checks | 14 | at most 3 |
| Release jobs / serial stages | 15 / 10 | 4 / 4 |
| Release runbook | 751 lines | tag and push, plus one approval |
| Local pre-publication step | full CI emulation | `scripts/check.sh` |
| Time from upstream release to user | unbounded (next release) | cool-off plus 24 h |
| Real boundary exercised per change | never | always |
