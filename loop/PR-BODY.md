## What this is

The tooling for rebuilding Workcell as v2 with a coding-agent loop that runs in the cloud.

`main` of this repository is v1's `main` with the v1 tree removed and a few reference packages moved to `_legacy/`.
This pull request adds only the loop kit on top of it. `omkhar/workcell` is not involved.

## What to read

| File | Why |
|------|-----|
| `loop/SPEC.md` | The rules the loop must follow: invariants, architecture, budgets, review, workflows, upstream bumping, final security review |
| `loop/PROMPT.md` | The instruction that every run of the loop follows |
| `loop/free-paths.txt` | The only paths the loop may change without the maintainer's signature. Everything else is locked |
| `.github/workflows/guard.yml`, `loop/guard.sh`, `loop/lib.sh` | The lock. The path filter and the signature checks are in `lib.sh` |
| `.github/workflows/ci.yml`, `loop/gate.sh` | The checks, and the automatic merge of `claude/*` branches |
| `.claude/settings.json`, `.claude/agents/` | What the agent is told it may not do, the model order, and the eight subagents |
| `loop/REFERENCE.md` sections 9 and 10 | What this does not protect against, and the review record |
| `loop/github-*.json`, `loop/settings.sh` | The repository settings the lock rests on |
| `loop/state/PLAN.md` | The backlog: 99 units, two of them shipped with the kit, and 13 human gates, one of them already decided |

## How it was made and checked

- An AI assistant wrote this kit. Separate AI agent sessions, given only the files, reviewed it adversarially. The first
  three versions failed and were redesigned. Version 4 was reviewed too. Eight reviewers judged it fit after small fixes, and
  reported about a hundred findings. Each is fixed, or admitted as a limit. Six reviewers then went over the fixes. They
  judged the kit fit after small fixes again, and found 58 more things, one of them critical and made by the fix round itself.
  Those are fixed or admitted too. The last fixes had one more review, of the changes alone. What it found was fixed or
  admitted, and those last changes have had no review.
  `REFERENCE.md` section 10 has the record. **No human has reviewed it yet.**
- More than 700 scripted checks and more than 200 gate cases, in `loop/test/`, with real GPG keys and a stand-in for
  GitHub that performs real merges. They pass under bash 5, and again with bash 3.2.57, a BWK awk and bsdtar. Those are
  close to what macOS ships, but not the same.
- The scripts were also tested by mutation, and the `go.mod` reader in `gate.sh` was compared with `go` itself on 7,000 generated files.
- The JSON payloads validate against GitHub's published API description.
- `shellcheck`, `actionlint` and `zizmor` are clean. `zizmor` has one documented exception, for the `pull_request_target`
  trigger that both workflows use on purpose.

## Known limits

- No checks run on this pull request. The workflows it adds load from the default branch, so they start to work once
  this is merged. `loop/setup-2-after-merge.sh` then tests them, KVM included, and attacks the lock before the loop starts.
- Nothing here has run against the real GitHub, in a real cloud session, or on a real Mac. `REFERENCE.md` section 11 lists it all.

## After merging

Run `~/loopkit/loop/setup-2-after-merge.sh`, then continue with `loop/START-HERE.md` step 5.
