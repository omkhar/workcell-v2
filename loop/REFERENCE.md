# Reference

`START-HERE.md` tells you what to do. This file explains why, and holds the detail.

## 1. How the loop is engineered

v1 was also built by agent loops. They had no stopping rule, no size limit, and a reviewer that
could always find one more thing. The result was 24% product code, with 65% of recent commits
touching none of it. Each mechanism below exists to stop that from happening again.

| Principle | Mechanism |
|-----------|-----------|
| Keep the agent away from production | The loop works in its own repository, which never holds a secret. It has no access to `omkhar/workcell`, its releases or its secrets |
| A fixed target | `SPEC.md` is locked. A change to it lands only with your reviewed signature |
| State on disk, not in context | `loop/state/`. Every iteration starts with a fresh context |
| One small unit per iteration | About 400 changed lines. Larger units are split, not stretched |
| The harness decides, not the model | Work reaches `main` only through a pull request that passes `gate`, `gate-macos` and `guard` |
| Locked by default | `free-paths.txt` is an allowlist. Anything not on it is locked, including things nobody thought of |
| What is judged is what lands | Every pull request must sit on the tip of `main`, so the tree that `guard` reads is the tree the merge produces |
| The checks are out of the model's reach | Both workflows load from the default branch, and an Actions policy lets no other workflow run |
| Your key means you looked | It signs locked changes, gates, checkpoints, the cutover and release tags. It never leaves your account on the Mac |
| Evidence is behaviour | Invariants are proven by root-in-guest tests on a real VM. Each test must first fail against an open control sandbox |
| Test author and code author differ | `redteam` may not read the implementation. `builder` may not edit the attack |
| Review is bounded | One round and five findings, each with an invariant ID, an in-scope attacker and a reproduction |
| Growth is capped | Line budgets for product, tests, shell, YAML and docs |
| Progress only moves forward | The lists of enforced invariants can only grow |
| It knows when to stop | A human gate, repeated failures, checks that never report, a `loop-halt` issue, or done |

## 2. GitHub settings

`settings.sh apply` sets all of these and reads each one back. `setup-2` runs it, and `checkpoint.sh` re-reads them
every time. All need Administration access. You have it. The Claude GitHub App has it as read only.

```bash
cd ~/workcell-v2 && ~/loopkit/loop/settings.sh apply
```

| Setting | File | Why it matters |
|---------|------|----------------|
| Ruleset on `main`: pull request required, squash only, linear history, no force push, no deletion | `github-main.json` | Work reaches `main` only through a pull request |
| The same ruleset: `gate`, `gate-macos` and `guard` required, from app 15368 | | 15368 is GitHub Actions. A check of the same name from any other app, the Claude app included, does not count |
| The same ruleset: branches must be up to date | | Without this, GitHub's merge can carry an edit into a locked file that `guard` never saw |
| The same ruleset: no bypass list | | Cloud sessions act with your GitHub access. A rule you could bypass would not stop them |
| Actions policy: only `pull_request_target` and `schedule` may start a workflow | `github-actions-policy.json` | Both take the workflow file from the default branch. `push`, `pull_request` and `workflow_dispatch` take it from a branch the agent controls, so they are refused |
| Tag ruleset: nobody creates, moves or deletes a tag, whatever its name | `github-tags-all.json` | GitHub publishes a release only on a tag. No tag, so no release |
| What each of the three is aimed at: the default branch, every workflow file, every tag, with no exception | the same three files | A rule that is aimed at nothing protects nothing, and still reads "active". For `main`, `settings.sh` also asks GitHub which rules are in force there |
| Pull requests from collaborators only | | Outsiders cannot open a pull request, so no stranger's code reaches the `gate` jobs. It does not expire |
| Interaction limit: collaborators only | | Outsiders cannot open issues or comment. **It lasts six months.** `settings.sh apply` renews it |
| Squash merges only; no auto-merge; merged branches deleted; no wiki | | One way in, and nothing that merges later by itself |
| Workflow tokens read-only by default | | A job gets more only if its workflow, which is locked, asks for more |
| The label `loop-halt` exists | | It is the loop's one call for help |
| **Checked, not set:** no tag, no Actions secrets, no environments, no releases or drafts, no deploy keys, no collaborator but you | | Each would be a way in or a way out that goes round the rules above. This repository never holds a secret (section 9) |

**Webhooks are shown, not refused.** A webhook here sees only what is public anyway, and the Claude app may make one for the
scheduled task's trigger. `settings.sh` prints a `NOTE` with the host of each one. If you do not know a host, delete that webhook.

**The Actions policy is needed twice over.** GitHub has added a default policy that blocks `pull_request_target` in public
repositories, and enforces it from 2 December 2026. A repository keeps the event only through a policy of its own that
allows it. This one does.

**Your checkpoints are not tags on GitHub.** A checkpoint is a signed tag object. It lives as `refs/tags/loop-checkpoint-N` in
`~/workcell-v2`, and that clone is the anchor. The scripts push a copy to `refs/checkpoints/loop-checkpoint-N`. No rule protects
the copy, so no script trusts it. If GitHub refuses it, the scripts print a `NOTE` and go on. Anyone can fetch the copies into
a clone of their own, and check them with `git verify-tag`. You need not: your clone holds the originals.

```bash
git fetch --no-tags origin 'refs/checkpoints/loop-checkpoint-*:refs/tags/loop-checkpoint-*'
```

Your clone keeps each checkpoint twice. The second copy is `refs/loop/checkpoints/loop-checkpoint-N`. GitHub holds no tags, so
with `fetch.prune` and `fetch.pruneTags` in your own settings one plain `git fetch` deletes every tag in the clone. Git never
prunes the second copy, and the scripts look there too.

**If someone plants names there.** Whoever can push can create any name under `refs/checkpoints/`. The scripts ignore what
you did not sign. A Mac cannot hold some names side by side, such as two that differ only in case. Then the scripts print a
`NOTE` and go on. A planted `loop-checkpoint-N/x` keeps GitHub from taking your copy number N, which costs a `NOTE` too. The
command below makes `refs/checkpoints/` on GitHub a mirror of what this clone holds: the second copies and the checkpoint tags.
Every other name there goes. Never list those names and paste one into a command: git allows `$(...)`, quotes and semicolons
in a name.

A clone that you made anew holds no such tags. `checkpoint.sh` works there, but it keeps only your newest checkpoint, and GitHub's
copies of the others are the only ones. So the command first looks for `loop-checkpoint-0` in this clone. If that is missing, it
prints nothing and deletes nothing. Then run the `git fetch` of "A new Mac" (section 8) and `checkpoint.sh`, and try again. If
`checkpoint.sh` names a lower number than you remember, do not run the command: treat that as an incident.

```bash
cd ~/workcell-v2 && [ -n "$(git for-each-ref refs/tags/loop-checkpoint-0 refs/loop/checkpoints/loop-checkpoint-0)" ] && git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags --prune origin '+refs/loop/checkpoints/*:refs/checkpoints/*' '+refs/tags/loop-checkpoint-*:refs/checkpoints/loop-checkpoint-*'
```

**If GitHub holds a tag after all,** `settings.sh` says so, because a release can be published on any tag that exists. The
tag rule lets nobody delete it, you included. Switch the task off. In the browser, under **Settings > Rules > Rulesets**, set
"loop: no tags" to **Disabled**. Then run the command below. It deletes every tag on GitHub and none in your clone, switches
the rule on again, and reads everything back.

```bash
cd ~/workcell-v2 && git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags --prune origin 'refs/loop/none/*:refs/tags/*' && ~/loopkit/loop/settings.sh apply
```

**`main` does not require signed commits.** That rule would look right here, and it would stop the loop. GitHub's documentation
says that unsigned commits on the head branch can block a squash merge, although GitHub signs the squash commit itself. The
agent's commits are unsigned. `checkpoint.sh` checks the signatures on `main` instead.

**By hand,** if a line says `WRONG`. Enter what the JSON file says, then run `settings.sh check`.

| Line | Where it is on GitHub |
|------|-----------------------|
| The rules on `main`, the tag rule | **Settings > Rules > Rulesets**. A ruleset made by hand starts with no target. Under **Target branches** add the default branch. Under **Target tags** add all tags |
| `GitHub holds no tag at all` | "If GitHub holds a tag after all", above. `settings.sh apply` alone removes no tag |
| The Actions policy | **Settings > Actions > Policies** |
| Pull requests from collaborators only | **Settings > General**, under **Features**: in the menu below **Pull requests**, choose **Collaborators only** |
| The interaction limit | **Settings > Moderation options > Interaction limits** |
| Secrets, environments, deploy keys, webhooks, collaborators | **Settings**, under those names in the sidebar. Delete what you did not put there, and ask how it got there (section 8) |
| Releases and drafts | The **Releases** page of the repository. Delete each one |

## 3. Models

The order of preference for the top tier is **Mythos, then Fable, then Opus**.

| Setting | Where | Effect |
|---------|-------|--------|
| `ANTHROPIC_DEFAULT_FABLE_MODEL = claude-mythos-5-1` | the cloud environment (step 5b), and the command line in the second account. **No file in the repository sets it** | In those sessions the alias `fable` resolves to Mythos 5.1, also in the Agent tool's per-call `model` parameter, which accepts aliases only |
| The model of the session itself | the task's model menu (step 5d), and `--model fable` in the second account | The orchestrator runs on the top tier |
| `fallbackModel = [claude-fable-5-1, claude-opus-5-5]` | `.claude/settings.json` | If the model in use is overloaded or unavailable, Claude Code tries Fable, then Opus |

Every run loads `.claude/settings.json`, `.claude/agents/` and `CLAUDE.md` from the commit it starts on. A scheduled run starts
on `main`. A run that a merged pull request sets off starts on that pull request's last commit. `guard` passed on
that commit, and the ruleset required it to be up to date, so its locked files are the ones on `main`. The first command
in the task's prompt then moves the session to the tip of `main`.

The committed settings also apply to anyone else who works in a clone of this repository with Claude Code. Nothing tells them
so first. For someone who works on Opus, Sonnet or Haiku the price goes up. This fallback chain replaces theirs, and it starts
with Fable 5.1, which costs more than any of the three. The eight agents take the place of agents of theirs that have the
same names, and five of them run on the top tier. `README.md` says all this, and says how to set another chain. The agent
descriptions say "Loop only" for the same reason. `.claude/` is deleted at cutover.

According to the public model pages, Mythos 5.1 is the same model as Fable 5.1 at the same price, offered to
verified accounts. On Fable, a cybersecurity classifier can flag a request, and Claude Code then re-runs it on an Opus
model. That is the safeguard working as designed. Anthropic offers Mythos to accounts that it has verified for security
work on their own code, so the red team and the auditor start there. The order is a preference for the strongest
model on offer. It is never a way round a safeguard: if any model declines, the loop logs that and carries on, and
never rephrases the request (SPEC S11).

| Role | Tier | Effort | Why |
|------|------|--------|-----|
| Orchestrator | top | high | Long-horizon routing and rule-keeping |
| `architect` | top | `xhigh` | Decisions that are costly to reverse |
| `redteam` | top | `high` | Adversarial creativity sets the quality ceiling |
| `reviewer` | top | `high` | Must be at least as strong as the author |
| `auditor`, `verifier` (Phase 10) | top | `max`, `high` | Whole-surface audit; refutation by running |
| the agent that writes (`builder`, `scribe`, or `redteam` for test-only units) | per unit: 42 top, 14 `opus`, 32 `sonnet`, 9 `haiku` | `high` (`scribe`: `medium`) | Top tier where a subtle slip breaks an invariant |
| `scout` | `haiku` | `low` | Searching, log condensing |

A unit that fails moves up one tier. After a second failure the architect writes a diagnosis first. After a
third, the unit is marked `[!]` and waits for you, and the loop moves on.

Public list prices per million tokens, input / output, at the time of writing:

| Model | Price |
|-------|-------|
| Mythos 5.1 and Fable 5.1 | $10 / $50 |
| Opus 5.5 | $4 / $20 |
| Sonnet 5.5 | $2 / $10 |
| Haiku 5.5 | from $0.10 / $0.50 |

To spend less, select Opus for the scheduled task, and leave `redteam`, `reviewer` and `auditor` alone. On a Pro plan, Mythos
and Fable are paid from usage credits, not from the plan. The `/model` list in Claude Code then says "Requires usage credits".

**If Mythos is not available:** it is missing from the model menu of a new task, where step 5b has you look, and from the
`/model` list in the second account. Three places name Mythos, and none is in the repository. Leave the
`ANTHROPIC_DEFAULT_FABLE_MODEL` line out of the cloud environment (step 5b). Choose Fable in the task's model menu (step 5d).
Leave the variable off the command line in the second account. `fable` then means Fable 5.1, and nothing locked changes.
Whether a personal subscription exposes Mythos in Claude Code or in the cloud selector could not be checked in advance. The
public page lists it for the Claude API and three cloud platforms.

## 4. Where the work happens

| Mode | Units it can take | Driver | Who delivers |
|------|-------------------|--------|--------------|
| **Cloud** (default) | 92: `env:any` and `env:kvm` | the scheduled task, chained by merges | the agent opens a pull request; CI merges it |
| **Mac**, in the second account | the 5 `env:macos` units | you start Claude there, one piece at a time | you run `land.sh --from` in your own account |

Both feed the same pipeline. Run one at a time.

No agent ever runs in your own account, attended or not, and there is no extra Linux machine. Earlier designs had
both. Review showed again and again that an agent and your signing key cannot safely share one user account
(section 10). The same holds for the code that an agent wrote. It runs on your Mac only as `loop`, in `~/work`, whoever
starts it (section 6).

**Virtual machines.** A cloud session offered no hypervisor when this was written. The docs do not say. GitHub's hosted
Linux runners offer one. So a unit marked `env:kvm` proves itself on its pull request: the test is a Go test, CI runs it,
and the agent reads the log. A title that starts with `try: ` runs the checks without merging. Every piece starts that
way, which also tells other runs that the piece is taken.

**Cloud facts**, from the public docs:

- Each run gets a fresh Ubuntu 24.04 VM with about 4 vCPUs, 16 GB of memory and 30 GB of disk, with Go and
  Docker installed.
- Traffic leaves through an HTTP and HTTPS proxy, so SSH to another machine is out.
- The GitHub proxy rejects branch deletions, pushes of anything but a branch, and GraphQL. So `gh pr` does not work, and
  `gh api` does.
- The proxy serves only the attached repository. Fetch release downloads from other projects in CI.
- Scheduled tasks are a research preview. The documented caps are 100 scheduled runs an hour per account and 30
  manual runs an hour per task. GitHub events over their own cap are dropped, which is why the hourly trigger
  exists.
- Do not run the loop as threads of a Claude project. Those load only `CLAUDE.md`.

## 5. The Mac scripts

Run every one of them from `~/loopkit/loop/`, in your own account, with `~/workcell-v2` as the current folder.

| Script | What it does |
|--------|--------------|
| `test/all.sh` | Runs every test below, offline, and says which passed. A test whose tool is missing counts as skipped, not as passed |
| `test/suite.sh`, `test/gate-test.sh` | Test the Mac scripts and `guard.sh`; test `gate.sh`. The second needs Go 1.27 or newer, and fetches nothing. It writes its own small Go files, and never runs code from the kit folder or from a clone |
| `test/check-plan.py`, `check-rules.py`, `check-prompt.sh`, `check-deny.py` | Test the plan's format, a model of the prompt's halt and retry rules, the prompt's commands, and the deny rules. Run them after you edit `PLAN.md`, `PROMPT.md` or `.claude/settings.json`, and before you land the edit. The command is below the table |
| `setup-1-open-pr.sh`, `setup-2-after-merge.sh` | `START-HERE.md` steps 2 and 4 |
| `settings.sh apply`, `settings.sh check` | Section 2 |
| `preflight.sh` | Is this Mac ready to sign? Do the locked files on `main` still equal your kit? It changes nothing |
| `land.sh` | Fixes your edits as one tree, judges it, shows it, signs it, opens the pull request, merges it when green |
| `land.sh --reviewed` | The same, and locked paths may change. It shows the whole diff first, and updates the kit afterwards |
| `land.sh --from <file>` | The same, for a hand-over file from the second account. Anything only you may change is refused outright |
| `adopt.sh` | Shows each file under `proposed/` against the real one, installs what you accept, asks about each waiting unit, then runs `land.sh --reviewed` |
| `checkpoint.sh` | Re-reads the settings, checks every commit since your last checkpoint, compares `main` with your kit, signs a tag, sweeps up left-over branches |
| `baseline-ci.sh` | Records v1's CI timings. `setup-2` runs it for you |

**The four checkers read the tree in the current folder,** if it holds `loop/PROMPT.md`, and print each path that they read.
From any other folder they read the kit's own copies, which are the old ones until your edit has landed. So always start
with `cd ~/workcell-v2`. `check-prompt.sh` goes one step further: it runs command lines out of the clone's `PROMPT.md`, in
scratch folders. That file is locked, so the clone holds what you signed, plus your own edit, plus any draft that you
accepted in `adopt.sh` and have not landed yet. The script shows each line that your kit does not hold, and asks before it
runs it. Let `preflight.sh` pass first.

```bash
cd ~/workcell-v2 && python3 ~/loopkit/loop/test/check-plan.py && python3 ~/loopkit/loop/test/check-rules.py && python3 ~/loopkit/loop/test/check-deny.py && ~/loopkit/loop/test/check-prompt.sh
```

If you change a sentence that `check-rules.py` quotes, change the quotation in the same edit. The kit's copy fails on that
sentence until the change has landed.

| `land.sh` exit | Meaning |
|----------------|---------|
| 0 | Landed, or nothing to do |
| 1 | You said no, you interrupted it, someone closed the pull request, or a required check failed. Your files are untouched |
| 2 | Setup or usage problem, a failed push, or the checks did not finish in time. Read the message |
| 3 | `main` is busy or moved, or your copy or the hand-over is stale. Pause the loop and follow the message |
| 4 | Something only you may change, a hand-over that git refuses, a review that could not be shown in full, a clone that holds commits which GitHub lacks, or locked files on `main` that differ from your kit. **Nothing was sent to GitHub.** One message is the exception, and says so: it merged, but `main` does not hold the tree you signed |
| 6 | Signing failed |

**When it gives up,** `land.sh` closes its pull request and deletes its branch. It does so when a check fails, when the
checks take more than forty minutes, when someone else closes the pull request, when you press Ctrl-C, and when the terminal
closes. After a failed `gate` it first waits for the jobs of that run that are still going, because `gh` hands out no log
before they end. That wait has no limit of its own. Ctrl-C ends it, and then the log is only on the pull request's page. A
crash, a `kill -9` or a power cut can still leave a pull request open. Nothing will finish that one. Close it on GitHub
(`START-HERE.md`, "Pausing and stopping").

**A commit that you signed and gave up on can still land.** Once you have signed and `land.sh` has pushed, the commit is
public. GitHub goes on serving it under `refs/pull/N/head` after the pull request is closed, and it still fits for as long
as `main` stands still. Anyone who can open a pull request could offer it again. A new `guard` run refuses a signature of
yours that is more than two hours old. It takes the time from gpg's own `VALIDSIG` line, and that time is part of what was
signed. Do not count on that: a green `guard` that the commit already has stays on it (section 9). Only a `main` that has
moved cancels the commit. When `land.sh` gives up after a signature, it says so:

```text
The signed commit 0123456789ab is public. Anyone who can open a pull request can still land it until main moves.
If you have changed your mind, first put the change aside (git stash -u), then land any other change before you switch the task on again. Waiting is not enough.
```

`checkpoint.sh` applies no age limit, because it judges what has already landed.

**How a signature is made.** `land.sh` writes one tree object: from your files, through a private index, or from the
hand-over file. From then on it refers to that object by hash, so later edits cannot matter. It compares the tree with
`main`, shows you the subject and every changed file taken from the same object, and signs a commit that holds exactly
that tree on exactly that parent.

**Two kinds of signature.** The signed message ends with `Locked-paths: none` or `Locked-paths: reviewed`. `land.sh`
writes the second only after it has shown the diff and you have answered `y`. `guard` accepts a locked change only if
that is the **last** line. A subject that imitates it is replaced. So a signature you give to ordinary work can never
authorise a locked change.

**Things in free files that are still yours.** `loop/state/PLAN.md` and `loop/state/LOG.md` are free, because the loop writes
them all day. Some of their content is not. A change to it needs one commit signed by you, which plain `land.sh` makes.
`guard`, `land.sh --from` and `checkpoint.sh` enforce that with one shared function, `yours_between` in `lib.sh`.

| File | What is yours | How it is judged |
|------|---------------|------------------|
| `PLAN.md` | The headings, the code fences, every line that carries a gate's ID, ticked or not, and each gate's `accept` line | Old and new are compared in file order. So a line that changes, moves, disappears or gains a twin counts |
| `PLAN.md` | A dependency on a gate, or on `above`, that disappears from a `deps` field | A new dependency is free |
| `LOG.md` | All that is already written, because the log is append-only. And every added heading that is not `## <time> <unit>` followed by `START`, `PASS`, `FAIL`, `BLOCKED` or `SPLIT`. A `RESUME` line is such a heading | Line by line against the old log |
| both | A NUL byte, or a byte outside printable ASCII in a line that these rules judge | Such a byte can say one thing to a reader and another to a rule |

Section 9 says what these rules cannot catch.

**Accepted decisions are locked by their path.** `docs/adr/` is free, and `docs/adr/accepted/` is locked. A decision counts as
accepted only when you have moved its file there, with `git mv` and `land.sh --reviewed`. From then on nobody can rewrite,
replace or delete it without you. No rule looks for the words "status: accepted". ADR-002 ships in that folder.

**The hand-over.** The agent in the second account commits its work there and writes one git bundle to
`/Users/Shared`. `land.sh --from` copies that file once, into a folder only you can read. It uses the copy only if
`git bundle verify` accepts it for this clone. Then it splits the header off, and feeds the rest to
`git unpack-objects --strict`, which checks every object on any version of git. The work must sit on the current tip of
`main`. The script never looks into a folder the agent can write, so there is nothing to race.

**The shared folder.** From your own account, read only the files that the guides name in `/Users/Shared`, and judge your
copy, not the original. Never write to a fixed name there. `loop` can put a link under any name first, and your copy would
go through the link into your own files. A folder from `mktemp -d` is new and yours alone. `START-HERE.md`, "For each
piece", hands the log of a failed check back in that way.

**What the scripts refuse to trust.** They call git with hooks and file monitors off. They switch off three settings of your
own that would change what is staged, pushed or printed: the global ignore list, `push.followTags` and `log.showSignature`.
They ignore replace refs, the system git config and inherited `GIT_*` variables. They spell every ref in full, because a
short name such as `origin/main` would resolve to a tag of that name first. They fetch only the refs they name, and copy the
checkpoints on GitHub into a namespace of their own. They work in the C locale, so that no odd byte can hide a line from a
pattern. Only the signing step keeps your terminal's locale, for the passphrase dialog. They resolve their own folder and
the clone's to real paths, so that no link and no other spelling can pass the repository's copy off as your kit. The pager
takes its options from the script alone. A locked file that holds a control character, such as a carriage return, is refused
before you are asked to read it. The line breaks U+0085, U+2028 and U+2029 count as control characters. Their scratch files
live in `~/.workcell-loop`. `land.sh` signs nothing, except a repair with `--reviewed`, while the locked files on `main`
differ from your kit.

## 6. Gates, and the final security review

| Gate | Account | Decision or action |
|------|---------|--------------------|
| H-000 | yours | `START-HERE.md` steps 1 to 4 tick it; steps 5 and 6 start the loop |
| H-011 | **`loop`** | Optional, and private: run the suite against v1.0.2, before hosted CI runs it against code ported from v1 |
| H-103 | yours | Choose the VM backend from ADR-001, and move the file to `docs/adr/accepted/` |
| H-104 | | Decided: `clone` |
| H-409 | **`loop`** | Read the provider terms on intercepting subscription sign-in, and test real sign-ins |
| H-703 | **`loop`** | Run the full suite on the Mac; arrange signing, entitlement and notarisation |
| H-704 | **`loop`** | Linux arm64: test it in a nested guest on the Mac, or narrow P6 |
| H-806 | **`loop`** | Optional, private, and outside this repository: compare with other sandboxes, and disclose privately first |
| H-1015 | **`loop`** | The Claude Security plugin, twice, and private fuzzing of ported code |
| H-1019 | yours | Read the security report, decide on a human audit, sign |
| H-807 | yours | Settings of `omkhar/workcell` for v2 (`WORKFLOW-REVIEW.md` section 5) |
| H-829 | yours | GitHub App, `bump` environment and channel signing key. In `omkhar/workcell` only, and only after the cloud task is deleted |
| H-905 | yours | Cutover: the pull request into `omkhar/workcell`, and the `v2.0.0` tag (section 8, "Bringing v2 home") |

To close a gate, change its `[H]` to `[x]` and land it. An optional gate is closed the same way, whether you did it or
decided not to.

**A gate that runs code is done as `loop`.** Code from the repository runs on your Mac only as `loop`, in `~/work`, whoever
starts it. Claude wrote that code. In your own account it would run beside your key and your `gh` login. As a backstop,
`gate.sh` refuses to execute anything in an account that holds `~/loopkit`. It cannot stop a `go test` that you type
yourself, so the rule is yours to keep.

1. Pause the cloud. As `loop`, run the two commands of `START-HERE.md`, "For each piece", without `claude`:

   ```bash
   screen -S loop
   ```

   ```bash
   rm -rf ~/work && git clone --branch main https://github.com/omkhar/workcell-v2.git ~/work && cd ~/work
   ```

2. Run what the gate asks for. `gate.sh` runs the invariants that `escape/enforced-macos.txt` lists. H-703 asks for all of
   them, so run the suite once more without a list:

   ```bash
   cd ~/work && GATE_MACOS=1 loop/gate.sh
   ```

   ```bash
   cd ~/work && go run ./escape/cmd/escape -sandbox workcell
   ```

3. If the gate wants a report in the repository, edit that file in `~/work`. Then commit, and write the hand-over file as
   `PROMPT.md` section 7b does. Put the gate's own ID in place of `H-703`:

   ```bash
   cd ~/work && git add -A && git -c user.name=loop -c user.email=loop@localhost commit -q -m "H-703: report from the Mac"
   ```

   ```bash
   cd ~/work && git bundle create /Users/Shared/workcell-handover.bundle refs/remotes/origin/main..HEAD
   ```

4. In your own account, land it:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/land.sh --from /Users/Shared/workcell-handover.bundle
   ```

5. Tick the gate as a separate landing (`START-HERE.md`, "Changing something yourself"). `--from` refuses a gate tick.

| Gate | What else to know |
|------|-------------------|
| H-011 | Step 2's commands do not do this: they test v2. The suite has no adapter for v1, and none may enter the repository. As `loop`, in a second clone that is never handed over (`~/v1look`), have Claude write one behind the `Sandbox` interface of U-004, driven through v1's own CLI. Install v1.0.2 as `loop` too. Run `go run ./escape/cmd/escape -sandbox v1`. Steps 3 and 4 fall away. If you would rather not, tick the gate as declined: "Fail a VM test in public" in section 9 then applies in full |
| H-409 | The code under test sees the real tokens. Use test accounts. If you must use your own, sign out and revoke those sessions afterwards |
| H-703 | The suite needs no Developer ID: as `loop`, sign the test binary ad hoc with the virtualization entitlement (`codesign -s - --entitlements`). Your Developer ID signs nothing that the second account built or could touch. It signs release builds only, in `omkhar/workcell`, after H-1019. Keep its certificate and key out of the `loop` account |
| H-704 | The suite runs in a Linux guest, and the guest is started as `loop` |
| H-806 | Nothing about it enters this repository, so steps 3 and 4 fall away |

If every unit passes first time, the loop stops for you seven times in all. The cloud can finish 20 units before its first
stop. It then needs you for U-102 and U-702 (two Mac pieces), and the optional gates H-011 and H-806 are ready. One unit
later comes your decision at H-103, which opens the longest stretch: about forty units.

**Phase 10** starts only when every other unit is `[x]`. The rules are in SPEC section 11.

1. **Map** the attack surface as built (S-1001).
2. **Audit** twelve surfaces, one per iteration (S-1002 to S-1013). The `auditor` runs at `max` effort and reads
   the whole surface through seven lenses. The last audit chains weaknesses across surfaces.
3. **Confirm by reproduction.** `redteam` writes a test for each candidate, and `verifier` tries to refute it by
   running it. Nothing counts unless it reproduces. Confirmed findings become fix units, and their tests stay.
4. **Fuzz** every target for four hours in hosted CI (S-1014). Targets in packages ported from v1 are left out there, because
   a crasher would be public. Step 5 covers them.
5. **Independent tools**, run by you in the second account (H-1015). Start Claude with the two commands of `START-HERE.md`, "For
   each piece". They give you the best model the account offers. Do not paste the supervised prompt. Type:

   ```text
   /plugin install claude-security@claude-plugins-official
   /claude-security scan the whole repository at high
   ```

   When the install asks for a scope, choose the **user** scope. The project scope would write `.claude/settings.json`, which
   is locked, and `land.sh --from` would then refuse the next hand-over. Run the scan twice, because scans are not
   deterministic. Ask Claude to copy each `CLAUDE-SECURITY-RESULTS.jsonl` into `loop/private/findings-in/`, which git ignores.
   `/security-review` is not on the list: it reviews the difference between a branch and `main`, and here there is none.

   Then fuzz each target in a package that was ported from v1, for four hours. Do it in a second clone that is never handed
   over, because Go writes each crasher into the source tree. The second command lists the ported files, and the third
   lists every fuzz target with its package. In the last, put the target in place of `FuzzNAME` and its folder in place of
   `PACKAGE`:

   ```bash
   rm -rf ~/fuzz && git clone --branch main https://github.com/omkhar/workcell-v2.git ~/fuzz
   ```

   ```bash
   cd ~/fuzz && grep -rl --include='*.go' 'Ported from v1:' .
   ```

   ```bash
   cd ~/fuzz && go test -list '^Fuzz' ./...
   ```

   ```bash
   cd ~/fuzz && go test -fuzz '^FuzzNAME$' -fuzztime 4h ./internal/PACKAGE
   ```

   Move each crasher from `~/fuzz`, where it lies under `testdata/fuzz/`, to `~/work/loop/private/findings-in/`. `git status` in
   `~/work` must show nothing before S-1016. Tick H-1015. For S-1016 **keep `~/work`**, because its inputs are files that git
   ignores. Start Claude there without a new clone, and give it the usual supervised prompt:

   ```bash
   cd ~/work && ANTHROPIC_DEFAULT_FABLE_MODEL=claude-mythos-5-1 claude --model fable
   ```

6. **Sweep again** until a whole sweep confirms nothing at medium or above. After three sweeps the loop halts and
   hands you a design question.
7. **Report** in `docs/security-review.md`. You read it and sign (H-1019).

The repository is public. A finding that also affects released v1 code, or someone else's project, stays out of
the repository, issues and CI logs until it is fixed or disclosed (SPEC S14).

This is an AI-assisted review. It is not a substitute for the independent human audit that v1's roadmap
deferred, and the report has to say so.

## 7. Signals

| Signal | Meaning | What to do |
|--------|---------|------------|
| Issue labelled `loop-halt` | The loop stopped and needs you. The title gives the reason; see the second table. GitHub sends you no notice, because the issue is opened with your own account | `START-HERE.md`, "When the loop asks for you" |
| A unit marked `[S]` | A locked file is drafted under `proposed/` | `adopt.sh` |
| A unit marked `[!]` | It failed three times, or it needs something only you have | Read `loop/state/BLOCKED.md`; rewrite or split it |
| `guard` red | Something only you may change was changed, or the branch is behind `main` | The agent should repair it once, or close it and try again. If not, close it yourself |
| A pull request titled `try: ...` | A piece in progress, or an experiment that needs a VM. It never merges under that title | Nothing, while commits or checks still arrive. After three hours without either, its run is dead. A later run closes it. If the task is off or a halt issue is open, no run will: close it yourself |
| A pull request from a `mac/` branch | Your own `land.sh` | Nothing, while `land.sh` runs. It merges or closes it. If `land.sh` is gone, close it yourself |
| `preflight.sh` says the locked files differ from your kit | Something is wrong, or your kit is out of date | Section 8 |

| Reason in the title | Meaning | What to do |
|---------------------|---------|------------|
| `nothing-to-do` | Every unit that is left waits for you | Do what the body asks |
| `six-failures` | The last six results were all FAIL or BLOCKED. Something general is wrong | Find the cause. Then add a RESUME line to the log (`START-HERE.md`, "Changing something yourself") |
| `needs-you` | The unit needs something that only you have, or that cannot be said in public: a credential, a purchase, a legal reading, or a weakness that may affect released v1 or someone else's project (SPEC S14). The public text is the same for all of them: `<unit>: needs the maintainer, see the run's transcript` | Read the transcript of the run that opened the issue, on the task's page. For a weakness, follow v1's `SECURITY.md`. If its test has already run in hosted CI, delete that run's logs in the **Actions** tab |
| `no-schedule` | A unit marked `wait:` needs a scheduled run of a workflow, and has been skipped for more than 48 hours | Look for that workflow in the **Actions** tab. It is disabled, its file is invalid, or its `cron` line is wrong. Switch it on again there, or repair the file like any locked file (`START-HERE.md`, "Changing something yourself"). Close the issue once a scheduled run has finished |
| `no-checks` | `gate`, `gate-macos` or `guard` did not start within 15 minutes or finish within 45. Or a runner had no KVM four times in a row | Look at the **Actions** tab. Run `settings.sh check`. If a workflow you adopted is broken: section 8. If GitHub's runners have stopped offering KVM, the plan needs a runner of your own |
| `no-merge` | Every check has been green for ten minutes, `main` has not moved, and still nothing merges | Read the last line of the `merge` job's log. GitHub refuses a merge when a required check is not green, when the branch is behind `main`, or when the change touches a workflow file. Then run `settings.sh check` |
| `main-red` | `main` itself fails the gate | Fix it from the Mac, or revert the last change |
| `no-logs` | The cloud cannot download CI logs | `START-HERE.md` step 5c, part 3 |
| `no-agents` | The session did not load `.claude/agents/` or `.claude/settings.json` | Check the task's repository and prompt (step 5d) |
| `stale-mac` | A `mac/` pull request has been open for three hours | Close it. A crash or a power cut during `land.sh` can leave one |
| `finished` | Everything above the Cutover heading is done | H-807, H-829 and H-905 |

## 8. Upkeep

**Add a unit, tick a gate, change a rule.** `START-HERE.md`, "Changing something yourself". After a `--reviewed` landing,
`land.sh` copies exactly the files you signed into `~/loopkit`.

**The loop keeps failing one unit.** It is usually too big, or its `accept` text is vague. Rewrite or split it.

**A budget is too tight.** First ask what could be deleted. If the answer is nothing, raise it in both `SPEC.md`
and `gate.sh`.

**The loop proposes a new validator, manifest or policy file.** That is v1's failure mode returning. Reject it
under SPEC W15.

**You shorten `free-paths.txt`.** Files that were free become locked, and your kit has no copy of them. `land.sh` ends with
`Your kit still differs from what you signed`, and `preflight.sh` lists them as "only in the repository". Read each one, then
copy it from `~/workcell-v2` to the same place under `~/loopkit`. Or delete them in the same change.

**Six months have passed.** The interaction limit has run out, and `checkpoint.sh` says so. Run `settings.sh apply`. Until you
do, outsiders can open issues and comment. They still cannot open pull requests, because that setting does not expire.

**A new Mac.** Bring your secret key over first, and do `START-HERE.md`, "Before you start". Then make the clone as
`setup-1` made it, and fetch the copies of your checkpoints. After that, rebuild the kit. The second account has to be made
again too (`START-HERE.md`, "The pieces that need your Mac").

```bash
git clone https://github.com/omkhar/workcell-v2.git ~/workcell-v2
```

```bash
cd ~/workcell-v2 && git config user.signingkey 90554248C4F7CC086BB745D0DA5A8E9F536C42FD && git config gpg.format openpgp
```

```bash
cd ~/workcell-v2 && git remote add v1 https://github.com/omkhar/workcell.git && git remote set-url --push v1 no-push-to-v1
```

```bash
cd ~/workcell-v2 && git fetch --no-tags origin 'refs/checkpoints/loop-checkpoint-*:refs/tags/loop-checkpoint-*'
```

A new clone knows only what GitHub tells it, and nothing protects those copies. If the highest number is lower than you
remember, treat that as an incident.

**Rebuild the kit,** after losing it or on a new Mac. Take it from a checkpoint you signed, the highest number that passes
this test. It must say `Good signature` with your key, and the line that starts with `tag` must name that very checkpoint.
Replace `N`, here and below:

```bash
cd ~/workcell-v2 && git verify-tag -v refs/tags/loop-checkpoint-N
```

Take only the locked files. The free folders hold code that Claude wrote, and none of that belongs in `~/loopkit`. The names
left out below are the lines of `loop/free-paths.txt`. If you have changed that file, change the list to match. The second
command fetches the one locked folder inside a free one.

```bash
mkdir ~/loopkit.new && git -C ~/workcell-v2 archive refs/tags/loop-checkpoint-N -- . ':(exclude)cmd' ':(exclude)internal' ':(exclude)escape' ':(exclude)pins' ':(exclude)docs' ':(exclude)spikes' ':(exclude)proposed' ':(exclude)_legacy' ':(exclude)loop/state' ':(exclude)loop/baseline' ':(exclude)go.mod' ':(exclude)go.sum' ':(exclude)README.md' | tar -x -C ~/loopkit.new
```

```bash
git -C ~/workcell-v2 archive refs/tags/loop-checkpoint-N -- docs/adr/accepted | tar -x -C ~/loopkit.new
```

Then move `~/loopkit` away, rename `~/loopkit.new` to `~/loopkit`, and run `preflight.sh`. A rebuilt kit holds what the signing
scripts need. `suite.sh` is made for the kit as it was shipped, free files included. From a rebuilt kit it reports failures,
and so does `all.sh`, which runs it.

`preflight.sh` may now list differences. That is normal if a locked change landed after checkpoint N: you sign a checkpoint
before each adoption, not after it. Copy nothing back. Run `checkpoint.sh`, which judges every commit since N before it looks
at your kit.

| What `checkpoint.sh` says | What it means | What to do |
|---------------------------|---------------|------------|
| It names commits that are wrong | Something landed that you never signed | "If something locked changed without you", below |
| Only `the locked files on main are not the ones in your kit` | Every commit since N passed. You signed each of those changes, and your kit is the older one | Rebuild once more, with `refs/remotes/origin/main` in place of the tag in both `archive` commands. Then run `checkpoint.sh` again, and sign |

**Your key is about to expire.** `guard` verifies against `.github/maintainer.asc`, a copy of your public key. Extend the
key **before** it expires, and land the new copy while the old one still verifies. Export it with the filters that `setup-1`
used: one user ID, and only keys that can sign.

```bash
cd ~/workcell-v2 && gpg --armor --export-options export-minimal --export-filter "keep-uid=mbox = $(git config user.email)" --export-filter 'drop-subkey=usage !~ s' --export 90554248C4F7CC086BB745D0DA5A8E9F536C42FD > .github/maintainer.asc && gpg --show-keys .github/maintainer.asc
```

Read the list that it prints. `land.sh --reviewed` can show the file only as armour, so this list is your review. If `setup-1`
needed `LOOP_UID`, put that address in place of `$(git config user.email)`. Then land it. Before `land.sh` sends anything, it
proves that the new file alone verifies your signature.

```bash
cd ~/workcell-v2 && ~/loopkit/loop/land.sh --reviewed
```

**You change to a new key.** Do these in order, while the old key still works. Both secret keys must be on this Mac.

1. Run `checkpoint.sh`, so that everything so far is vouched for by the old key.
2. In `~/workcell-v2`, export the new public key with the long command above, with the new fingerprint in place of the old
   one. Write the new fingerprint, forty characters with no spaces, into `.github/maintainer.fpr`. Replace the fingerprint
   in `SECURITY.md` too. Run `land.sh --reviewed`. It signs with the old key, tests the new one, and then the kit pins the
   new one.
3. Tell git to sign with the new key:

   ```bash
   cd ~/workcell-v2 && git config user.signingkey NEWFINGERPRINT
   ```

4. Sign the next checkpoint by hand with the new key, as described next. `checkpoint.sh` now ignores the tags made with the old
   key, and says that there is no checkpoint signed by the key in your kit. That is expected. Do not delete the old tags.
   `setup-2` still runs after the change, because it skips its first two steps once gate H-000 is ticked.

**Sign a checkpoint by hand.** `checkpoint.sh` cannot do it in two cases: after a change of key, and after an incident that you
have read and settled. Replace `N` with the next free number. The tag stays in your clone, and only its copy goes to GitHub,
under `refs/checkpoints/`. The two `-c` options make git use the token that `gh` holds, as the scripts do.
`--no-follow-tags` keeps git from sending the tag itself along, which it does if your own settings say `push.followTags`.
The `update-ref` makes the second copy that section 2 describes.

```bash
cd ~/workcell-v2 && git tag -s loop-checkpoint-N refs/remotes/origin/main -m "reviewed by hand" && git update-ref refs/loop/checkpoints/loop-checkpoint-N refs/tags/loop-checkpoint-N
```

```bash
cd ~/workcell-v2 && git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags origin refs/tags/loop-checkpoint-N:refs/checkpoints/loop-checkpoint-N
```

**When the checks themselves are broken.** Both workflows load from `main`. So if you adopt a broken `ci.yml` or `guard.yml`, or
let the key in `.github/maintainer.asc` expire, no pull request can pass, the repair included. Only you can get out of
that, because only you can switch the ruleset off.

1. Switch the scheduled task off.
2. Make the repair in `~/workcell-v2`. An earlier version of a file is in any checkpoint. Replace `N`:

   ```bash
   cd ~/workcell-v2 && git show refs/tags/loop-checkpoint-N:.github/workflows/ci.yml > .github/workflows/ci.yml
   ```

3. In the browser, under **Settings > Rules > Rulesets**, set "loop: main takes only checked pull requests" to **Disabled**.
   From now until step 5 nothing protects `main`, so do not stop half-way.
4. Land the repair. With the ruleset off, GitHub merges it without waiting for the checks:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/land.sh --reviewed
   ```

5. Switch everything on again, and prove the lock again:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/settings.sh apply && ~/loopkit/loop/setup-2-after-merge.sh
   ```

6. Sign a checkpoint. It notices if anyone moved `main` back while the ruleset was off.

**If something locked changed without you.** This covers `CHECKPOINT STOP`, `THE LOCK DOES NOT HOLD`, and a `preflight.sh`
or `land.sh` message that the locked files differ from your kit and you cannot say why. If you have rebuilt your kit a
moment ago, read "Rebuild the kit" first: a kit that is older than `main` gives the same message, and is no incident.

1. Switch the scheduled task off. Delete it if you suspect more than a mistake.
2. Run `settings.sh check`. If a setting changed and you did not change it, the cloud holds rights it should not have:
   repeat `START-HERE.md` steps 5a and 5c before anything else.
3. Read **every** commit that the message names, on GitHub. Look at which pull request brought each one, and at that pull
   request's checks. Look in the **Actions** tab for runs of workflows you do not know.
4. Put the locked files back. Your kit holds the last version you signed. Let `preflight.sh` list every difference,
   and bring the clone up to date:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/preflight.sh ; git merge --ff-only refs/remotes/origin/main
   ```

   If history was rewritten, that merge is refused, because your clone holds commits that `main` has lost. Keep them under
   another name, and follow `main`. `git log refs/remotes/origin/main..lost-main` then lists what vanished:

   ```bash
   cd ~/workcell-v2 && git branch lost-main refs/heads/main && git reset --hard refs/remotes/origin/main
   ```

   | Line from `preflight.sh` | Do this in `~/workcell-v2` |
   |--------------------------|----------------------------|
   | `differs`, `only in the kit`, `not a plain file in the repository` | Delete the file if it is there. Copy the one from `~/loopkit` to the same place |
   | `only in the kit`, and it is a left-over of your own, such as a note or an editor's backup | Delete it in `~/loopkit`. Change nothing in the clone |
   | `only in the repository` | Delete it |
   | `executable only in the repository` | `chmod -x` it |
   | `executable only in the kit` | `chmod +x` it |

   Then land the repair:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/land.sh --reviewed
   ```

   If `guard` or `gate` is red on this repair, the incident broke the checks themselves. Go on with steps 3 to 5 of "When
   the checks themselves are broken", above.

5. **`preflight.sh` must now say that the locked files are identical to your kit.** Do not go on until it does.
   Then read everything since your last checkpoint, because the checks may not have been real in that period.
6. `checkpoint.sh` will keep stopping at the bad commits. Once you are satisfied, sign the next checkpoint by hand ("Sign a
   checkpoint by hand", above).

**Leaving.** Delete the scheduled task. Remove `omkhar/workcell-v2` from the Claude GitHub App. Delete the repository, or
archive it. Delete the `loop` user account. `omkhar/workcell` was never touched.

**Bringing v2 home** is the point of all this, and it is all yours: gates H-807, H-829 and H-905. This repository began as v1's
`main`, so its history is v1's history plus the loop's commits, and the Go module is already named
`github.com/omkhar/workcell/v2`. `SECURITY.md` is v2's own by then: a unit of Phase 9 (U-907) drafts it from v1's, and you adopt
it. In order:

1. Freeze v1's `main`, so that it stands still while you work. Switch off the workflow that refreshes its pins
   (`upstream-refresh.yml`). Close any pull request that it has left open, because those merge by themselves. Merge nothing
   from Dependabot.

   ```bash
   gh workflow disable "Upstream refresh" --repo omkhar/workcell
   ```

2. Delete the scheduled task, and remove `omkhar/workcell-v2` from the Claude GitHub App. From here on no agent has a hand in
   anything. If ADR-004 is not accepted yet, accept it now. Then sign a last checkpoint.
3. Only now create what the update bot needs (H-829): the GitHub App, the `bump` environment with its secrets, and the channel
   signing key if ADR-004 calls for one. Create them in `omkhar/workcell`, never in the building site. Nothing uses them
   before the merge in step 9. If the client is to carry the public half of that key, it goes into the commit of step 4.
4. Start a branch. On it, make one signed commit that strips the loop's own files and gives each workflow its final
   triggers. The plan has the whole list, under H-905. Do not land the commit here: the checks here need the files it deletes.

   ```bash
   cd ~/workcell-v2 && git switch --no-track -c cutover refs/remotes/origin/main
   ```

   ```bash
   cd ~/workcell-v2 && git add -A && git commit -S -m "Cutover: remove the loop, switch on the final triggers"
   ```

5. v1's `main` has probably moved since you ran `setup-1`. Read what changed there, in case v2 needs the same fix. Then tie
   the two histories together with one signed merge that keeps v2's files. Without it the pull request would conflict, and
   GitHub runs no checks on a pull request that conflicts.

   ```bash
   cd ~/workcell-v2 && git fetch --no-tags v1 +refs/heads/main:refs/remotes/v1/main && git merge -S -s ours refs/remotes/v1/main -m "Merge v1 main, which v2 replaces"
   ```

6. Change the required checks of `omkhar/workcell` first (H-807). Today they come from workflows that v2 deletes. They would
   never report on this pull request, and it would wait for ever. From now until the merge, v1's own audit of its settings
   (`hosted-controls.yml`) would fail. It is not a required check, and the merge removes it.
7. Push the branch. Your clone already has v1 as a remote, with pushing switched off until now:

   ```bash
   cd ~/workcell-v2 && git remote set-url --push v1 https://github.com/omkhar/workcell.git && git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags v1 cutover:refs/heads/cutover
   ```

8. Open the pull request into `main` there. It asks for a title and a text. It shows v1's tree going and v2's arriving.

   ```bash
   gh pr create --repo omkhar/workcell --base main --head cutover
   ```

   v1's `main` accepts only signed commits, and this history meets that rule: each commit is either yours or a squash commit
   that GitHub signed. v1's `AGENTS.md` asks for more: a publishing script, and your own signature on every commit. Those
   rules are written for agents, and rest on files that this pull request deletes. This one pull request is made by hand.
   The first run of `gate` on it is the test of your cutover commit. If it is red, repair the branch and push again.
9. Merge it with **Create a merge commit**, as v1 does today. That keeps v2's whole history. v1's rules also ask for an
   approving review, which you cannot give yourself. So merge as you merge there today
   (`WORKFLOW-REVIEW.md` F8), or set the required approvals to zero in step 6. One blemish stays: the loop's commit subjects
   end in `(#N)`, and in `omkhar/workcell` GitHub links those numbers to v1's own pull requests.
10. Only now switch `main` to linear history and squash merges, which the H-807 checklist also asks for. If you switch
    first, v2 can arrive only as one squashed commit, and its history stays behind in the building site.
11. Wait until `gate` is green on the merged `main`. Then sign the tag `v2.0.0`, and push that one tag. **Never push with
    `--tags`:** your clone holds the checkpoint tags, and they do not belong in `omkhar/workcell`.

    ```bash
    cd ~/workcell-v2 && git fetch --no-tags v1 +refs/heads/main:refs/remotes/v1/main && git tag -s v2.0.0 refs/remotes/v1/main -m "Workcell v2.0.0"
    ```

    ```bash
    cd ~/workcell-v2 && git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags v1 refs/tags/v2.0.0
    ```

12. See that the release is published, and that the next scheduled run of `bump.yml` prints its plan. Then see that the
    first bump that falls due is opened by the App, merges by itself, and that its channel manifest is accepted by a
    released client (P7). Archive `omkhar/workcell-v2` only after that.

## 9. What protects what, and what does not

| Threat | Prevention | Detection |
|--------|------------|-----------|
| Anything the agent does reaches v1's users | It has no access to `omkhar/workcell`. This repository can publish no tag and no release: the tag rule has no exception, and GitHub publishes a release only on a tag. `setup-2` tries to push a tag | `settings.sh check` counts releases and drafts |
| A secret leaks from CI | There is none to leak. This repository never holds a secret, a GitHub App of its own or an environment. `bump.yml` does its plan and a dry run here, and nothing more. The App, the `bump` environment and the channel key are made in `omkhar/workcell`, after the cloud task is deleted (H-829) | `settings.sh check`: no secrets, no environments |
| The model says "done" when it is not | `gate` in hosted CI, on a real VM. Tree checks run before any repository code does | red check, no merge |
| The model changes the rules, the checks, or its own permissions | Allowlist, plus `guard`, plus your reviewed signature | `checkpoint.sh` stops at any locked change you did not sign, and at any difference between `main` and your kit |
| The model rewrites a check inside its own pull request | Both workflows load from the default branch, whatever the pull request contains | the same |
| The model pushes a workflow of its own, to forge a green check | The Actions policy refuses `push`, `pull_request` and `workflow_dispatch`. `setup-2` tries this very attack | `checkpoint.sh` lists every run that a forbidden event started, whatever its file and its result. It cannot see a run that was deleted, and GitHub hands out at most 1,000 runs per search, so after a long stretch the list can be cut short. `checkpoint.sh` prints a `WARNING` when the period holds 1,000 runs or more |
| The model ticks, rewrites, moves, hides or doubles a human gate, moves a heading, or takes a dependency on a gate out of a unit | `guard` needs your signature for each of these (section 5) | `checkpoint.sh` applies the same rules to every commit |
| The model accepts its own design decision, or rewrites one of yours | A decision counts only in `docs/adr/accepted/`, and that folder is locked | the same |
| The model clears its own halt | The log is append-only. The loop may add its five kinds of heading, and no other. A `RESUME` line needs your signature | the same |
| File-name tricks: case, Unicode, quotes, spaces, newlines, dashes, links, submodules, agent files | A plain character set, no dot or dash components, special files caught by shape and by name in any mix of capitals, links never free, no two files or folders that differ only in case | the same |
| A stale branch whose edit follows a file into a locked place when GitHub merges | Every pull request must sit on the live tip of `main`: `guard` checks it, and the ruleset makes GitHub check it again at merge time | the same |
| An old signed commit offered again | The same rule. Such a change must also be exactly one commit on that tip | `checkpoint.sh` lists it among what you signed. After a locked change the kit was not updated, so `preflight.sh` and `checkpoint.sh` report a difference |
| `main` is moved back to an older commit, and your signed changes vanish | The ruleset forbids force pushes, for everyone | `checkpoint.sh` remembers where this clone last saw `main`, and compares `main` with your kit before it asks you to sign |
| A rule is left in place and aimed at nothing | Only an administrator can do that | `settings.sh check` reads what each rule is aimed at, and asks GitHub which rules are in force on `main` |
| The model signs as you | The key is in your account. No agent runs there, and no code from the repository | `git log --show-signature` |
| Code that the model wrote runs beside your key | It runs on your Mac only as `loop` (section 6). `gate.sh` executes nothing in an account that holds `~/loopkit`. `gate-test.sh` writes its own Go files. A rebuilt kit holds only locked files | none. The rule is yours to keep |
| Something changes between the check and the signature | `land.sh` fixes one tree object, then judges, shows and signs that object | n/a |
| What you are shown differs from what is installed | `adopt.sh` reads each proposal once, from the commit on GitHub, and shows and installs those bytes. A locked file that holds a control character is refused. The pager ignores your own `LESS` options | `land.sh --reviewed` shows the fixed diff again, and warns of very long lines |
| Hooks, config, replace refs or look-alike tags that redirect git | Section 5, "What the scripts refuse to trust" | n/a |
| Tampered scripts reach your Mac | Nothing in your own account runs a file from the repository, the gates included (section 6). The one exception is `check-prompt.sh`, which runs command lines from the clone's locked `PROMPT.md` (section 5). The clone holds what you signed, plus your own edit, plus any draft that you accepted in `adopt.sh` and have not landed yet. So the script shows each line that your kit does not hold, and asks before it runs it. The kit changes only by `land.sh --reviewed`, with the bytes you signed | `preflight.sh` |
| An outsider interferes | Only collaborators can open pull requests, and that does not expire. The interaction limit keeps outsiders from issues and comments, for six months at a time | `settings.sh check` |

### What it rests on

According to the public docs, the Claude GitHub App holds these permissions:

| Permission | Access |
|------------|--------|
| Contents, Pull requests, Issues, Discussions, Workflows, Checks, Actions, Repository hooks | write |
| Administration | **read only** |

Everything in section 2 needs Administration. So the lock holds **as long as the cloud session uses the App's credential**.
If the Claude account was ever connected with `/web-setup`, cloud sessions hold your own `gh` token instead, which is an
administrator's. `START-HERE.md` step 5c tests for that once. Nothing can test it continuously. `checkpoint.sh` re-reads the
settings, and its signature checks do not depend on them.

### What it does not stop

| The agent can still | What limits the damage |
|---------------------|------------------------|
| Run any code it likes in the `gate` jobs, for up to 25 minutes, with network access | The job's token can only read a public repository. There are no secrets. Caches are read-only under this trigger |
| Make its own tests pass: code under test has root on the runner | Separate agents write tests and code; checkpoints; Phase 10. The lock protects the rules, not the quality |
| Go round a gate without touching it. `guard` protects only the step from a unit to the gate it names. The model can still tick that unit while the gate is open, take that unit out of the `deps` of the units behind it (U-203 without U-200 and U-201 no longer waits for H-103), move a unit below `## Cutover`, or add a new unit that leaves the dependency out | No rule can judge what a new unit means. The plan's changes are in every checkpoint's diff. Read them |
| Log a `PASS` that never happened, which also ends a streak of failures | The same. The gate still has to be green before anything merges |
| Close a `loop-halt` issue, so that the next run carries on | The App may write issues. Closed halt issues stay in the list, under **Closed**. After `six-failures` the log itself still halts the next run |
| Land a commit that you signed and then gave up on | Only while `main` stands still. `land.sh` says so when it gives up. You did read that very change once. A new `guard` run refuses the signature after two hours. But a green `guard` that the commit already has stays on it, and the App may disable a workflow or delete a run, so that no new run takes its place (reasoned, not tested). Do not count on the two hours: land any other change, which moves `main` |
| Push the head of a green pull request straight to `main`, if GitHub allows it | **Not tested.** GitHub's text suggests that it may. The tree at the tip is the one `guard` judged, so no locked file changes. `main` would then hold commits that are neither squashed nor signed, and `checkpoint.sh` stops at each one. It is a nuisance, not a break. `setup-2` does test a push of a commit that is in no pull request, and that must be refused |
| Fail a VM test in public | A cloud session offered no hypervisor when this was written, so a test meets the code for the first time in a public CI log. If that code was ported from v1, the log shows a weakness of released v1 before anyone can stop it. H-011 gives you the first look, in private, and the units that wire ported code in wait for it. Afterwards: section 7, `needs-you` |
| Let an onlooker guess why a unit halted with `needs-you` | The record is the same for a credential, a purchase, a legal reading and a weakness. A unit that only ports a v1 package needs none of the first three, so the guess is easy. It names a package and a day, nothing more. Treat such a halt as urgent |
| Cancel, re-run or delete workflow runs, or disable a workflow | A required check that never reports blocks the merge. It fails closed, and the loop halts. The exception is a commit that already has its three green checks. With `guard.yml` disabled no new run judges it, so it does not fail closed. That matters for a commit that you signed and then gave up on, above. A deleted run is gone from `checkpoint.sh`'s list too |
| Create check runs as the Claude app | The ruleset counts only GitHub Actions, and so does `land.sh` |
| Create a webhook, or a draft release | The repository is public already, so a webhook learns nothing new. `settings.sh check` shows it in a `NOTE`. A draft cannot be published without a tag, and `settings.sh check` counts drafts, so the next checkpoint stops |
| Create, move or delete anything under `refs/checkpoints/` | Rulesets cover branches and tags, and this is neither. So nothing trusts those copies. Your clone holds the originals, ignores what you did not sign, and puts the copies back at each checkpoint. Names that a Mac cannot fetch cost a `NOTE`. Whatever is parked there is downloaded at each checkpoint, however large. Section 2 has the one command that clears planted names away |
| Create branches, pull requests and issues | A branch named `mac`, with nothing after it, blocks your landings until it is deleted. `land.sh` says so, and `checkpoint.sh` sweeps it up |
| Write misleading text in the plan, the log or an issue | `START-HERE.md`: a halt issue may ask for only four things |

**Other limits:**

- **The Actions policy is new.** The kit's payload matches GitHub's published schema, but the feature's exact behaviour
  could only be read, not tried. `setup-2` step 4 is the test.
- **Free files still matter.** `README.md`, `docs/`, `go.mod` and the tests are free. A bad install command in the
  README would be as harmful as bad code. `checkpoint.sh` shows where changes are and what disappeared. Read them.
- **A poisoned plan.** `loop/state/` is free, so a confused iteration can mislead later ones. The damage is bounded
  by everything above.
- **A halt makes no sound.** The loop opens its halt issue with your own account, and GitHub sends no notice about your own
  activity. `START-HERE.md`, "What you do from now on", has the two remedies.
- **The second account shares your Mac.** It cannot reach your `gpg-agent`. It cannot read your files once you have run
  `chmod 700 ~`, which `START-HERE.md` has you do and test. As macOS makes a home folder, other accounts can read all of it
  except the few folders that macOS closes itself, such as Desktop, Documents, Downloads and Library. That would include
  your dotfiles, your other projects, `~/loopkit` and `~/workcell-v2`. The account can fill the disk, use the network, and
  write to shared folders such as `/Users/Shared` and `/tmp`. A macOS privilege-escalation bug is out of scope. It holds a
  Claude login, which code running there could misuse. From your own account, read only the files that the guides name in
  `/Users/Shared`, and judge your copy, not the original. Never write to a fixed name there. `loop` can put a link under any
  name first, and your copy would go through the link into your own files. A folder from `mktemp -d` is new and yours alone.
- **A refused hand-over leaves its objects behind.** `land.sh --from` unpacks the whole file into `~/workcell-v2/.git` before
  it judges the work. If it then refuses, the objects stay there until git prunes them. The script reads at most 256 MB. That
  bounds the file, not what it unpacks to. The command below clears the objects away. If git still warns about `.git/gc.log`
  afterwards, delete that file.

  ```bash
  cd ~/workcell-v2 && git gc --prune=now
  ```

- **`gpg-agent` caching.** While your passphrase is cached, any process in **your** account can sign. Prefer a short cache.
- **Nested virtualisation on hosted runners is not a promise.** GitHub's documentation calls it "technically possible" and
  "not officially supported". It also says that standard Linux jobs can run in more than one cloud, and step 4 sees only a
  handful of runs. If a later runner has no KVM, the job says `no KVM on this runner (infrastructure, not your change)`, and the
  loop tries again before it halts.

## 10. Review record

This kit was attacked before it was offered as a pull request. The author is an AI assistant. The reviewers were
separate AI agent sessions, given the files and no conclusions. No human has reviewed it yet: you are the first.
**The first three versions failed.** This is the fourth. Its reviewers judged it fit after small fixes, and what you hold has
those fixes.

| Version | Design | What broke it |
|---------|--------|---------------|
| 1 | A denylist matched against git's display output; scripts run from inside the repository | Nine of nine new attacks passed the guard. Four more made the Mac harness sign attacker-chosen content |
| 2 | An allowlist; scripts run from `~/loopkit`; one frozen tree; an unattended agent on the Mac in a sandbox | `guard` judged a merge base, not the merge. File tools were outside the sandbox. `.git` was trusted but writable |
| 3 | No unattended agent; a watched session in a clone of its own; a branch `v2` inside `omkhar/workcell` | See below |
| 4 | This one: its own repository, trusted workflow definitions, an Actions policy, a second macOS account | Nothing broke the design. The second table below lists what was found. Section 11 lists what is still unproven |

| Finding in version 3 | Severity | What changed |
|----------------------|----------|--------------|
| GitHub loads `pull_request_target` workflows only from the default branch, so a guard that lived on `v2` would never start | critical | The loop's branch is the default branch of its own repository |
| `land.sh --from` read a folder the agent could still write. A directory swapped for a link at the right moment published the maintainer's private key file | critical | The hand-over is one file, used only if it is a valid bundle |
| Starting a new session cloned into a path that a left-over process could write, which ran its code with the `gh` token | critical | No agent in the maintainer's account |
| `guard` refused every clone that `actions/checkout` makes, and the live test read that as proof that the lock worked | critical | The check was corrected; the live test has a positive control; the test stand-in imitates the action |
| In the shared repository the agent could publish a release on an existing tag, and use the owner's bypass on `main` | high | It has no access to that repository |
| The kit's tag rule turned v1's own audit red and would have burnt a release tag | high | Nothing is set on v1's repository |
| After `/web-setup`, cloud sessions hold an administrator's token | high | A warning, and a live test (step 5c) |
| Scheduled runs started on v1's `main` and loaded its `AGENTS.md` as instructions | high | Runs start on the loop's own `main` |
| The macOS units could not be done inside the sandbox, so the guide trained the maintainer to approve unsandboxed runs | high | A second account, with no sandbox to fight |
| A checkpoint stopped at the first bad commit; the recovery then installed a later one into the kit | high | Every problem is listed; `checkpoint.sh` copies nothing; recovery requires `preflight.sh` to be clean |
| A stale hand-over silently undid newer work | high | It must sit on the current tip |
| Three failures halted the loop for ever; parallel runs took the same unit | high | New halt rules; a unit is claimed by a `try:` pull request |
| The agent chose the signed subject, unseen, and could imitate the reviewed marker | medium | The subject is shown and cleaned; the marker counts only as the last line |
| Human gates were free text | medium | They need your signature |
| `go.mod` could switch checks off; tests could empty the enforced list | medium | More tree checks, all read before any code runs |
| Only the last 39 changed files were shown | medium | All are shown |

**Version 4 was reviewed in the same way,** by eight reviewers. Each had one surface: the lock, macOS portability, GitHub's
side, the signing scripts, the setup and checkpoint scripts, the loop's logic, the guides, and what publishing gives away.
All eight said "fit after small fixes". Together they reported about a hundred findings: one rated critical, six high, 37
medium and 57 low. Several reviewers found the same thing, so the table merges those. It holds every finding that anyone
rated high or critical, and every distinct medium one.

A sceptic re-tested every report that was rated critical or high, seven in all. That is one more session each, told to
refute the claim by running it again from scratch. None was refuted. Four were lowered: the missing Go from critical to
high, one of the two reports on the account rule to medium, and the two on bytes that hide a line to medium and to low.

| Finding in version 4 | Severity | What changed |
|----------------------|----------|--------------|
| The required check `gate-macos` could never go green. GitHub's Macs have no Go on the path, and the job set none up. Step 4 would have stopped, and nothing could have merged, the repair included | critical, then high | Both gate jobs set Go up with a pinned action, in the version that `go.mod` names. Unit U-002 ships as done. The gate formats with the `gofmt` of the Go it compiles with |
| Four human gates had the maintainer run agent-written code on the Mac, and did not say in which account. In the maintainer's own account, a test signed a locked change with the maintainer's key. The documented rebuild of the kit, followed by `all.sh`, led to the same place | high | One rule, in locked text: code from the repository runs on the Mac only as `loop`. The gate lines name the account. `gate.sh` executes nothing where `~/loopkit` exists. `gate-test.sh` writes its own Go files. A rebuilt kit holds only locked files |
| From gate H-829 on, unreviewed code in free paths would have run with the update bot's App key and the channel signing key, and the plan then carried both home | high | The building site never holds a secret, an App or an environment. H-829 moves behind the Cutover heading. `settings.sh` checks that no environment exists |
| One NUL byte hid an accepted decision and a RESUME line from `guard`, `land.sh --from` and `checkpoint.sh`, because git then calls the file binary | high | The rules read the files, not a diff. A NUL byte, or a byte outside printable ASCII in a judged line, is itself a reason to refuse |
| On macOS `grep` skips a line that holds an illegal byte, so `land.sh --from` would have signed an agent's own acceptance | high | `lib.sh` sets the C locale for every script that loads it |
| A gate could be closed in effect without touching its line: by a ticked twin, a moved heading, a rewritten `accept` line, or a unit that dropped its dependency on the gate | medium | Headings, fences, gate lines and their `accept` lines are compared in file order. A dependency on a gate that disappears needs your signature. Section 9 says what no rule can catch |
| An accepted decision could be rewritten, replaced or deleted, and "accepted" could be spelled a dozen other ways | medium | `docs/adr/accepted/` is locked by its path. No rule reads the text |
| "No tag, so no release" was false. The agent could publish a release on `loop-checkpoint-0`, or on a checkpoint tag of its own making | medium | Checkpoints are no longer tags on GitHub. The tag rule has no exception, and `setup-2` tests it |
| `settings.sh` never read what a ruleset or the policy was aimed at. All of them could point at nothing and still read "ok" | medium | It reads each target and condition, and the rules in force on `main`. It also counts deploy keys, webhooks, collaborators and environments |
| A signature withdrawn by Ctrl-C, a timeout or a red check stayed valid until `main` moved, and the agent could land that commit itself | medium | `land.sh` says so, and says that landing any other change cancels the commit. A new `guard` run also refuses a signature that is more than two hours old. Section 9 says why that is not to be counted on |
| `checkpoint.sh` signed a `main` that had been moved back and rebuilt. The only hint came after the signature, and its advice installed the older files | medium | It remembers where the clone last saw `main`, and it compares `main` with the kit before it asks |
| The final review obeyed `LESS` from the environment. With `-S`, everything beyond the right edge of the window was signed unseen | medium | The pager takes its options from the script alone, and long lines are announced |
| A carriage return printed as `?`, while YAML and Python read it as a line break. Live code could pass for the rest of a comment | medium | A locked file that holds a control character is refused. Other odd bytes are counted above the diff |
| Under bash 3.2 on a recent macOS the gate's failure text would have turned into question marks, and `paste` would have dropped enforced invariants without a word | medium | `gate.sh` works in the C locale too |
| Run a second time, `setup-1` could publish a stale, empty or incomplete kit and say DONE. Run after the merge, it told the maintainer to delete the repository | medium | Every run compares the signed branch with the kit, byte for byte. After the merge it says so, and points to `setup-2` |
| The cutover as written could not be merged: v1's `main` keeps moving, so the pull request conflicts and no check runs. It would also have carried the building site's `SECURITY.md` home | medium | Section 8, "Bringing v2 home", is new. A unit of Phase 9 drafts v2's own `SECURITY.md`. H-905 lists what else must go |
| A planned daily dry run would have left a draft release, which every checkpoint reports as an incident | medium | The dry run stops before the draft |
| The four checkers tested the kit's old copies and not the edit. One never read the prompt that it claimed to test | medium | They read the tree in the current folder, and print each path. The model checks that the prompt still holds each sentence it models |
| SPEC S14 cannot hold for code that only a VM can test: the suite meets code ported from v1 for the first time in a public log | medium | The units that wire such code in wait for H-011, the private first look. The rest is admitted in section 9 |
| The marker `<unit>: private` told the public which package of released v1 has an unfixed weakness, and since when | medium | One neutral reason, `needs-you`, for everything that cannot be said in public or that only the maintainer has |
| The rules for file names never reached the agents that create files, the local gate did not check them, and one red `guard` threw the whole unit away | medium | The rules are in `CLAUDE.md`, which every agent loads. The orchestrator runs `guard.sh` before each push, and may repair once |
| A later unit protected only the job name `gate`, although `gate-macos` is required and `merge` lands the work | medium | The unit names all three |
| A run killed by a usage limit was booked as the unit's failure. A closed terminal or a dead run left a pull request that nothing would finish, and every message said "wait" | medium | The first abandoned run costs no try. The scripts also clean up on a hang-up. The messages list the open pull requests, and say when to close one |
| "No access to your files" was wrong for a macOS home folder as it comes | medium | `chmod 700 ~`, and a test that it worked |
| Step 5b chose a network level that had to fail step 5c. The remedy admitted one host where GitHub documents a wildcard | medium | Custom network access with the two domains from the start. Step 5c asks for the check by name |
| The Mac section could not be followed to the letter: no shared clipboard, a command that wiped the inputs of S-1016, and advice that threw finished work away | medium | The section is rewritten |
| The 57 low ones: wrong or missing sentences in the guides, error paths that failed open only with a broken tool, messages that sent the reader the wrong way, a file and a folder that differ only in case, a key export that could publish every address on the key, a test that erased the folder it was given | low | Fixed where a fix exists. The rest is admitted in section 9 or section 11 |

One decision of the fix round was withdrawn. To close the direct push of a green head (section 9), it first added "require
signed commits" to the rules on `main`. GitHub's documentation says that unsigned commits on the head branch can block a
squash merge. Every commit the agent pushes is unsigned, so the rule would have blocked every pull request of the loop.

**The fixes were reviewed once more,** by six reviewers: the lock, the signing scripts, the setup and checkpoint scripts, CI
with the loop's logic, the guides, and what publishing gives away. Each had the earlier findings for its surface, and tested
them again. That made 151 tests, because some findings were on more than one list. 127 were fixed, 21 partly fixed, and 3 no
longer applied. All six said "fit after small fixes". They reported 58 new findings: two rated critical and one high, 12
medium and 43 low. The first three are one and the same fault, which three reviewers found independently. A sceptic tested
each of the three reports again, and confirmed it. Much of what this round found had been made by the fix round itself.

| Finding in the fixed version 4 | Severity | What changed |
|--------------------------------|----------|--------------|
| The fix round's own guide had the maintainer copy a log to a fixed name in `/Users/Shared`. The second account can put a link under that name first. The copy then overwrites a file of the maintainer's, such as a script of the kit, and the next command runs it beside the key | critical | The log goes into a new folder from `mktemp -d` each time. One rule, in locked text: never write to a fixed name there |
| With `push.followTags` in the maintainer's own git settings, `setup-2` published the first checkpoint as a real tag, before the tag rule existed. "No tag, so no release" was false again, and nothing noticed | medium | The scripts switch that setting off for every git call. `settings.sh` reads back that GitHub holds no tag at all. The suite runs with the setting on |
| Two planted names under `refs/checkpoints/` stopped `checkpoint.sh` and `setup-2` for good on a disk that ignores case | medium | The copies are fetched apart from `main`, and a failure there is a `NOTE`. One fixed command clears planted names away (section 2) |
| Gate H-703 put the maintainer's Developer ID, and Apple's notarisation, on a binary that only the second account had seen | medium | The test binary is signed ad hoc, as `loop`. The Developer ID signs release builds only, after the cutover |
| A second run of `setup-1` could present an outsider's look-alike pull request as the one to merge | medium | It lists only pull requests from the repository itself. Before the first push it asks GitHub to take pull requests from collaborators only. Step 3 says what to look at |
| Three Unicode line breaks (U+0085, U+2028, U+2029) could still pass a live workflow job off as the rest of a comment | medium | They count as control characters, so both scripts refuse the file |
| `check-prompt.sh` ran command lines from the clone, which can hold a draft that was accepted in `adopt.sh` and not signed yet | medium | It shows each line that the kit does not hold, and asks before it runs anything |
| Since the secrets left the building site, no `accept` line asked that a bump ever opens, merges and reaches a client | medium | B-825 tests those steps against a stand-in. H-905 is not done, and the building site is not archived, until the first real bump has reached a released client |
| The command given for H-703 ran 5 of the 14 invariants. H-011 needed an adapter for v1 that no unit builds | medium | Section 6 gives the command for the whole suite. It says how the adapter is made, and that it stays off GitHub |
| "Wait two hours" did not cancel a signature that was withdrawn. The limit binds only a new `guard` run | medium | The guides and `land.sh` say: land any other change. Waiting is not enough |
| This record claimed a review whose result it did not give | medium | This paragraph and this table |
| The 43 low ones: a failed call that was taken for a verdict, a stand-in that failed more politely than the real `gh`, refusals that did not say what to do next, git settings of the maintainer's own that changed what a script printed or kept, a checker that went red on an honest change to the plan, and counts and sentences that disagreed between files | low | Fixed where a fix is a few lines. The rest is admitted in section 9 or section 11 |

**The last fixes had one more review.** Four reviewers, one for each group of changed files, read only what had changed since
the round above, and ran it. All four said "fit after small fixes". None found a changed line of script that fails open. They
reported 19 findings, several of them more than once: three rated medium and 16 low. A sceptic tested the three again,
confirmed each, and lowered each to low. Nearly all were sentences in the new guide text. The three were these. A new command
in section 2 deleted the maintainer's own checkpoint copies on GitHub when it was run in a fresh clone. "Land any other
change" landed the withdrawn change as well, because that change was still in the clone. And this record still held two
placeholders. All 19 were fixed, or admitted in section 11. Every test was then run again. Nobody has reviewed that last
handful of changes.

Three lessons. Enumerate what is allowed, not what is forbidden, and treat every error as a refusal. When patches
keep finding new holes in one component, remove the component. And question the outermost assumption first: most of
three versions' trouble came from sharing a repository, and an account, with things worth protecting.

## 11. What was and was not tested

**Tested** with more than 700 scripted checks (`loop/test/suite.sh`) and more than 200 gate cases
(`loop/test/gate-test.sh`) on Linux, under bash 5 and again with **bash 3.2.57, a BWK awk and bsdtar**. Those are close to what
macOS ships, but not the same. Apple's awk is an older version with changes of its own, and the bash that was tested is
linked to another C library. Every test is in the kit, and `START-HERE.md` step 0 runs the first on your Mac.

- The suite uses real throwaway GPG keys. A stand-in for GitHub (`loop/test/fake-gh`) performs real merges, enforces the stored
  ruleset and Actions policy, loads workflows only from the default branch, runs `guard` in a clone made the way
  `actions/checkout` makes one, and answers every settings query from stored JSON through the caller's own `jq` expression.
- The suite passed on a small stand-in for v1, and again on v1's real tree.
- The scripts were also tested by mutation: copies were broken on purpose, one rule at a time, to see whether a test
  notices. For `gate.sh` as reviewed in version 4, the cases caught all but two kinds. Those two only move a step to a later
  point where nothing could have interfered, so they decide nothing differently. For what the fix round added, 153 more
  broken copies were made: 15 of `gate.sh`, 41 of the setup, settings and checkpoint scripts, and 97 of the lock and signing
  scripts. The tests caught 150. The other three change nothing that a test could observe. The first rounds also showed
  tests that proved nothing, and those were sharpened.
- `gate.sh` was run by hand on the kit as shipped, in the shape of both CI jobs. No kit test does that any more, because
  `gate-test.sh` runs no Go code but its own.
- The part of `gate.sh` that reads `go.mod` was compared with `go` itself on 7,000 generated files. It never accepted a file in
  which `go` sees a `replace`, `exclude` or `ignore` directive, or another module path. The two disagreed only about
  malformed tool paths, which `go` itself refuses to build.
- The JSON payloads, and the request bodies that `settings.sh` builds, validate against GitHub's published API description.
- The deny rules were tested against the documented matching rules, not against Claude Code itself (`check-deny.py`).
- Every `gh` flag and field was checked against `gh` 2.89. Every command block in the guides was parsed under zsh 5.9 and both
  bash versions.
- The procedures of sections 6 and 8 were followed to the letter against the stand-in: accepting a decision, a gate's report
  from the second account, a rebuilt kit, a new Mac, a renewed key, a new key, broken checks, a rewritten history, and the
  git commands of "Bringing v2 home" with a v1 `main` that had moved. The incident recovery is part of the suite.
- Reviewers of version 4 ran the whole suite on a case-insensitive, case-preserving file system, with the macOS-like tools.
  It passed, and it passed there again after the last fixes.
- The whole suite was also run with some fifty popular git settings in the maintainer's global configuration, for the
  scripts that load `lib.sh`. `setup-1` does not. Its first run was tried under them by itself, and passed. Among them were
  `push.followTags`, `fetch.prune`, `fetch.pruneTags`, `commit.gpgSign`, `tag.gpgSign`, `log.showSignature`,
  `diff.noprefix`, an external diff program, `core.autocrlf`, `submodule.recurse`, `color.ui = always` and a log format of
  one's own. It passed. On the kit as it was before the last fixes, the same run showed the published tag of section 10. The
  suite itself now always runs with `push.followTags` and `log.showSignature` on.
- The command that hands a log back through `/Users/Shared` was run with planted links, under zsh and both bash versions,
  with another user as the planter. One run repeated it 120 times against a process that planted links as fast as it could.
  The links' targets stayed untouched. The two `--prune` commands of section 2 were run against planted names that hold
  `$(...)`, quotes and semicolons.
- Reviewers of version 4 fed 900,000 generated names to the path filter, under three awks and an independent model in
  Python. mawk, the BWK awk and the model agreed byte for byte. The third awk, goawk, differs on a trailing carriage return.
  Neither the runner nor the Mac uses it.
- For the BSD tools those reviewers read Apple's published sources, release by release: `grep`, `paste`, `tr`, awk, bash and
  the C library, among others. Two of the findings in section 10 came from that reading. Nothing ran on a real Mac.

**Not tested:**

- Any real `claude` run, in the cloud or on the Mac. So Claude Code has never loaded this `.claude/settings.json` or these
  agents.
- Whether the cloud's GitHub proxy passes the two reads of step 5c on to GitHub. A refusal by the proxy looks like a pass. For
  part 1 that is still good news, because a path that the proxy refuses to read is one it will hardly let through to change.
- The scheduled task and its triggers.
- **GitHub itself.** Every call was written from GitHub's documentation and API description. `setup-2` reads each setting back
  and then attacks the lock, so that a mistake shows up before the loop starts.
- Whether check runs from `pull_request_target` workflows attach to the pull request's head commit in the way `setup-2` reads
  them. If not, step 4 stops with `THE LOCK IS NOT PROVEN`.
- Whether a merge made by the workflow token fires the "pull request merged" trigger. The hourly run covers the case
  where it does not.
- Whether a squash commit shows as Verified, with `web-flow` as its committer. `checkpoint.sh` depends on this,
  and stops loudly if it is not so.
- Whether `actions/setup-go`, at the pinned commit, installs the Go that `go.mod` names on GitHub's Linux and Mac runners. The
  commit was read from upstream's tag, and its `action.yml` was read at that commit. Step 4 finds out.
- KVM on real runners. Step 4 finds out, but from a handful of runs. GitHub can place a later job on another kind of machine.
- Whether GitHub accepts a push to `refs/checkpoints/`. If it does not, the scripts print a `NOTE`, and your checkpoints live
  in your clone alone.
- Whether GitHub lists `bypass_actors` as an empty list for you. `settings.sh` counts a missing list as none. GitHub leaves the
  list out for a caller who may not edit the ruleset, and for such a caller the reads of deploy keys, webhooks and
  collaborators fail.
- Which status GitHub answers when it refuses to merge the bad change of step 4. `setup-2` takes 403, 405, 409 and 422 for a
  refusal. On anything else it stops with `THE LOCK IS NOT PROVEN`, and prints what `gh` said.
- `gh run watch`. `land.sh` uses it to wait until a failed run has ended, because `gh` hands out no log before that. If it
  fails, or if the check was cancelled or timed out and did not fail, `last-failure.txt` holds only the table of checks, and a
  line that says `failed to get run`. Nothing else depends on it.
- The BSD versions of `sed`, `mktemp`, `cp` and `chmod`. The three Unicode line breaks are counted with `sed`, and the log is
  handed back with the other three. Both were tested with the GNU tools only.
- Whether GitHub lets the head of a green pull request be pushed straight to `main` (section 9).
- The setting that keeps pull requests to collaborators, and the reads of deploy keys, webhooks, collaborators and
  environments. They were written from the API description, like the rest.
- Whether the scheduled task's trigger (step 5d) makes a webhook in the repository. If it does, `settings.sh` shows it in a `NOTE`.
- Whether GitHub offers targeting by workflow path here. Its API description says that it can be unavailable. Then
  `settings.sh apply` stores the policy without the condition, and such a policy covers every workflow file.
- BSD `sed`, `grep`, `find`, `sort`, `tr` and `comm` themselves, and APFS. Step 0 finds out.
- What a UTF-8 locale does to bash 3.2, `grep`, `paste` and `sed` on a real Mac. The scripts now set the C locale, which
  should make the question moot.
- What GitHub does in "Bringing v2 home" (section 8): the settings of `omkhar/workcell`, the pull request, the merge and the
  release. Those steps were checked against v1's files, not against its live settings.

## 12. Files

| Path | Purpose |
|------|---------|
| `README.md`, `SECURITY.md` | What a visitor reads first; how to report a weakness, and who signs what here |
| `loop/START-HERE.md`, `REFERENCE.md` | The guide, and this file |
| `loop/SPEC.md` | Invariants, architecture, budgets and rules |
| `loop/PROMPT.md` | The instruction for each iteration |
| `loop/WORKFLOW-REVIEW.md` | Review of v1 workflows, bumping and process; input to Phase 8 |
| `loop/free-paths.txt` | The allowlist |
| `loop/state/` | `PLAN.md`, `LOG.md`, `BLOCKED.md`, `PARKED.md` and later `FINDINGS.md`. With `loop/baseline/ci.tsv`, the loop's only free files under `loop/` |
| `loop/lib.sh` | Shared helpers: path filter, signature checks, comparison with the kit |
| `loop/gate.sh`, `guard.sh` | The gate; the lock |
| `loop/setup-1-open-pr.sh`, `setup-2-after-merge.sh`, `settings.sh`, `preflight.sh`, `baseline-ci.sh` | Setup and settings, on the Mac |
| `loop/land.sh`, `adopt.sh`, `checkpoint.sh` | Your signature, on the Mac |
| `loop/github-main.json`, `github-tags-all.json`, `github-actions-policy.json`, `PR-BODY.md` | Inputs to the scripts above: two rulesets, the Actions policy, and the text of the kit's pull request |
| `loop/test/` | The tests, and the stand-in for GitHub |
| `.claude/agents/`, `.claude/settings.json`, `CLAUDE.md` | Eight subagents; model order and deny rules; project memory. The kit carries the settings as `loop/claude-settings.json`, and `setup-1` gives them their real name |
| `.github/workflows/ci.yml`, `guard.yml`, `.github/zizmor.yml` | The harness on GitHub. `ci.yml` already holds what unit U-002 asks for, so that unit ships as done |
| `.github/maintainer.asc`, `.fpr` | Your public key and its fingerprint, written by `setup-1` |
| `.gitignore` | Among other things it keeps `loop/private/`, scan results and `.claude/settings.local.json` out of git |
| `cmd/`, `internal/`, `go.mod` | Unit U-001, shipped with the kit so that the first CI run compiles real Go |
| `docs/adr/`, `docs/adr/accepted/` | Design decisions. The first folder is free. The second is locked, and holds the ones you have accepted. ADR-002, which is decision H-104, ships there |
| `LICENSE`, `NOTICE`, `CODE_OF_CONDUCT.md`, `CITATION.cff` | Kept from v1 as they are, and locked. They are not in the archive you unpack: `setup-1` copies them into `~/loopkit` |
| `_legacy/` | Code and data of v1, kept for reference. `setup-1` makes it. It is free, it is not compiled, and U-905a deletes it |
| `~/.workcell-loop/` (not in the repository) | Scratch files, and `last-failure.txt`, the log of the last failed landing |
| `refs/checkpoints/` on GitHub (not a file) | The copies of your checkpoints (section 2) |

Since version 4 was reviewed, `loop/github-tags-checkpoint.json` is gone, and `docs/adr/002-workspace-default.md` has moved to
`docs/adr/accepted/`.
