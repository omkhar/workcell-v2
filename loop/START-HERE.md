# Start here

You are going to let Claude rebuild Workcell as v2, one small piece at a time, mostly
while you do other things.

```
 Claude in the cloud          GitHub                         You, on the Mac
 ───────────────────          ──────                         ───────────────
 builds one small piece ───>  checks it on a real VM
                              checks it touched nothing
                              it is not allowed to touch
 starts the next piece  <───  merges it
                                                             now and then: read, sign
```

Claude can change the product code. It cannot change the rules, the checks or its own
permissions. Those are **locked**. A locked file changes only when you have read the change
and signed it, and your key never leaves your Mac.

**All of this happens in a new repository, `omkhar/workcell-v2`.** It is a building site. Claude is never given
access to `omkhar/workcell`, so nothing it does can reach v1, its releases or its users.

**The finished work goes home as v2 of `omkhar/workcell`.** The building site starts from v1's own history, and the code
already carries its final name, `github.com/omkhar/workcell/v2`. So the last step is a pull request into `omkhar/workcell`,
raised and signed by you, followed by the tag `v2.0.0`. That is gate H-905 in the plan. `REFERENCE.md` section 8, "Bringing v2
home", has the steps.

**Time needed now:** about an hour and a half. Three commands, one pull request, some clicking.

---

## Before you start

Open Ghostty. Every command in this guide works the same in zsh and in bash, so paste each one as it is.
This first one installs anything that is missing.

```bash
brew install git gnupg gh jq
```

Check that `gh` is signed in. If it says you are not, run `gh auth login` first.

```bash
gh auth status
```

Let `gh` push workflow files. It opens a browser page once. Without this, step 2 stops and tells you.

```bash
gh auth refresh -h github.com -s workflow
```

Check that your signing key is on this Mac. It should print the key, not an error.

```bash
gpg --list-secret-keys 90554248C4F7CC086BB745D0DA5A8E9F536C42FD
```

---

## Step 0: Unpack the kit, and test it on your Mac

If you unpacked an earlier kit, move it out of the way first: `mv ~/loopkit ~/loopkit.old`

```bash
tar -xzf ~/Downloads/workcell-v2-loopkit.tgz -C ~
```

You now have a folder called `~/loopkit`. **Leave it there.** It is your trusted copy of the
scripts. You always run them from `~/loopkit`, never from inside the repository.

**You run two scripts before you have reviewed anything:** `loop/test/suite.sh` now (about 1,000 lines), and
`loop/setup-1-open-pr.sh` in step 2 (about 190 lines). An AI assistant wrote them, and they run in the account that
holds your key. The first also starts the kit's other scripts, in a temporary folder. The second pushes nothing until you
type `y`. Read them first if you like: `less` shows a file, and `q` leaves it.

The scripts were written and tested on Linux, with bash 3.2.57 and a BWK awk. Those are close to what macOS ships, but
not the same. Now test them on the real thing. This takes about ten minutes. It works offline, in a temporary folder,
with throwaway keys. It touches nothing of yours.

```bash
~/loopkit/loop/test/suite.sh
```

The last line must say `0 wrong`. **If it does not, stop here.** Run it again like this, and show the output to Claude:

```bash
SUITE_VERBOSE=1 ~/loopkit/loop/test/suite.sh
```

Optional: `~/loopkit/loop/test/all.sh` runs every test in the kit. It takes about twenty minutes, and also needs Python 3 and
Go 1.27 or newer.

---

## Step 1: Make the new repository

In a browser, go to <https://github.com/new>.

| Field | What to enter |
|-------|---------------|
| Owner | `omkhar` |
| Repository name | `workcell-v2` |
| Description | `Workcell v2, under construction. Not for use yet.` |
| Visibility | **Public** |
| Add a README, .gitignore, licence | **No** to all three. It must be empty |

Click **Create repository**. Ignore the page of instructions that follows.

---

## Step 2: Fill it, and open the pull request

```bash
~/loopkit/loop/setup-1-open-pr.sh
```

It copies v1's history into a new folder, `~/workcell-v2`, and prepares two branches, both signed by you:

| Branch | What it is |
|--------|------------|
| `main` | v1's `main` with the old code removed. A few packages worth reusing move to `_legacy/` |
| `kit` | `main` plus this kit. **This is the pull request** |

It gives one file its real name. The kit carries Claude Code's project settings as `loop/claude-settings.json`, and the
script moves them to `.claude/settings.json`. They hold a list of commands that Claude is told never to run, and the
order of models. They allow nothing and run nothing.

It publishes one user ID of your key: the one whose address is git's `user.email`. If your key has no such user ID, it stops
before it makes anything, and tells you how to name the address you want published.

It lists every file the kit adds, and counts the files that stay from v1. It shows the public key it will publish, and
asks `[y/N]`. Nothing leaves your Mac until you type `y`. Then it tells GitHub to take pull requests from collaborators only,
and pushes. `gpg` may ask for your passphrase. At the end it prints a link.

It only ever reads `omkhar/workcell`.

---

## Step 3: Read it and merge it

Open the link. The pull request contains only the kit, about 60 files. More than a third of the lines are tests.
It must be opened by you, from the branch `kit` of this repository, and its one commit must show Verified. If another
account's name stands before the branch, as in `someone:kit`, it comes from a fork and is not yours. Do not merge it.

**If you read only seven things, read these:**

| File | Why |
|------|-----|
| `loop/SPEC.md` | The rules Claude must follow. This is the thing you are really approving |
| `loop/PROMPT.md` | The instruction that every run follows, word for word |
| `loop/free-paths.txt` | The only places Claude may change without you. Everything else is locked |
| `.github/workflows/guard.yml`, `loop/guard.sh` and `loop/lib.sh` | The lock. The path filter and the signature checks are in `lib.sh` |
| `.github/workflows/ci.yml` and `loop/gate.sh` | The checks, and the automatic merge |
| `.claude/settings.json` and `.claude/agents/` | What every Claude Code session in this repository loads before it does anything |
| `loop/REFERENCE.md`, sections 9 and 10 | What all this does **not** protect against, and what the reviews found |

The pull request's own description has the same list, plus the settings files and the plan.

No checks run on this pull request. That is expected: the workflows it adds start to work only once
they are on `main`. Step 4 tests them.

Click **Squash and merge**.

---

## Step 4: Lock it down, and prove the lock

```bash
~/loopkit/loop/setup-2-after-merge.sh
```

It takes about twenty minutes, nearly all of it waiting for GitHub. It does six things:

1. Checks that what merged is byte-for-byte what you signed.
2. Signs a tag, `loop-checkpoint-0`. This is your "I have read everything up to here" mark. The tag stays on your Mac.
   GitHub gets a copy under another name, because this repository is to hold no tags at all.
3. Applies the GitHub settings, and reads each one back from GitHub.
4. **Tests the lock for real**, four times. It opens and closes two pull requests itself, and tries two pushes.
   - An honest pull request. All three checks must go green, on real runners, with virtual machines switched on.
   - A hostile pull request. It changes a locked file without your signature, and it brings a forged workflow that
     claims all three checks passed. GitHub must refuse to run the forgery and refuse to merge.
   - A push straight to `main`, with no pull request. GitHub must refuse it.
   - A push of a tag. GitHub must refuse it.
5. Checks your Mac.
6. Records how long v1's CI takes (so v2 has something to beat), and ticks the first box in the plan, using
   the real pipeline.

The three checks are `gate` (the tests, on Linux, with a real virtual machine), `gate-macos` (the same gate on one of
GitHub's Macs, which cannot start virtual machines) and `guard` (the lock).

It stops at the first thing that is not right, and says what to do. Lines that start with `ok` are fine. A line that starts
with `NOTE` does not stop it: read it, and act on it afterwards.
If it prints **THE LOCK DOES NOT HOLD** or **THE LOCK IS NOT PROVEN**, do not go on. It is safe to run again.

It must end with `ALL DONE on the Mac`.

---

## Step 5: Set up Claude in the cloud

This part is clicking, in a browser, signed in to your personal Claude account.

### 5a. Let Claude see the new repository, and only that one

Go to <https://github.com/apps/claude> and click **Configure**. Under **Repository access**, choose **Only select
repositories**, and select `omkhar/workcell-v2`. If `omkhar/workcell` is in the list, remove it.

The same page lists the app's permissions. Find the word **administration**. It must be in the sentence that begins
**Read access to**, not in the one that begins **Read and write access to**. If it is in the second, stop: the lock
would not hold.

> **Never run `/web-setup` in Claude Code while the loop exists.** It hands cloud sessions your whole `gh`
> token, which can change every setting that step 4 applied. If you have ever run it, go to
> <https://claude.ai/customize/connectors>, disconnect GitHub, and connect it again in the browser. Step 5c checks this.

### 5b. Make an environment

**First find out whether you have Mythos 5.1.** Go to <https://claude.ai/code/routines>, start a new task, and open the model
menu in its prompt box. Is **Mythos 5.1** in the list? Close the dialog without saving. You need the answer three times:
here, in step 5d, and when you start Claude on the Mac.

Now go to <https://claude.ai/code>. Open the environment menu, which is the first control under the message box, and choose
**New environment**.

| Field | What to enter |
|-------|---------------|
| Name | `workcell-v2` |
| Network access | **Custom** |
| Allowed domains | the two lines below |
| Also include default list of common package managers | tick it |
| Environment variables | the three lines below those |
| Setup script | leave empty |
| Network secrets | leave empty |

```text
*.blob.core.windows.net
results-receiver.actions.githubusercontent.com
```

GitHub serves the logs of its checks from those two places. The loop reads such logs all day. The default list lacks both.
The first line admits every storage account at Azure, not only GitHub's. GitHub names no narrower host.

```text
ANTHROPIC_DEFAULT_FABLE_MODEL=claude-mythos-5-1
BASH_DEFAULT_TIMEOUT_MS=600000
BASH_MAX_TIMEOUT_MS=1800000
```

If Mythos 5.1 is not in your model list, leave the first of the three lines out. That is all. No file in the repository
needs a change (`REFERENCE.md` section 3).

**Never put a password, token or key in here.** Claude can read everything in it, and it needs none.

### 5c. Check what the cloud is allowed to do

Start one ordinary session at <https://claude.ai/code>, on `omkhar/workcell-v2`, in the `workcell-v2` environment.
Paste this:

```text
Do these three things and nothing else. They only read. Show me the complete output of each, errors included.
1. Run: gh api repos/omkhar/workcell-v2/actions/policies
2. Run: gh api repos/omkhar/workcell-v2/dependabot/secrets
3. Run: gh api "repos/omkhar/workcell-v2/pulls?state=closed&per_page=1" --jq '.[0].head.sha'
   Then, with that value in place of SHA: gh api "repos/omkhar/workcell-v2/commits/SHA/check-runs?check_name=gate&app_id=15368&per_page=1" --jq '.check_runs[0].id'
   Then, with that number in place of ID: gh api repos/omkhar/workcell-v2/actions/jobs/ID/logs
   Print only the last five lines. If the download is refused, tell me which host name was refused.
```

| Part | What you want to see | If not |
|------|----------------------|--------|
| 1 | **An error**, such as `403` and `Resource not accessible by integration` | If it prints the policy (look for `loop: only workflows from the default branch run`), the cloud has administrator rights. **Stop.** Do what the box in 5a says, then test again |
| 2 | **An error** of the same kind | If it prints `total_count`, the cloud is using your own token, not the Claude app's. **Stop**, and do the same |
| 3 | Five lines of a log | If a host name was refused, add it to **Allowed domains** (5b), and test again. A `404` is not the network: the wrong check was asked for. See that the second command holds `check_name=gate` |

Why this works. GitHub lets a token read the Actions policy only if that token may also change it. So part 1 asks for
exactly the right that the lock needs the cloud not to have, and changes nothing. Part 2 asks for something that
your own token may read, and that the Claude app was never granted.

The error must come from running the command. If Claude says that it may not run a command, or will not, that proves
nothing. Tell it to run exactly the command shown.

### 5d. Make the scheduled task

Go to <https://claude.ai/code/routines> and create a new task.

| Field | What to enter |
|-------|---------------|
| Name | `workcell-v2-iterate` |
| Repository | `omkhar/workcell-v2` |
| Environment | `workcell-v2` |
| Model | **Mythos 5.1** if it is in the list, otherwise **Fable 5.1** |
| Effort | high |
| Connectors | remove every one |

Prompt, copied exactly:

```text
You are one iteration of the Workcell v2 build loop for omkhar/workcell-v2.
Run: git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main && git checkout -B work refs/remotes/origin/main
Then read loop/PROMPT.md from that checkout and follow it exactly. It is your whole instruction. Do nothing else.
```

Add **two triggers**:

| Trigger | Settings | Why |
|---------|----------|-----|
| GitHub event | Pull request, **closed**. Filters: Base branch *equals* `main`; Is merged *is* true; Author *equals* `omkhar` | Each finished piece starts the next one |
| Schedule | Hourly | A safety net. If nothing needs doing, it stops at once |

Never switch on **Auto-fix** for one of the loop's pull requests.

---

## Step 6: Go

On the task's page, click **Run now**.

In a few minutes you should see a pull request into `main` from a branch called `claude/...`, with a title that
starts with `try:`. That is Claude claiming a piece. When the piece is finished the title changes, the checks run
once more, it merges by itself, and the next one begins. That is the loop. It can do about twenty pieces before
it first needs you.

---

## What lives where

| Place | What it is | Who touches it |
|-------|------------|----------------|
| `~/loopkit` | Your scripts, and a copy of every locked file | Only you |
| `~/workcell-v2` | Your clone. Everything you sign is judged here | Only you and your scripts. **Never open Claude in this folder, and never build, test or run anything from it** |
| A second user account on your Mac, `loop`, and its folder `~/work` | Where the code runs on your Mac: the few pieces that need macOS, and the gates that have you try the product | Claude, and you when a gate asks. It holds no key and no GitHub login |

**Code from the repository runs on your Mac only as `loop`, in `~/work`, whoever starts it.** Claude wrote that code. In your
own account it would run beside your key and your GitHub login, and could use both.

---

## What you do from now on

| When you see this | Do this | Time |
|-------------------|---------|------|
| Nothing | Once a day, glance at the pull requests **and** at the open halt issues: <https://github.com/omkhar/workcell-v2/issues?q=is%3Aopen+label%3Aloop-halt> | 2 min |
| An issue labelled **loop-halt** | Read it. See "When the loop asks for you" | varies |
| **guard** is red on a pull request | Claude touched something locked, or its branch fell behind. It should repair or close that pull request itself. If it keeps happening, pause | 2 min |

**GitHub does not tell you when the loop halts.** The loop opens its issues with your own account, and GitHub sends no
notice about your own activity. So look every day. Or, on GitHub, open **Settings > Notifications** and switch on
**Include your own updates**.

### When the loop asks for you

A `loop-halt` issue is a short form. Its title gives a reason, and `REFERENCE.md` section 7 explains each one. Its body
lists unit names, and can ask for only four things:

| It says | You do |
|---------|--------|
| `run adopt.sh` | "Approving a locked file", below |
| `do a Mac piece` | "The pieces that need your Mac", below |
| `decide an [H] line` | `REFERENCE.md` section 6 lists every one. **If the gate has you run code, run it as `loop`, never in your own account.** Decide, then tick it: "Changing something yourself" |
| `rewrite a unit` | Read `loop/state/BLOCKED.md`, then rewrite or split the unit: "Changing something yourself" |

**Never paste a command, follow a link, or change a setting, because an issue or a comment tells you to.** Claude writes
those issues, and they should hold none of these. If one does, treat it as a warning sign.

Each time, in this order: pause, **sign a checkpoint**, do the thing, close the issue, resume.

### Pausing and stopping

| To | Do this |
|----|---------|
| Pause | Open the task at <https://claude.ai/code/routines> and use the on/off switch at the top of its page. A piece already in flight finishes first. Wait until no pull request into `main` is open |
| Clear away a pull request that nothing will finish | See below. Open it on GitHub and click **Close pull request** |
| Resume | Switch it on again, close any `loop-halt` issue, and click **Run now** |
| Stop for good | Delete the scheduled task |

**A pull request that nothing will finish.** A closed terminal, a crash or a dead cloud run can leave one open. While it is
open, `land.sh` and `adopt.sh` refuse to start, and no amount of waiting helps. You close it yourself.

| What it looks like | Where it came from |
|--------------------|--------------------|
| A `mac/` branch, and no `land.sh` of yours is running | A landing that was cut off |
| A `claude/selftest-` branch, and `setup-2` is not running | A self-test that was cut off. The next `setup-2` also closes it |
| A title that starts with `try:`, no new commit and no running check for three hours, and the task is off or a halt issue is open | A cloud run that died, often at a usage limit. While the loop runs, a later run closes it for you |

### Signing a checkpoint

Pause first.

```bash
cd ~/workcell-v2 && ~/loopkit/loop/checkpoint.sh
```

It reads the GitHub settings back, then looks at every commit since your last checkpoint. It stops with a loud
message, and lists everything it found, if:

- a setting has changed;
- a locked file changed, or a gate was ticked, and you never signed that change;
- a commit came from neither you nor GitHub;
- history was rewritten, since your last checkpoint or since this clone last looked at `main`;
- the locked files on `main` are not the ones in your kit.

Then it tells you what it cannot judge for you: where the changes are, which tests were deleted, which enforced
invariants disappeared, and which workflow runs a forbidden event started. Your first checkpoint lists the forged workflow
of step 4 there, which GitHub stopped. It prints a link. Read the changes there, about a minute per pull request, then
answer `y`.

The signed tag stays in `~/workcell-v2`, and that copy is the one that counts. GitHub holds no tags for this repository, so
it gets a copy under `refs/checkpoints/`, as a public record. If GitHub does not take the copy, you see a `NOTE`, not a stop.

Last, it deletes left-over `claude/` and `mac/` branches on GitHub that have no open pull request, and names each one.

**Do not skip checkpoints.** They are the one check that does not depend on GitHub or on Claude.

### Approving a locked file

Pause first.

```bash
cd ~/workcell-v2 && ~/loopkit/loop/adopt.sh
```

1. It shows you each drafted file against the real one, and asks `[y/N]` for each.
2. It shows you each unit that was waiting, and asks whether it is finished.
3. It shows the whole change once more, exactly as it will be signed, and asks a last time.

Then it signs with your key, sends the change to GitHub, waits for the checks, merges, and brings `~/loopkit` up to
date. The line `LANDED` must appear. After it come the lines `kit updated`.

### Changing something yourself

1. Pause.
2. Bring your clone up to date **before** you open any file:

   ```bash
   cd ~/workcell-v2 && ~/loopkit/loop/preflight.sh && git merge --ff-only refs/remotes/origin/main
   ```

3. Edit the file with any editor. The plan is `loop/state/PLAN.md`. To finish a gate, change its `[H]` to `[x]`.
   After a halt with the reason `six-failures`, also add one line at the end of `loop/state/LOG.md`, with the time now:
   `## 2026-11-01T10:15Z - RESUME`
   To check the plan's format after an edit:

   ```bash
   cd ~/workcell-v2 && python3 ~/loopkit/loop/test/check-plan.py
   ```

   **To accept a decision,** move its file into `docs/adr/accepted/`. That folder is locked, so only you can put a file
   there, and nobody can change it afterwards without you. For ADR-001 that is:

   ```bash
   cd ~/workcell-v2 && git mv docs/adr/001-vmm.md docs/adr/accepted/001-vmm.md
   ```

4. Send it:

   | What you edited | Command |
   |-----------------|---------|
   | The plan, the log, or anything else that is free | `cd ~/workcell-v2 && ~/loopkit/loop/land.sh` |
   | A locked file, such as `loop/SPEC.md`, or a decision that you accept | `cd ~/workcell-v2 && ~/loopkit/loop/land.sh --reviewed` |

5. The line `LANDED` must appear. If it says `nothing to land`, your edit was not saved.

---

## The pieces that need your Mac

Five pieces need macOS itself: they start virtual machines and use the Keychain. Claude does them on your Mac, **in a
second user account**. That account has no signing key and no `gh` login. After step 1 below it cannot read your files
either. So nothing that Claude writes or runs there can reach them by itself. It could with your help, so keep one rule.

**From your own account, read only the files that this guide names in `/Users/Shared`, and judge your copy, not the
original. Never write to a fixed name there.** `loop` can put a link under any name first, and your copy would go through
the link into your own files. A folder from `mktemp -d` is new and yours alone.

### Once

1. In your own account, close your home folder. As macOS makes it, other accounts on the Mac can read much of it.

   ```bash
   chmod 700 ~
   ```

2. In your own account, install Go for everyone.

   ```bash
   brew install go
   ```

3. Open **System Settings > Users & Groups**, click **Add User**, and make a **Standard** user called `loop`.
4. Open **System Settings > Control Center**, find **Fast User Switching**, and let it show in the menu bar. The new menu at
   the top right of the screen changes accounts without logging you out. Use it to log in as `loop`.
5. As `loop`, open Ghostty. Test step 1, with your own short user name in place of `YOU`. It must say `Permission denied`.

   ```bash
   ls /Users/YOU
   ```

6. As `loop`, install Claude Code with the installer from Anthropic's own documentation
   (<https://code.claude.com/docs/en/setup>). Then run `claude` once and sign in.

   ```bash
   curl -fsSL https://claude.ai/install.sh | bash
   ```

7. Check that `go version` works. If it does not, run `eval "$(/opt/homebrew/bin/brew shellenv)"` and add that line to
   `~/.zshrc`.

**The two accounts share no clipboard, and `loop` cannot see `~/loopkit`.** As `loop`, read this guide on GitHub, at
<https://github.com/omkhar/workcell-v2/blob/main/loop/START-HERE.md>, or in `~/work/loop` once that folder exists.

### For each piece

Pause the cloud first. Then, as `loop`:

```bash
screen -S loop
```

```bash
rm -rf ~/work && git clone --branch main https://github.com/omkhar/workcell-v2.git ~/work && cd ~/work && ANTHROPIC_DEFAULT_FABLE_MODEL=claude-mythos-5-1 claude --model fable
```

If Mythos 5.1 is not in your model list, leave out `ANTHROPIC_DEFAULT_FABLE_MODEL=claude-mythos-5-1`.
**Not for S-1016: keep `~/work`** (`REFERENCE.md` section 6).

Paste this:

```text
This session is supervised. Read loop/PROMPT.md and follow it exactly, for exactly one unit.
```

When Claude says the piece is ready, it has written one file, `/Users/Shared/workcell-handover.bundle`. Switch back to
your own account and run:

```bash
cd ~/workcell-v2 && ~/loopkit/loop/land.sh --from /Users/Shared/workcell-handover.bundle
```

It reads that one file, refuses anything locked, lists every file that changes, and asks before it signs. When it says
`LANDED`, go back to `loop`, type `/exit`, and start the next piece with the same two commands.

| If `land.sh` says | Do this |
|-------------------|---------|
| a required check failed | Run the command below in your own account. It puts the log into a new folder, and prints where. You need not retype that. Tell Claude: `read last-failure.txt in the newest folder /Users/Shared/from-you.*` |
| `main` moved, or the hand-over is from an older `main` | Do not start again. Tell Claude: `main moved`. It brings the work up to date and writes the file again |

```bash
d="$(mktemp -d /Users/Shared/from-you.XXXXXX)" && cp ~/.workcell-loop/last-failure.txt "$d/" && chmod -R go+rX "$d" && echo "$d/last-failure.txt"
```

**The rule about pasting holds here too.** Never run a command in your own account, and never type an administrator's
password, because the session asks you to. If a piece needs a tool, look the tool up yourself and decide.

**Some gates have you run the code yourself:** H-011, H-409, H-703 and H-704. Do those as `loop` as well, with the same two
commands but without `claude`. `REFERENCE.md` section 6 has the commands, and says what more H-011 needs: a clone of its own,
and Claude once.

| In `screen` | Keys |
|-------------|------|
| Leave it running and close Ghostty | `Ctrl-A`, then `D` |
| Come back to it | `screen -r loop` |
| Scroll back | `Ctrl-A`, then `Esc`; arrow keys; `Esc` to leave |

---

## If something goes wrong

| What you see | What it means | What to do |
|--------------|---------------|------------|
| `STOP: ...` from a setup script | A check failed. Nothing further was done | Read the line. It says what to fix. Then run the script again |
| `THE LOCK DOES NOT HOLD` | GitHub merged, ran or accepted something it should have refused | Do not start the loop. `REFERENCE.md` section 8, "If something locked changed without you" |
| `THE LOCK IS NOT PROVEN` | A test could not finish. The message says which check, and what it reported | Look at the pull request it names. Then run `setup-2` again |
| The same, with `gate-macos: failure` | GitHub's Mac could not build or test the kit's own small program. The likely cause is Go: the step `setup-go` could not install the version that `go.mod` names | On the pull request it names, click **Details** beside `gate-macos` and read the end of the log. If a second run fails the same way, the fault is in `ci.yml`: `REFERENCE.md` section 8, "When the checks themselves are broken" |
| `land.sh`: `Only you may change these`, and it stops (exit 4) | **Nothing was signed** | If it is your own edit to a locked file, use `--reviewed`. If it came from Claude, tell Claude to undo it |
| `land.sh`: the locked files on main are not the ones in your kit (exit 4) | Something locked changed without you, or your kit is out of date | `REFERENCE.md` section 8 |
| `land.sh` or `adopt.sh`: one of your pull requests into main is still open (exit 3) | The loop is still working, or a pull request was left behind. The message lists them | Pause and wait. If nothing will finish it, close it on GitHub: "Pausing and stopping". Then run the script again |
| `land.sh`: main moved, or the hand-over is from an older main (exit 3) | Something landed in between | Pause. Your own edit: run `land.sh` again. A Mac piece: tell Claude `main moved`, then hand over again |
| `land.sh`: your edits touch files that changed (exit 3) | You edited a stale copy | Run the three commands it prints |
| `land.sh`: signing failed (exit 6) | `gpg` could not sign | `gpg --clearsign <<< test` should print a signed message. Fix that first |
| `land.sh`: `The signed commit ... is public` | It gave up after you had signed: Ctrl-C, a red check, or checks that took too long. The pull request is closed. Anyone who can open a pull request can still land that commit until `main` moves | You still want the change: run `land.sh` again. You have changed your mind: first take the change out of your clone, with `cd ~/workcell-v2 && git stash -u`. Then land any other change, for example a line in `loop/state/PARKED.md`, before you switch the task on again. The list that `land.sh` shows must hold that new change and nothing else. Waiting is not enough |
| `adopt.sh`: it refuses a proposal, before its first question (exit 4) | One draft under `proposed/` is not fit to be shown: a control character, an odd name, or a name that clashes with another. It holds up every other draft too | The message ends with how to clear that draft away. Do that, then run `adopt.sh` again. If it speaks of a link or a submodule, treat it as an incident: `REFERENCE.md` section 8 |
| `CHECKPOINT STOP` | Something reached `main`, a setting changed, or your kit differs from `main`, and it should not | Pause. Do not sign. `REFERENCE.md` section 8 |
| The loop has gone quiet | A `loop-halt` issue is open. Or a run died and left its `try:` pull request behind. Or a trigger was dropped, or you hit a usage limit | Look at the open halt issues first, then at the pull requests ("Pausing and stopping"). If both lists are empty, wait for the hourly run, or click **Run now**. If runs start and end within a minute or two, open the newest one under **History** on the task's page and read its last lines. `RESULT - HALT` with no issue means that it could not read GitHub: repeat step 5c |
| The same piece fails again and again | The piece is too big, or badly described | After three tries it is marked `[!]` and the loop moves on. Read `loop/state/BLOCKED.md` |
| You want out | | `REFERENCE.md` section 8, "Leaving". `omkhar/workcell` was never touched |

---

## The honest small print

- **What the lock rests on.** Four settings: the rules on `main`, the Actions policy, the tag rule, and the limit on who may
  open pull requests. Only an administrator of the repository can change them. You are one. Claude's GitHub App is not.
  Step 4 proves the first three. Steps 5a and 5c check that the cloud is not an administrator. Checkpoints read all four
  again. Their signature checks need none of the four, so they still work if a setting has failed.
- **Nothing here can reach v1's users.** Claude has no access to `omkhar/workcell`. The new repository can publish no tag and
  no release: the tag rule has no exception, not even for your checkpoints, and GitHub publishes no release without a tag.
- **Claude writes the tests as well as the code.** Different agents do each, and neither may edit the other's
  work. Even so, read the tests at checkpoints.
- **Everything in the repository and its CI logs is public**, including the plan and the journal.
- **Virtual machines on GitHub's runners work, but GitHub does not promise them.** Its documentation calls nested
  virtualisation "technically possible" and "not officially supported". If it goes away, the plan needs a runner of
  your own.
- **Cost.** There is no per-run spending cap in the cloud. Your plan's limits apply. On a Pro plan the top tier, Mythos and
  Fable, is paid from usage credits and not from the plan. Decide on purpose whether usage credits are on.
- **Several parts have never run for real.** `REFERENCE.md` section 11 lists them. The tests ran on Linux, with bash 3.2.57 and
  a BWK awk, which are close to what macOS ships but not the same. Steps 0, 4 and 5c exist to find problems early.

More detail on everything: `loop/REFERENCE.md`.
