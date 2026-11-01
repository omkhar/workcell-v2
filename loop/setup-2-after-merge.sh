#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# STEP 2 of 2, on the Mac, after you have merged the kit pull request.
#   ~/loopkit/loop/setup-2-after-merge.sh [directory]     (default: ~/workcell-v2)
# It checks that what merged is byte-for-byte what you signed, signs checkpoint 0, applies the
# GitHub settings and reads them back, proves the lock with four live tests, and ticks gate H-000.
# It stops at the first thing that is not right. It is safe to run again.
set -uo pipefail
self="$(cd "$(dirname "$0")" && pwd)" # resolved before the cd below, so a relative path cannot pick up the repository's copy
cd "${1:-$HOME/workcell-v2}" || exit 1
# shellcheck source=loop/lib.sh
. "$self/lib.sh"
v1_slug="${LOOP_V1_SLUG:-omkhar/workcell}" # only ever read
ok() { printf '  ok    %s\n' "$1"; }
stop() { echo "STOP: $1" >&2; exit 1; }
runs() { # runs <commit> <check name>: every conclusion GitHub Actions has reported under that name, for example "success" or "failure,success"
  local said # a call that fails says nothing. gh then prints GitHub's error text where the answer would be, so only the answer of a call that worked is passed on
  said="$(gh api "repos/$slug/commits/$1/check-runs?check_name=$2&app_id=15368&filter=all" --jq '[.check_runs[] | .conclusion // "pending"] | sort | join(",")' 2>/dev/null)" || return 0
  printf '%s\n' "$said"
}
probe_commit() { # probe_commit <message> <path> <content> [<path> <content>]: an unsigned commit on the tip of main
  local message="$1" blob made
  shift
  export GIT_INDEX_FILE="$tmp/probe-index"
  git read-tree "$TRUNK" || return 1
  while [ $# -gt 0 ]; do
    blob="$(printf '%s\n' "$2" | git hash-object -w --stdin)" || return 1
    git update-index --add --cacheinfo "100644,$blob,$1" || return 1
    shift 2
  done
  made="$(git -c commit.gpgsign=false commit-tree "$(git write-tree)" -p "$TRUNK" -m "$message")" || return 1
  unset GIT_INDEX_FILE
  printf '%s' "$made"
}
tidy() { for pr in "$@"; do [ -z "$pr" ] || gh pr close "$pr" --repo "$slug" --delete-branch >/dev/null 2>&1; done; }
direct() { # direct <refspec>: what GitHub says to a push that goes round the pull requests: accepted, refused or unclear
  local report
  if report="$(git push --porcelain origin "$1" 2>/dev/null)"; then echo accepted
  elif printf '%s\n' "$report" | has_line '^!.*\[remote rejected\]'; then echo refused # GitHub heard the push and said no
  else echo unclear; fi # it never got that far: no network, or main has moved
}

echo "1/6 what merged is what you signed"
git fetch --quiet --no-tags origin "$TRUNK_SPEC" || stop "fetch failed"
git fetch --quiet --no-tags --prune origin '+refs/checkpoints/*:refs/loop/remote-tags/*' 2>/dev/null || # as in checkpoint.sh
  echo "NOTE: not every copy under refs/checkpoints/ on GitHub could be fetched. Nothing trusts those copies, so this run goes on.
One command clears away every name there that you did not make: REFERENCE.md section 2. Never paste such a name into a command."
# Steps 1 and 2 are done once. They are done if some checkpoint passes the test that checkpoint.sh applies (your
# signature, over that very name), or if gate H-000 is ticked on main. A later key, or a later main, changes neither.
before=""
while IFS= read -r ref; do
  if [[ "$ref" =~ /loop-checkpoint-[0-9]{1,9}$ ]] && signed_by_maintainer tag "$ref" &&
    [ "$(git cat-file tag "$ref" | sed -n 's/^tag //p' | head -n 1)" = "${ref##*/}" ]; then
    before="you have signed ${ref##*/}"
    break
  fi
done < <(git for-each-ref --format='%(refname)' 'refs/tags/loop-checkpoint-*' refs/loop/checkpoints/ refs/loop/remote-tags/)
if [ -z "$before" ] && git cat-file blob "$TRUNK:loop/state/PLAN.md" 2>/dev/null | has_line '^- \[x\] H-000 '; then
  before="gate H-000 is ticked on main"
fi
if [ -n "$before" ]; then
  ok "checked on an earlier run: $before"
else
  signed_by_maintainer commit refs/heads/kit || stop "the local kit branch is not the commit you signed in START-HERE.md step 2 (setup-1-open-pr.sh)"
  [ "$(git rev-parse "$TRUNK^{tree}")" = "$(git rev-parse 'refs/heads/kit^{tree}')" ] ||
    stop "main on GitHub does not match the kit tree you signed. Is the pull request merged? Was anything else pushed?"
  ok "identical trees"
  git push --quiet origin :refs/heads/kit 2>/dev/null || true # the branch has done its work, and no later sweep would take it
fi
git switch --quiet main || stop "could not switch to main"
git merge --quiet --ff-only "$TRUNK" || stop "could not fast-forward local main"

echo "2/6 checkpoint 0, signed with your key"
if [ -n "$before" ]; then
  ok "nothing to sign: $before"
else
  signing tag -s loop-checkpoint-0 "$(git rev-parse "$TRUNK")" -m "checkpoint 0: the kit as reviewed and merged by the maintainer" || stop "could not sign the tag"
  git update-ref refs/loop/checkpoints/loop-checkpoint-0 refs/tags/loop-checkpoint-0 || stop "could not keep the second copy of the tag" # see checkpoint.sh
  ok "signed. The tag stays in this clone, because GitHub is to hold no tags at all"
  if git push --quiet origin '+refs/tags/loop-checkpoint-0:refs/checkpoints/loop-checkpoint-0' 2>/dev/null; then
    ok "a copy is on GitHub, as refs/checkpoints/loop-checkpoint-0"
  else
    echo "NOTE: GitHub did not take the copy of your checkpoint (refs/checkpoints/). The signed tag in this clone is the one that counts. Keep this clone safe."
  fi
fi

echo "3/6 GitHub settings, each one read back"
"$here/settings.sh" apply || stop "a setting did not take. Fix the lines marked WRONG by hand (REFERENCE.md section 2), then run this script again"

echo "4/6 four live tests (about ten minutes; most of it is GitHub's runners starting)"
# A run that was cut off may have left its pull requests open, and land.sh works only when none of yours is.
left="$(gh pr list --repo "$slug" --base main --state open --json number,headRefName --jq '.[] | select(.headRefName | startswith("claude/selftest-")) | .number')" ||
  stop "could not list the open pull requests"
for pr in $left; do
  tidy "$pr"
  ok "closed pull request #$pr, which an earlier run of this script left open"
done
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
# The honest probe looks like a real claim: it also adds a line to the log. So guard must fetch a file's content, as it must for the loop.
log="$(git cat-file blob "$TRUNK:loop/state/LOG.md" && printf .)" || stop "could not read loop/state/LOG.md on main"
log="${log%.}" # the dot kept the empty lines at the end, which $( ) would drop: the log is append only
[ -z "$log" ] || [ "${log%$'\n'}" != "$log" ] || log="$log"$'\n'
good="$(probe_commit "self-test: a free change (must pass)" "docs/selftest-$stamp.md" "Left by a self-test. Safe to delete." \
  loop/state/LOG.md "$log## $(date -u +%Y-%m-%dT%H:%MZ) U-001 START mode=cloud")" || stop "could not build the first probe"
forged='on: [push, pull_request]
jobs:
  gate: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] }
  gate-macos: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] }
  guard: { runs-on: ubuntu-24.04, steps: [{ run: "true" }] }'
evil="$(probe_commit "self-test: an unsigned locked change and a forged workflow (must be refused)" \
  loop/selftest-delete-me.txt "Left by a failed self-test ($stamp). Safe to delete." .github/workflows/selftest-forged.yml "$forged")" || stop "could not build the second probe"
stray="$(probe_commit "self-test: a push straight to main (must be refused)" "docs/selftest-direct-$stamp.md" "Left by a failed self-test ($stamp). Safe to delete.")" ||
  stop "could not build the third probe" # it is on no branch and in no pull request
git push --quiet origin "$good:refs/heads/claude/selftest-good-$stamp" "$evil:refs/heads/claude/selftest-evil-$stamp" || stop "could not push the probes"
pr_good="$(gh pr create --repo "$slug" --base main --head "claude/selftest-good-$stamp" --title "try: self-test, a free change" --body "Opened by setup-2-after-merge.sh. It closes itself.")" ||
  stop "could not open the first test pull request"
pr_evil="$(gh pr create --repo "$slug" --base main --head "claude/selftest-evil-$stamp" --title "self-test: must be refused" --body "Opened by setup-2-after-merge.sh. It closes itself.")" ||
  { tidy "$pr_good"; stop "could not open the second test pull request"; }
trap 'tidy "$pr_good" "$pr_evil"; rm -rf "$tmp"; exit 1' INT TERM HUP
for _ in $(seq 1 "${SELFTEST_POLLS:-80}"); do # wait until all six real checks have reported
  gg="$(runs "$good" gate)" gm="$(runs "$good" gate-macos)" gd="$(runs "$good" guard)"
  eg="$(runs "$evil" gate)" em="$(runs "$evil" gate-macos)" ed="$(runs "$evil" guard)"
  case ",$gg,$gm,$gd,$eg,$em,$ed," in *,,* | *pending*) sleep "${SELFTEST_SLEEP:-15}" ;; *) break ;; esac
done
if answer="$(gh api -X PUT "repos/$slug/pulls/${pr_evil##*/}/merge" -f merge_method=squash 2>&1 >/dev/null)"; then merged=yes
else case "$answer" in *"rate limit"*) merged=unclear ;; *"(HTTP 403)"* | *"(HTTP 405)"* | *"(HTTP 409)"* | *"(HTTP 422)"*) merged=no ;; *) merged=unclear ;; esac; fi # only these four are GitHub's own no
[ "$(gh pr view "$pr_evil" --repo "$slug" --json state --jq .state 2>/dev/null)" != MERGED ] || merged=yes
[ "$(gh pr view "$pr_good" --repo "$slug" --json state --jq .state 2>/dev/null)" != MERGED ] || try_merged=yes
pushed="$(direct "$stray:refs/heads/main")"
tagged="$(direct "$good:refs/tags/loop-selftest-$stamp")"
if [ "$tagged" = accepted ]; then
  if git push --quiet origin ":refs/tags/loop-selftest-$stamp" 2>/dev/null; then tag_now="It has been deleted again"; else tag_now="It is still there: GitHub would not delete it again"; fi
fi
tidy "$pr_good" "$pr_evil"
trap - INT TERM HUP
left="$(gh pr list --repo "$slug" --base main --state open --json number,headRefName --jq '[.[] | select(.headRefName | startswith("claude/selftest-")) | "#\(.number)"] | join(" ")' 2>/dev/null || true)"
[ -z "$left" ] || echo "NOTE: these test pull requests could not be closed: $left. Close them on GitHub, or run this script again. It closes them first."
[ "$merged" != yes ] || stop "THE LOCK DOES NOT HOLD: GitHub merged an unsigned change to a locked path. Do not start the loop. See REFERENCE.md section 8, 'If something locked changed without you'"
[ "${try_merged:-no}" = no ] || stop "a pull request titled 'try: ...' merged by itself. Do not start the loop. Look at $pr_good"
[ "$pushed" != accepted ] || stop "THE LOCK DOES NOT HOLD: GitHub let a plain git push move main, with no pull request and no checks.
main now holds the probe commit $stray, which adds docs/selftest-direct-$stamp.md. Do not start the loop. See REFERENCE.md section 8, 'If something locked changed without you'"
[ "$tagged" != accepted ] || stop "THE LOCK DOES NOT HOLD: GitHub accepted the tag loop-selftest-$stamp, and whoever can push a tag can publish a release. $tag_now.
Do not start the loop. See REFERENCE.md section 2"
[ "$gg" = success ] && [ "$gm" = success ] && [ "$gd" = success ] ||
  stop "THE LOCK IS NOT PROVEN: honest work did not pass (gate: ${gg:-never started}, gate-macos: ${gm:-never started}, guard: ${gd:-never started}; expected success three times).
If a check never started, the Actions policy is the likely cause: REFERENCE.md section 2. If gate says 'no KVM on this runner', GitHub gave us a machine without virtual machines: run this script again.
If gate or gate-macos failed for another reason, read its annotation on the pull request. setup-go may not have been able to install the Go version that go.mod names.
Look at $pr_good, then run this script again"
ok "honest work passes: gate, gate-macos and guard were green on a free change, KVM included"
case ",$ed," in
  *,success,*) stop "THE LOCK DOES NOT HOLD: a workflow pushed on a side branch reported a green 'guard' ($ed). The Actions policy is not working: REFERENCE.md section 2. Do not start the loop" ;;
  ,failure,) ;;
  *) stop "THE LOCK IS NOT PROVEN: guard reported '${ed:-nothing}' on the bad change; expected one failure. Look at $pr_evil, then run this script again" ;;
esac
[ "$eg" = success ] && [ "$em" = success ] ||
  stop "THE LOCK IS NOT PROVEN: on the bad change gate reported '${eg:-nothing}' and gate-macos '${em:-nothing}'; expected one success each, so that only guard stood in the way. Look at $pr_evil"
[ "$merged" = no ] || stop "THE LOCK IS NOT PROVEN: the attempt to merge the bad change failed before GitHub could judge it. gh said: $(printf '%s' "${answer:-nothing}" | tr '\n' ' ' | plain | cut -c1-300)
Run this script again"
ok "a locked change without your signature is refused: guard was red, and GitHub would not merge"
ok "a forged workflow on a side branch did not run: nothing but the three real checks reported"
[ "$pushed" = refused ] && [ "$tagged" = refused ] ||
  stop "THE LOCK IS NOT PROVEN: the push straight to main was $pushed, and the push of a tag was $tagged; GitHub should have refused both.
'unclear' means that the push failed before GitHub could judge it, for example because the network dropped. Run this script again"
ok "a push straight to main is refused: nothing reaches it but a pull request"
ok "a tag is refused, so no release can be published"

echo "5/6 this Mac"
"$here/preflight.sh" || stop "fix what preflight reported above, then run this script again"

echo "6/6 gate H-000, through the real pipeline"
if [ "$(gh api "repos/$v1_slug/private-vulnerability-reporting" --jq .enabled 2>/dev/null || true)" = true ]; then
  ok "private vulnerability reporting is on at $v1_slug, where SECURITY.md sends reporters"
else
  echo "NOTE: SECURITY.md sends reporters to the private vulnerability reporting of $v1_slug. It is switched off there, or could not be read. Switch it on in that repository's settings."
fi
if git cat-file blob "$TRUNK:loop/state/PLAN.md" | has_line '^- \[H\] H-000 '; then
  sed 's/^- \[H\] H-000 /- [x] H-000 /' loop/state/PLAN.md >"$tmp/plan" && cp "$tmp/plan" loop/state/PLAN.md
  if "$here/baseline-ci.sh" "$v1_slug" >/dev/null 2>&1; then
    ok "recorded v1's CI timings in loop/baseline/ci.tsv. This is the text that your key signs next:"
    plain <loop/baseline/ci.tsv | sed 's/^/          /'
  else
    rm -rf loop/baseline
  fi
  printf 'y\n' | "$here/land.sh" "H-000: finish setup" || stop "the first real landing failed; read the message above, then run this script again"
  ok "H-000 ticked: pull request, three checks, merge"
else
  ok "H-000 is already ticked on GitHub"
fi

echo
echo "ALL DONE on the Mac. Next: the browser part, START-HERE.md step 5."
