#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only, from your unpacked kit, inside your own clone. Check what landed on main since your
# last checkpoint, then sign a tag over it. A signed tag vouches for all history below it.
# The tag stays in this clone, as refs/tags/loop-checkpoint-N. GitHub holds no tags at all. It gets a copy, as
# refs/checkpoints/loop-checkpoint-N: a public record and a backup. Nothing protects that copy, so nothing trusts it.
set -euo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo"
stop() { die "CHECKPOINT STOP: $1"; }
copy_to_github() { # copy_to_github <refspec>: this clone's tags are the ones that count, so a failure is said aloud and is not fatal
  git push --quiet origin "$1" 2>/dev/null ||
    echo "NOTE: GitHub did not take the copy of your checkpoints (refs/checkpoints/). The signed tags in this clone are the ones that count. Keep this clone safe.
A name that you did not make may be in its way: REFERENCE.md section 2 has the one command that clears such names away."
}
seen="$(git rev-parse --quiet --verify "$TRUNK" || true)" # where this clone last saw main
git fetch --quiet --no-tags origin "$TRUNK_SPEC" || stop "fetch failed"
# The copies on GitHub are fetched into a namespace of their own. They can never overwrite or shadow a local ref.
# Whoever can push can plant names there that this disk cannot hold side by side. So a failure is said aloud and is not fatal.
git fetch --quiet --no-tags --prune origin '+refs/checkpoints/*:refs/loop/remote-tags/*' 2>/dev/null ||
  echo "NOTE: not every copy under refs/checkpoints/ on GitHub could be fetched. Nothing trusts those copies, so this run goes on.
One command clears away every name there that you did not make: REFERENCE.md section 2. Never paste such a name into a command."
tip="$(git rev-parse "$TRUNK")"
for old in "$seen" "$(git rev-parse --quiet --verify refs/heads/main || true)"; do
  [ -z "$old" ] || git merge-base --is-ancestor "$old" "$tip" ||
    stop "main no longer contains $old, which this clone has seen there: history was rewritten.
Switch the scheduled task off. Do not sign. See REFERENCE.md section 8, 'If something locked changed without you'."
done

# The anchor is the highest-numbered checkpoint that really is yours: your signature, over that very name.
last="" last_ref=""
while IFS= read -r ref; do
  name="${ref##*/}"
  if [[ "$ref" =~ /loop-checkpoint-[0-9]{1,9}$ ]] && signed_by_maintainer tag "$ref" &&
    [ "$(git cat-file tag "$ref" | sed -n 's/^tag //p' | head -n 1)" = "$name" ]; then
    last="$name" last_ref="$ref"
    break
  fi
  echo "note: $(printf '%s' "${ref#refs/}" | plain) is not a checkpoint you signed. It is ignored."
done < <(git for-each-ref --format='%(refname)' 'refs/tags/loop-checkpoint-*' refs/loop/checkpoints/ refs/loop/remote-tags/ |
  LC_ALL=C awk -F- '{ print ($NF + 0) "\t" $0 }' | LC_ALL=C sort -rn | cut -f2)
[ -n "$last" ] || stop "there is no checkpoint signed by the key in your kit. If the setup is not finished, run setup-2-after-merge.sh first.
If you have changed your key, sign one by hand: REFERENCE.md section 8, 'You change to a new key'.
If you had checkpoints before and have not changed your key, treat this as an incident."
git update-ref "refs/tags/$last" "$(git rev-parse "$last_ref")"
# A second copy in this clone, under a name that git never prunes. With fetch.prune and fetch.pruneTags set, one plain git fetch deletes every tag that GitHub lacks.
git update-ref "refs/loop/checkpoints/$last" "refs/tags/$last"
copy_to_github '+refs/tags/loop-checkpoint-*:refs/checkpoints/loop-checkpoint-*' # puts back any copy that was moved or deleted
from="$(git rev-parse "refs/tags/$last^{commit}")" number=$((10#${last##*-} + 1))
# Only the names that are taken in this clone are skipped. A name that someone planted on GitHub does not choose your numbers.
while [ -n "$(git for-each-ref --format=x "refs/tags/loop-checkpoint-$number" "refs/loop/checkpoints/loop-checkpoint-$number")" ]; do number=$((number + 1)); done

echo "GitHub settings:"
"$here/settings.sh" check || stop "a setting the lock depends on is not as it should be. If you did not change it yourself, treat this as an incident.
To put the settings back: $here/settings.sh apply"
[ "$from" != "$tip" ] || { echo "nothing new since $last"; exit 0; }
git merge-base --is-ancestor "$from" "$tip" || stop "main no longer contains $from: history was rewritten"

# same_change <candidate> <commit> <reviewed|signed>: a commit you signed, with the same content on the same parent.
same_change() {
  [ "$(git rev-parse "$1^{tree}")" = "$(git rev-parse "$2^{tree}")" ] || return 1
  [ "$(git rev-parse "$1^")" = "$(git rev-parse "$2^")" ] || return 1
  if [ "$3" = reviewed ]; then reviewed_by_maintainer "$1"; else signed_by_maintainer commit "$1"; fi
}
# vouched <commit> <reviewed|signed>: you signed this very change, on this Mac or as the head of its pull request.
vouched() {
  local candidate pr
  if same_change "$1" "$1" "$2"; then return 0; fi
  for candidate in $(git for-each-ref --format='%(objectname)' refs/loop/landed); do
    if same_change "$candidate" "$1" "$2"; then return 0; fi
  done
  pr="$(git log -1 --format=%s "$1" | sed -nE 's/.*\(#([0-9]+)\)$/\1/p')"
  [ -n "$pr" ] || return 1
  git fetch --quiet --no-tags origin "+refs/pull/$pr/head:refs/loop/pull-head" 2>/dev/null || return 1
  same_change "$(git rev-parse refs/loop/pull-head)" "$1" "$2"
}

# Look at every commit, and collect every problem before stopping: the first one may be a decoy.
count=0 problems="" all_locked="" all_yours=""
for commit in $(git rev-list --reverse "$from..$tip"); do
  count=$((count + 1))
  if [ "$(git rev-list --parents -n 1 "$commit" | wc -w | tr -d ' ')" != 2 ]; then
    problems="$problems
$commit is a merge commit; main takes squash merges only"
    continue
  fi
  # 1. Every commit is yours, or one that GitHub itself made and signed.
  if ! signed_by_maintainer commit "$commit"; then
    verdict="$(gh api "repos/$slug/commits/$commit" --jq '"\(.commit.verification.verified) \(.committer.login)"')" ||
      stop "could not ask GitHub about $commit"
    [ "$verdict" = "true web-flow" ] || problems="$problems
$commit is signed neither by you nor by GitHub ($(printf '%s' "$verdict" | plain))"
  fi
  # 2. Whatever only you may change was changed by you. No forged green tick can pass this.
  #    Each commit is judged by the allowlist that was in force when it was made: its parent's.
  git cat-file blob "$commit^:loop/free-paths.txt" >"$tmp/free-then" 2>/dev/null || : >"$tmp/free-then"
  locked="$(FREE_LIST="$tmp/free-then" guarded_between "$commit^" "$commit")" || stop "could not compare the trees"
  yours="$(yours_between "$commit^" "$commit")" || stop "could not compare the plan"
  if [ -n "$locked" ] && ! vouched "$commit" reviewed; then
    problems="$problems
$commit changed locked paths, and you never signed that change:
$(printf '%s\n' "$locked" | sed 's/^/    /')"
  elif [ -n "$yours" ] && ! vouched "$commit" signed; then
    problems="$problems
$commit did something only you may do, and you never signed it:
$(printf '%s\n' "$yours" | sed 's/^/    /')"
  fi
  all_locked="$all_locked$locked
" all_yours="$all_yours$yours
"
done
[ -z "$problems" ] || stop "$count commits since $last, and these are wrong:$problems

Switch the scheduled task off. Do not sign. See REFERENCE.md section 8, 'If something locked changed without you'."
# A change of yours that has vanished from main leaves no commit to stop at. Your kit still holds what you signed last.
stale="$(differs_from_kit "$tip")" || stop "your kit could not be compared with main"
[ -z "$stale" ] || stop "the locked files on main are not the ones in your kit:
$(printf '%s\n' "$stale" | sed 's/^/    /')

Do not sign. See REFERENCE.md section 8, 'If something locked changed without you'."
echo "$count commits since $last. Each is signed by you or by GitHub, and everything only you may change was signed by you."
list() { printf '%s' "$2" | sed '/^$/d' | LC_ALL=C sort -u >"$tmp/listing"; if [ -s "$tmp/listing" ]; then echo "$1"; sed 's/^/  /' "$tmp/listing"; fi; }
list "Locked paths you changed in this period:" "$all_locked"
list "Gates, gate dependencies and log lines you signed in this period:" "$all_yours"

# What the signature check cannot judge for you. Read these.
echo "Where the changes are:"
git diff -z --no-renames --name-only "$from" "$tip" | LC_ALL=C tr '\n\000' '?\n' | plain | cut -d/ -f1 | LC_ALL=C sort | uniq -c | sed 's/^/  /'
list "TESTS THAT WERE DELETED. Make sure each had a good reason:" \
  "$(git diff --no-renames --diff-filter=D --name-only "$from" "$tip" -- escape '*_test.go' | plain)"
for file in escape/enforced.txt escape/enforced-macos.txt; do
  git cat-file blob "$from:$file" 2>/dev/null | LC_ALL=C sort >"$tmp/was" || true
  git cat-file blob "$tip:$file" 2>/dev/null | LC_ALL=C sort >"$tmp/is" || true
  list "ENFORCED INVARIANTS THAT DISAPPEARED from $file. The gate should have refused this:" "$(LC_ALL=C comm -23 "$tmp/was" "$tmp/is" | plain)"
done
since="$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd "$from")"
if gh api --paginate "repos/$slug/actions/runs?created=%3E%3D$since&per_page=100" \
  --jq '.workflow_runs[] | select(.event != "pull_request_target" and .event != "schedule") | "\(.event) \(.path) \(.head_branch)"' >"$tmp/ran" 2>/dev/null; then
  list "WORKFLOW RUNS THAT A FORBIDDEN EVENT STARTED (event, file, branch). The Actions policy allows only pull_request_target and schedule.
A run that the policy stopped is listed too, and so are the probes of setup-2 (selftest-forged.yml). Look at each in the Actions tab before you sign. None may have run a job:" \
    "$(sed "s# $slug/# #" "$tmp/ran" | plain)"
  total="$(gh api "repos/$slug/actions/runs?created=%3E%3D$since&per_page=1" --jq .total_count 2>/dev/null || true)"
  case "$total" in
    '' | *[!0-9]*) echo "note: could not count the workflow runs. GitHub lists 1,000 at most, so older ones may be missing above" ;;
    *) [ "$total" -lt 1000 ] || echo "WARNING: $total runs since $last. GitHub lists 1,000 at most, so older ones are missing above. Look at the Actions tab." ;;
  esac
else
  echo "note: could not list workflow runs"
fi

git --no-pager diff --shortstat "$from" "$tip"
echo "Read the changes: https://github.com/$slug/compare/$from...$tip"
printf 'Sign loop-checkpoint-%s over %s? [y/N] ' "$number" "$(git rev-parse --short "$tip")"
read -r answer || answer=""
[ "$answer" = y ] || { echo "not signed"; exit 1; }
signing tag -s "loop-checkpoint-$number" "$tip" -m "checkpoint $number: reviewed by the maintainer"
git update-ref "refs/loop/checkpoints/loop-checkpoint-$number" "refs/tags/loop-checkpoint-$number"
echo "signed loop-checkpoint-$number"
copy_to_github "+refs/tags/loop-checkpoint-$number:refs/checkpoints/loop-checkpoint-$number"
# The cloud cannot delete branches, so closed pull requests leave theirs behind. Sweep up those with no open pull request.
# A branch called just "mac" or "claude" goes too: while it exists, git can create no branch below that name.
if gh api --paginate "repos/$slug/pulls?state=open&per_page=100" --jq '.[].head.ref' >"$tmp/in-use" 2>/dev/null; then
  doomed=()
  while IFS= read -r branch; do doomed+=(":refs/heads/$branch"); done < <(git ls-remote --heads origin 'refs/heads/claude/*' 'refs/heads/mac/*' refs/heads/claude refs/heads/mac |
    cut -f2 | sed 's#^refs/heads/##' | { grep -E '^(claude|mac)(/[A-Za-z0-9._-]+)?$' || true; } | { grep -vxFf "$tmp/in-use" || true; })
  if [ "${#doomed[@]}" -gt 0 ] && git push --quiet origin "${doomed[@]}"; then
    echo "deleted ${#doomed[@]} left-over branches on GitHub, none of which had an open pull request:"
    printf '  %s\n' "${doomed[@]#:refs/heads/}"
  fi
fi
