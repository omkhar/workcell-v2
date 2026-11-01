#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only. Run it from your unpacked kit, inside your own clone (which no agent ever opens):
#   cd ~/workcell-v2 && ~/loopkit/loop/land.sh [--reviewed | --from <hand-over file>] ["subject"]
# It fixes the change as one immutable tree object, judges that object, shows it to you, signs
# exactly that object with your key, opens a pull request into main and merges it when green.
#   (no option)    your own edits in this clone; free paths only
#   --reviewed     your own edits; locked paths may change, and it shows you the whole diff
#   --from <file>  a git bundle written by the agent in the other macOS account; free paths only
# Exit: 0 landed or nothing to do; 1 refused by you or by the checks; 2 setup; 3 main is busy or
# moved, try again; 4 something only you may change, or something is wrong; 6 signing failed.
set -uo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo" || exit 2
mode=own bundle="" subject=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reviewed | --from)
      [ "$mode" = own ] || die "--reviewed and --from cannot be combined: an agent's work never changes locked paths" 2
      mode="${1#--}"
      if [ "$mode" = from ]; then
        bundle="${2:?--from needs the hand-over file}"
        shift
      fi
      ;;
    -*) die "unknown option $1" 2 ;;
    *) subject="$1" ;;
  esac
  shift
done
case "$here/" in "$repo"/*) die "run the copy in your unpacked kit, not the one inside the repository" 2 ;; esac
out="$(out_dir)" || exit 2
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

fetch_refs "$TRUNK_SPEC" || die "fetch failed" 2
[ "$(git branch --show-current)" = main ] || die "not on main" 2
parent="$(git rev-parse "$TRUNK")" || die "cannot read main" 2
if [ "$(git rev-parse HEAD)" != "$parent" ]; then # bring this clone up to date whenever that is safe
  git merge-base --is-ancestor HEAD "$parent" ||
    die "this clone holds commits that GitHub does not. Only land.sh makes commits. Look at: git log $TRUNK..HEAD" 4
  git merge --quiet --ff-only "$TRUNK" 2>/dev/null ||
    die "this clone is behind GitHub, and your edits touch files that changed there. Run these three, then land.sh again:
  git stash
  git merge --ff-only $TRUNK
  git stash pop" 3
fi
nothing_open
stale="$(differs_from_kit "$parent")" || exit 4
if [ -n "$stale" ]; then
  echo "The locked files on main are not the ones in your kit:"
  printf '%s\n' "$stale" | sed 's/^/  /'
  [ "$mode" = reviewed ] ||
    die "nothing is signed under rules you have not read. See REFERENCE.md section 8, 'If something locked changed without you'" 4
fi

# unbundle <file>: check every object in the bundle, store them, and point refs/loop/incoming at its HEAD.
# fetch.fsckObjects would be shorter, but before git 2.46 it does nothing for a bundle. Only the plain form
# that `git bundle create` writes is taken: version 2, so SHA-1 and no capability lines, and exactly one HEAD.
unbundle() {
  local lines bytes tip
  lines="$(grep -a -n -m 1 '^$' "$1" | cut -d: -f1)" || return 1 # the header ends at the first empty line
  [[ "$lines" =~ ^[1-9][0-9]*$ ]] || return 1
  head -n "$lines" "$1" >"$tmp/in.header" || return 1
  tip="$(awk '
    function id(s) { return length(s) == 40 && s !~ /[^0-9a-f]/ }
    NR == 1 { if ($0 != "# v2 git bundle") odd = 1; next }
    $0 == "" { next }
    /^-/ { if (!id(substr($0, 2, 40)) || substr($0, 42, 1) !~ /^ ?$/) odd = 1; next } # what the receiver must already have
    { if (!id(substr($0, 1, 40)) || substr($0, 41, 1) != " ") odd = 1 }
    substr($0, 42) == "HEAD" { heads++; tip = substr($0, 1, 40) }
    END { if (odd || heads != 1) exit 1; print tip }' "$tmp/in.header")" || return 1
  bytes="$(wc -c <"$tmp/in.header" | tr -d ' ')" || return 1
  tail -c "+$((bytes + 1))" "$1" >"$tmp/in.pack" || return 1
  if ! git unpack-objects -q --strict <"$tmp/in.pack" >/dev/null 2>"$tmp/in.errors"; then
    plain <"$tmp/in.errors" | tail -n 5 >&2
    return 1
  fi
  git update-ref refs/loop/incoming "$tip"
}

# Fix the change as one tree object. From here on everything refers to $tree by hash.
if [ "$mode" = from ]; then
  dirty="$(git status --porcelain | plain)" || die "git status failed" 2
  [ -z "$dirty" ] || die "this clone has edits of its own. Land them, stash them or move them away first. Files that only your own global ignore list hides count too:
$dirty" 2
  [ -f "$bundle" ] && [ ! -L "$bundle" ] || die "there is no hand-over file at $bundle" 2
  # One read, into a folder only you can reach. Whatever the file is, it is used only if it is a valid bundle.
  head -c 268435456 "$bundle" >"$tmp/in.bundle" || die "could not read $bundle" 2
  moved="tell Claude that main moved (PROMPT.md section 7b says how it brings the work up to date), then hand over again"
  git bundle verify "$tmp/in.bundle" >/dev/null 2>&1 ||
    die "that file is not a valid hand-over for this clone. If main moved since the piece was started, $moved" 3
  unbundle "$tmp/in.bundle" || die "git refused the hand-over" 4
  incoming="$(git rev-parse refs/loop/incoming)" || die "git refused the hand-over" 4
  git update-ref -d refs/loop/incoming
  [ "$(git cat-file -t "$incoming")" = commit ] || die "git refused the hand-over" 4
  git merge-base --is-ancestor "$parent" "$incoming" ||
    die "the hand-over was made from an older main, so landing it would undo newer work. To keep the work, $moved" 3
  tree="$(git rev-parse "$incoming^{tree}")" || die "git refused the hand-over" 4
  # The check above lets odd file modes and empty folders pass. A merge would not keep them, so main could never hold the tree you signed.
  same_tree="$(git ls-tree -r -z "$tree" | GIT_INDEX_FILE="$tmp/index" git update-index -z --index-info && GIT_INDEX_FILE="$tmp/index" git write-tree)" || die "git refused the hand-over" 4
  [ "$same_tree" = "$tree" ] || die "git refused the hand-over: its tree holds file modes or empty folders that git never writes" 4
  [ -n "$subject" ] || subject="$(git log -1 --no-show-signature --no-color --format=%s "$incoming" | cut -c1-100)"
else
  export GIT_INDEX_FILE="$tmp/index"
  git read-tree "$parent" || die "could not read main" 2
  git add -A || die "could not stage the files" 2
  tree="$(git write-tree)" || die "could not write the tree" 2
  unset GIT_INDEX_FILE
fi
if [ "$tree" = "$(git rev-parse "$parent^{tree}")" ]; then
  echo "nothing to land"
  exit 0
fi

# The subject is untrusted text too: one line, plain characters only, and never something that reads like the marker.
if [ "$(printf '%s\n' "$subject" | wc -l | tr -d ' ')" != 1 ] ||
  [ "$(printf '%s\n' "$subject" | LC_ALL=C grep -cE '^[A-Za-z0-9][ -~]{2,99}$')" != 1 ] ||
  [ "$(printf '%s\n' "$subject" | grep -ciE '^locked-paths')" != 0 ]; then
  subject="loop: change from the maintainer's Mac"
fi

show() { git --no-pager diff --text --no-renames --no-color --no-ext-diff --no-textconv "$@" "$parent" "$tree"; } # raw: print it through plain
page() { # the pager takes its options from here alone: LESS=-S in your shell would cut every long line at the edge of the window
  if [ -t 0 ] && [ -t 1 ] && command -v less >/dev/null; then
    (unset LESSOPEN LESSCLOSE LESSKEY LESSKEYIN LESSKEY_CONTENT && LESS="" LESSSECURE=1 less -FX "$1")
  else cat "$1"; fi
}
locked="$(guarded_between "$parent" "$tree")" || exit 4
yours="$(yours_between "$parent" "$tree")" || exit 4
if [ "$mode" = reviewed ]; then # a locked file is read by you, line by line, so it may hold nothing that shifts the lines
  show -z --name-only --diff-filter=AMT >"$tmp/touched" || die "git diff failed; refusing to continue" 4
  guarded <"$tmp/touched" >"$tmp/touched-locked" || die "the path filter failed; refusing to continue" 4
  while IFS= read -r path; do
    [[ "$path" =~ ^[A-Za-z0-9._/+-]+$ ]] || die "a locked file with such a name cannot be checked for control characters: $path" 4
    hidden="$(git cat-file blob "$tree:$path" | control_bytes)" || die "could not read $path; refusing to continue" 4
    [ "$hidden" = 0 ] ||
      die "$path holds $hidden control character(s), such as a carriage return. They print as ? and can hide a line break. Take them out" 4
  done <"$tmp/touched-locked"
fi
review() { # what you read before you sign. Every step is checked, so that a review that was cut short is never shown
  local odd long
  echo "Subject: $subject" || return 1
  if [ -n "$locked$yours" ]; then
    echo "Only you may change these:" || return 1
    printf '%s\n' "$locked" "$yours" | sed -e '/^$/d' -e 's/^/  /' || return 1
  fi
  echo "Every file that changes (A added, M changed, D deleted):" || return 1
  show --name-status | plain | sed 's/^/  /' || return 1
  [ "$mode" = reviewed ] || return 0
  show --irreversible-delete >"$tmp/diff.raw" || return 1
  plain <"$tmp/diff.raw" >"$tmp/diff.txt" || return 1
  odd="$(odd_bytes <"$tmp/diff.raw")" || return 1
  long="$(awk 'length($0) > 200 { n++ } END { print n + 0 }' "$tmp/diff.txt")" || return 1
  echo "The whole change, exactly as it will be signed. Deleted files are named, not shown:" || return 1
  if [ "$odd" != 0 ]; then echo "NOTE: $odd bytes of it are not plain ASCII (above 0x7e, or control characters in free files). They print as ?" || return 1; fi
  if [ "$long" != 0 ]; then echo "WARNING: $long of its lines are longer than 200 characters. Read each one to its end" || return 1; fi
  cat "$tmp/diff.txt"
}
review >"$tmp/review.txt" || die "the review could not be written in full, so nothing is signed. Is the disk full?" 4
page "$tmp/review.txt" || die "the review could not be shown in full, so nothing is signed" 4
[ -z "$locked" ] || [ "$mode" = reviewed ] || die "your key does not sign locked paths unread. If these are your own edits, use --reviewed" 4
[ -z "$yours" ] || [ "$mode" != from ] || die "an agent may not change a human gate, drop a gate dependency, or touch the log's past" 4
printf 'Sign this with your key and send it to main? [y/N] '
read -r answer || answer=""
[ "$answer" = y ] || die "not signed"

# The last line is the signed statement that guard.sh requires before it lets a locked path change.
if [ -n "$locked" ]; then note="$REVIEWED"; else note="Locked-paths: none"; fi
commit="$(signing commit-tree -S "$tree" -p "$parent" -m "$subject" -m "$note")" || die "signing failed; check gpg-agent and your key" 6
signed_by_maintainer commit "$commit" || die "the new commit is not signed by the maintainer key" 6

# new_key_works: the change touches the key that guard trusts. Prove now what guard will need afterwards: the new key
# file alone verifies your signature, and the new fingerprint file names that key. If the fingerprint stays, the
# commit just signed is the proof. If it changes, the proof is a test object signed with the new key.
new_key_works() {
  local fingerprint proof="$commit"
  git cat-file blob "$tree:.github/maintainer.asc" >"$tmp/new.asc" || return 1
  fingerprint="$(git cat-file blob "$tree:.github/maintainer.fpr")" || return 1
  [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || return 1
  if [ "$fingerprint" != "$(maintainer_fingerprint)" ]; then
    proof="$(signing commit-tree "-S$fingerprint" "$tree" -m "a test of the new key")" || return 1
  fi
  mkdir -m 700 "$tmp/ring" || return 1
  (
    export GNUPGHOME="$tmp/ring"
    gpg --no-autostart --quiet --batch --dry-run --import "$tmp/new.asc" >/dev/null 2>&1 || exit 1 # guard.sh stops if gpg finds any fault with the file
    gpg --no-autostart --quiet --batch --import "$tmp/new.asc" >/dev/null 2>&1 # it also fails for want of an agent, so the next line is the judge
    signed_by "$fingerprint" commit "$proof"
  )
}
case $'\n'"$locked"$'\n' in
  *$'\n'.github/maintainer.asc$'\n'* | *$'\n'.github/maintainer.fpr$'\n'*)
    new_key_works || die "after this change guard could not verify your signature. Nothing was sent. Look at .github/maintainer.asc and .github/maintainer.fpr" 4
    ;;
esac

git update-ref "refs/loop/landed/$stamp-${commit:0:8}" "$commit" || die "could not record the signed commit" 2 # checkpoint.sh looks here
branch="mac/$stamp-${commit:0:8}"
if ! git push --quiet origin "$commit:refs/heads/$branch"; then
  if git ls-remote origin refs/heads/mac 2>/dev/null | cut -f2 | has_line '^refs/heads/mac$'; then
    die "push failed: GitHub holds a branch named mac, so it can hold no branch under mac/. Delete the branch mac on GitHub, then run this again" 2
  fi
  die "push failed" 2
fi
public="The signed commit ${commit:0:12} is public. Anyone who can open a pull request can still land it until main moves.
If you have changed your mind, first put the change aside (git stash -u), then land any other change before you switch the task on again. Waiting is not enough."
url="$(gh pr create --repo "$slug" --base main --head "$branch" --title "$subject" --body "Opened by loop/land.sh.")" ||
  die "could not open the pull request; delete the branch $branch on GitHub. $public" 2
echo "waiting for $url"

give_up() { # give_up <exit code> <message>: never leave a pull request behind that nothing will finish
  gh pr close "$url" --repo "$slug" --delete-branch >/dev/null 2>&1
  git push --quiet origin ":refs/heads/$branch" >/dev/null 2>&1 # gh leaves the branch if someone else closed the pull request
  if [ "$(git rev-parse "$TRUNK")" = "$parent" ]; then die "$2
$public" "$1"; fi
  die "$2" "$1"
}
trap 'give_up 1 "interrupted; the pull request is closed and your files are untouched"' INT TERM HUP

# refresh_kit: copy the locked files you have just read and signed, from that very tree, into the kit. What left the
# tree goes first, so that a file can take the place of a directory and the other way round. Then say what still differs.
refresh_kit() {
  local root path pass bits left
  root="$(dirname "$here")"
  for pass in remove write; do
    printf '%s\n' "$locked" | while IFS= read -r path; do
      [[ "$path" =~ ^[A-Za-z0-9._/+-]+$ ]] || continue
      case "/$path/" in */../* | */./*) continue ;; esac
      bits="$(git ls-tree "$tree" -- "$path" | cut -c1-6)" || continue
      case "$pass $bits" in
        "remove 100644" | "remove 100755") ;;
        remove*) # no longer a plain file in the tree
          if [ -f "$root/$path" ] || [ -L "$root/$path" ]; then rm -f -- "${root:?}/${path:?}" && echo "  kit updated: $path (removed)"; fi
          ;;
        "write 100644" | "write 100755")
          if [ -d "$root/$path" ] || [ -L "$root/$path" ]; then rm -rf -- "${root:?}/${path:?}"; fi
          if mkdir -p "$root/$(dirname "$path")" && git cat-file blob "$tree:$path" >"$root/$path.new" &&
            chmod "${bits#100}" "$root/$path.new" && mv -f "$root/$path.new" "$root/$path"; then
            echo "  kit updated: $path"
          else rm -f -- "${root:?}/${path:?}.new"; fi
          ;;
      esac
    done
  done
  if ! left="$(differs_from_kit "$tree")"; then left="(the comparison failed)"; fi
  [ -z "$left" ] || printf 'Your kit still differs from what you signed. See REFERENCE.md section 8:\n%s\n' "$(printf '%s\n' "$left" | sed 's/^/  /')"
}

for _ in $(seq 1 "${LAND_POLLS:-80}"); do
  # You merge your own pull requests: the workflow's token may not merge a change to a workflow file.
  # GitHub refuses this call until gate, gate-macos and guard are green on exactly this commit.
  gh api -X PUT "repos/$slug/pulls/${url##*/}/merge" -f merge_method=squash -f sha="$commit" \
    -f commit_title="$subject (#${url##*/})" -f commit_message="" >/dev/null 2>&1 || true
  state="$(gh pr view "$url" --repo "$slug" --json state --jq .state)" || state=unknown
  fetch_refs "$TRUNK_SPEC" || true
  if [ "$state" = MERGED ]; then
    trap - INT TERM HUP
    [ "$(git rev-parse "$TRUNK^{tree}")" = "$tree" ] ||
      die "it merged, but main does not hold exactly the tree you signed. This clone is left as it is. Switch the task off and run checkpoint.sh" 4
    # Your own edits are already in place, so only the branch and index move. Otherwise fast-forward.
    if [ "$mode" = from ]; then git merge --quiet --ff-only "$TRUNK"; else git reset --quiet "$TRUNK"; fi
    echo "LANDED $(git log -1 --format='%h %s' "$TRUNK" | plain)"
    if [ -n "$locked" ]; then refresh_kit; fi
    exit 0
  fi
  [ "$(git rev-parse "$TRUNK")" = "$parent" ] ||
    give_up 3 "main moved while this waited, so the signature no longer fits. Nothing is lost: run land.sh again"
  [ "$state" != CLOSED ] || give_up 1 "someone closed the pull request, so nothing will merge it. Your files are untouched"
  red=""
  for check in gate gate-macos guard; do # only what GitHub Actions itself (app 15368) reports counts, here as in the ruleset
    # A call that fails proves nothing. gh then prints GitHub's error text where the number would be, so the fallback stands outside the brackets.
    ended="$(gh api "repos/$slug/commits/$commit/check-runs?check_name=$check&app_id=15368" \
      --jq '[.check_runs[].conclusion | select(. != null and . != "success" and . != "neutral" and . != "skipped")] | length' 2>/dev/null)" || ended=0
    [ "$ended" = 0 ] || red="$red $check"
  done
  if [ -n "$red" ]; then
    # gh hands out the log of a run only once all its jobs have ended, and gate and gate-macos are jobs of one run.
    if [ "$red" != " guard" ]; then # guard is the only job of its run, so its log is ready at once
      echo "A required check failed:$red. Waiting for the runs that are still going, so that the log can be read. Ctrl-C ends the wait."
      for run in $(gh run list --repo "$slug" --branch "$branch" --status in_progress --json databaseId --jq '.[].databaseId' 2>/dev/null); do
        case "$run" in *[!0-9]*) ;; *) gh run watch "$run" --repo "$slug" --interval 15 >/dev/null 2>&1 || true ;; esac
      done
    fi
    {
      gh pr checks "$url" --repo "$slug"
      gh run view --repo "$slug" --log-failed "$(gh run list --repo "$slug" --branch "$branch" --status failure --limit 1 --json databaseId --jq '.[0].databaseId')"
    } 2>&1 | plain | tail -n 150 >"$out/last-failure.txt"
    tail -n 40 "$out/last-failure.txt"
    give_up 1 "a required check failed:$red (more in $out/last-failure.txt). Your files are untouched"
  fi
  sleep "${LAND_SLEEP:-30}"
done
give_up 2 "the checks did not finish in time. The pull request is closed and your files are untouched. Look at the Actions tab, then run land.sh again"
