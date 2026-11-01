#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only, from your unpacked kit, inside your own clone. The loop may not touch locked paths,
# so it writes what it wants there under proposed/, with "dot-" standing for a leading dot:
#   proposed/dot-github/workflows/ci.yml  ->  .github/workflows/ci.yml
#   proposed/CLAUDE.md.txt                ->  CLAUDE.md
# This shows you each proposal against the real file and installs the ones you accept. What it
# shows and what it installs are the same bytes, read once from the commit on GitHub. Then it
# hands over to land.sh --reviewed, which shows the total and signs with your key.
set -euo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo"
fetch_refs "$TRUNK_SPEC"
[ "$(git branch --show-current)" = main ] || die "not on main" 2
dirty="$(git status --porcelain | plain)"
[ -z "$dirty" ] ||
  die "this clone has edits of its own. To finish an adoption you began: $here/land.sh --reviewed   To start again: git stash -u
Files that only your own global ignore list hides count too. git stash does not take those: move them away.
$dirty" 2
git merge --quiet --ff-only "$TRUNK"
tip="$(git rev-parse "$TRUNK")"
work="$tmp/adopt"
mkdir "$work"
git ls-tree -r -z --name-only "$tip" -- proposed >"$work/names"
[ -s "$work/names" ] || { echo "nothing is proposed"; exit 0; }
nothing_open # land.sh would refuse for the same reason, but only after all your answers
special_entries "$tip" >"$work/links"
if has_line "$(printf '\t')\"?proposed/" <"$work/links"; then die "proposed/ holds a link or a submodule; refusing" 4; fi
# Every file and directory of the commit, as "<blob or tree><tab><path>". The targets that pass are added as they come.
git ls-tree -r -t -z "$tip" | tr '\n\000' '\001\n' | sed -E 's/^[0-9]+ ([a-z]+) [0-9a-f]+/\1/' >"$work/all"

# Pass 1: vet every proposal before the first question, so that a bad one cannot stop the run half-way.
# A Mac folds case. So a target, and each directory above it, is compared in lower case with all that exists or
# is about to: the same name in another spelling is refused, and so is a file where a directory must be.
: >"$work/pairs"
# refuse <why>: one draft that is refused holds up all the others, so every refusal ends with the way to clear it away. The name is
# the agent's text, and you may paste that command. So each byte that is not plain is shown as "?", which to git rm means any one byte.
refuse() {
  die "$1; refusing. To clear it away: git rm '$(printf '%s' "$source" | tr -c 'A-Za-z0-9._/+-' '?')', then $here/land.sh. Put its unit back to [ ] in the plan, so that the loop drafts it again" 4
}
while IFS= read -r -d '' source <&3; do
  [[ "$source" =~ ^proposed/[A-Za-z0-9._/+-]+$ ]] || refuse "odd characters in a proposed path"
  target="$(printf '%s' "${source#proposed/}" | sed -E 's#(^|/)dot-#\1.#g; s#\.md\.txt$#.md#')"
  case "/$(printf '%s' "$target" | tr '[:upper:]' '[:lower:]')/" in
    */.git/* | */../* | */./* | *//* | */-* | /proposed/*) refuse "a proposal targets $target" ;;
  esac
  clash="$(awk -F '\t' -v target="$target" '
    BEGIN {
      depth = split(target, part, "/")
      for (i = 1; i < depth; i++) { path = path (i > 1 ? "/" : "") part[i]; above[tolower(path)] = path }
    }
    { low = tolower($2) }
    low == tolower(target) && $2 != target { print "which differs only in case from " $2; exit }
    low == tolower(target) && $1 == "new" { print "and so does another proposal"; exit }
    low == tolower(target) && $1 != "blob" { print "which is a directory"; exit }
    (low in above) && $2 != above[low] { print "under " above[low] ", which differs only in case from " $2; exit }
    (low in above) && $1 != "tree" { print "under " above[low] ", which is a file"; exit }' "$work/all")"
  [ -z "$clash" ] || refuse "a proposal targets $target, $(printf '%s' "$clash" | plain)"
  hidden="$(git cat-file blob "$tip:$source" | control_bytes)"
  [ "$hidden" = 0 ] ||
    refuse "the proposal for $target holds $hidden control character(s), such as a carriage return. They print as ? and can hide a line break"
  printf 'new\t%s\n' "$target" >>"$work/all"
  above="$(dirname "$target")"
  while [ "$above" != . ]; do
    printf 'tree\t%s\n' "$above" >>"$work/all"
    above="$(dirname "$above")"
  done
  printf '%s\t%s\n' "$source" "$target" >>"$work/pairs"
done 3<"$work/names"

# Pass 2: show, ask, install.
n=0 adopted=0 dropped=0
while IFS="$(printf '\t')" read -r source target <&3; do
  n=$((n + 1))
  git cat-file blob "$tip:$source" >"$work/$n.new"
  : >"$work/$n.old"
  note="new file"
  if git cat-file -e "$tip:$target" 2>/dev/null; then
    git cat-file blob "$tip:$target" >"$work/$n.old"
    note="replaces the current file"
  fi
  bits=644
  if [ "$(git ls-tree "$tip" -- "$source" | cut -c1-6)" = 100755 ]; then bits=755 note="$note; EXECUTABLE"; fi
  if [ "$bits" = 644 ] && [ "$(git ls-tree "$tip" -- "$target" | cut -c1-6)" = 100755 ]; then note="$note; NO LONGER EXECUTABLE"; fi
  odd="$(odd_bytes <"$work/$n.new")"
  if [ "$odd" != 0 ]; then note="$note; HOLDS $odd BYTES ABOVE 0x7e, WHICH PRINT AS ?"; fi
  echo
  echo "=== $n. $target   ($note)"
  (git --no-pager diff --no-index --text --no-color --no-ext-diff --no-textconv -- "$work/$n.old" "$work/$n.new" || true) |
    tail -n +5 | plain
  printf 'Adopt %s? [y/N] ' "$target"
  read -r answer || answer=""
  rm -f -- "${source:?}"
  if [ "$answer" = y ]; then
    mkdir -p "$(dirname "$target")"
    rm -f -- "${target:?}"
    cp "$work/$n.new" "$target"
    chmod "$bits" "$target"
    adopted=$((adopted + 1))
  else
    dropped=$((dropped + 1))
    echo "dropped"
  fi
done 3<"$work/pairs"
find proposed -depth -type d -empty -delete 2>/dev/null || true
echo
echo "$adopted adopted, $dropped dropped."

# The plan marks a unit [S] while it waits for you. Decide each one; nothing is ticked wholesale.
grep -a '^- \[S\] ' loop/state/PLAN.md >"$work/waiting" || [ $? -eq 1 ]
while IFS= read -r line <&3; do
  id="$(printf '%s\n' "$line" | sed -nE 's/^- \[S\] ([A-Z]-[0-9]+[a-z]?|S-F[0-9]+) .*/\1/p')"
  [ -n "$id" ] || continue
  printf '%s\n' "$line" | cut -c1-160 | plain
  printf 'Is %s finished? [y = done / N = the loop must do it again] ' "$id"
  read -r answer || answer=""
  if [ "$answer" = y ]; then mark="x"; else mark=" "; fi
  sed "s/^- \[S\] $id /- [$mark] $id /" loop/state/PLAN.md >"$work/plan"
  cp "$work/plan" loop/state/PLAN.md
done 3<"$work/waiting"

echo
echo "Next you see the whole change once more, and sign it. If you answer n there, or the checks fail, your"
echo "choices stay in this folder. To carry on: $here/land.sh --reviewed   To start again: git stash -u, then adopt.sh"
rm -rf "$tmp" # exec skips the exit trap
exec "$here/land.sh" --reviewed "adopt: $adopted proposed file(s)"
