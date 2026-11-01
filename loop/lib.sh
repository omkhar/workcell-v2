# Shared by the loop scripts. Sourced, never executed.
# shellcheck shell=bash
# One locale for bash's own patterns and for every tool: plain bytes, in byte order. In a UTF-8 locale
# a byte that is not valid text can make a pattern, or a whole line, go unseen. Your terminal's own locale
# is kept for one purpose, see signing() below. A script that one of these scripts starts inherits it.
export LOOP_LOCALE="${LOOP_LOCALE:-${LC_ALL:-${LC_CTYPE:-${LANG:-C}}}}"
export LC_ALL=C
# `here` is where these scripts live. On the Mac that is your unpacked kit, outside the
# repository, so nothing that reaches the repository can change what runs with your key.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
git_bin="$(type -P git)" || { echo "git is not installed" >&2; exit 2; }

# Nothing inherited from the caller, and nothing stored under .git, may redirect git.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
  GIT_COMMON_DIR GIT_NAMESPACE GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_EXTERNAL_DIFF GIT_SSH GIT_SSH_COMMAND
export GIT_NO_REPLACE_OBJECTS=1 GIT_CONFIG_NOSYSTEM=1
repo="${LOOP_REPO:-$("$git_bin" rev-parse --show-toplevel 2>/dev/null || true)}"
if [ -z "$repo" ] || [ ! -d "$repo/.git" ] || [ -L "$repo/.git" ]; then
  echo "run this inside the repository, or set LOOP_REPO" >&2
  exit 2
fi
if [ -e "$repo/.git/commondir" ] || [ "$("$git_bin" -C "$repo" config --bool extensions.worktreeConfig 2>/dev/null || true)" = true ]; then
  echo "$repo/.git takes its configuration from somewhere else; refusing to use this clone" >&2
  exit 4
fi
repo="$(cd "$repo" && pwd -P)" || exit 2 # resolved like `here`, so that a link or another spelling cannot make one folder look like two
export LOOP_REPO="$repo" # so that sibling scripts started from the kit find the same repository
# GPG_TTY lets a terminal pinentry ask for your passphrase. When stdin is a pipe, `tty` has nothing
# to say, and the value this script inherited stays.
if terminal="$(tty 2>/dev/null)"; then export GPG_TTY="$terminal"; fi

# Refs are always spelled in full. A short name such as origin/main would resolve to a TAG of that
# name first, and anyone who can push a tag could then choose what these scripts look at.
# shellcheck disable=SC2034 # used by the scripts that source this file
TRUNK=refs/remotes/origin/main TRUNK_SPEC=+refs/heads/main:refs/remotes/origin/main
# shellcheck disable=SC2034
slug="${LOOP_SLUG:-omkhar/workcell-v2}"

die() { echo "$(basename "$0"): $1" >&2; exit "${2:-1}"; }

# Every git call made by these scripts ignores repository hooks and file-system monitors, which
# are programs that git would otherwise run. It calls git by path, not through `command`: in
# bash 3.2 (macOS) a failing `command ...` ends a `set -e` script even when the caller handles it.
# Network calls use the token that gh holds, so nothing depends on your keychain or global helpers.
# Your own global ignore list is left out too: it must not decide what is staged, shown or signed.
# So are push.followTags, which would publish your checkpoint tags with any push, and log.showSignature, which adds gpg's lines to git log.
git() {
  "$git_bin" -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.excludesFile=/dev/null \
    -c push.followTags=false -c log.showSignature=false \
    -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"
}

# signing <git arguments>: for the git commands that sign with your key (commit-tree -S, tag -s), and for nothing else.
# gpg hands its locale to the passphrase dialog. In the C locale a dialog in the terminal cannot take a passphrase
# that holds anything but ASCII. Nothing reads what these commands print but an object name. The brackets keep
# the change from leaking, however bash was started.
signing() { (export LC_ALL="$LOOP_LOCALE" && git "$@"); }

# fetch_refs <refspec>...: fetch exactly what is named. Never any stray tag.
fetch_refs() { git fetch --quiet --no-tags origin "$@"; }

# Logs and scratch files live outside the repository and outside the shared temporary folder.
out_dir() {
  local d="${LOOP_OUT:-$HOME/.workcell-loop}"
  mkdir -p "$d" || die "cannot create $d" 2
  chmod 700 "$d" || die "cannot restrict $d" 2
  printf '%s' "$d"
}
tmp="$(mktemp -d "$(out_dir)/tmp.XXXXXX")" || exit 2
trap 'rm -rf "$tmp"' EXIT

# has_line <extended regex>: true if any line of stdin matches. It reads all of its input, so it
# cannot kill the writer early and turn a match into a pipeline failure. Feed it from a file or
# through a pipe, never a here-string: bash 3.2 passes a here-string through a file in the temporary
# folder. From grep, 1 means "no line matches". Anything else is an error, and an error is fatal. In a
# pipe that ends has_line alone, and the caller hears a plain no. So where a no lets something pass, feed it from a file.
has_line() {
  local n
  n="$(LC_ALL=C grep -a -cE -- "$1")" || [ $? -eq 1 ] || die "grep failed; refusing to continue" 4
  [[ "$n" =~ ^[0-9]+$ ]] || die "grep failed; refusing to continue" 4
  [ "$n" -gt 0 ]
}

# same <file> <file>: true if they hold the same bytes. From cmp, too, only 1 means "no".
same() {
  local verdict=0
  cmp -s "$1" "$2" || verdict=$?
  [ "$verdict" -le 1 ] || die "cmp failed; refusing to continue" 4
  return "$verdict"
}

# plain: make untrusted text safe to print on a terminal or in a CI log.
plain() { LC_ALL=C tr -c '[:print:]\n\t' '?' | sed -e 's/::/: :/g' -e 's/##\[/# #[/g'; }

# say <label>: the lines of stdin, each behind its label, made safe to print, and cut to a length that fits a screen.
say() { sed "s/^/($1) /" | plain | cut -c1-200; }

# odd_bytes: how many bytes of stdin are not plain text (printable ASCII, tab, newline). plain prints each as "?".
# control_bytes: how many of those are control characters. One of them, the carriage return, is a line
# break to YAML and to Python, so code behind it can pass for the rest of a comment. To YAML, so are U+0085, U+2028
# and U+2029, which UTF-8 spells in two or three bytes. Each counts as one. A NUL byte goes to sed as \001: POSIX does not say what sed does with one.
odd_bytes() { tr -d '[:print:]\n\t' | wc -c | tr -d ' '; }
control_bytes() {
  tr '\000' '\001' | LC_ALL=C sed "$(printf 's/\302\205/\001/g; s/\342\200\250/\001/g; s/\342\200\251/\001/g')" |
    tr -cd '\000-\010\013-\037\177' | wc -c | tr -d ' '
}

# guarded: NUL-separated paths on stdin. Prints every path that is NOT free, one per line, made
# safe to print. A path is free only if all of these hold:
#   - it uses a plain character set, and no component starts with a dot or a dash;
#   - it is not a file that an agent or GitHub treats as special wherever it lies. Such files are
#     caught by shape (an all-capitals Markdown name) as well as by name, in any mix of capitals;
#   - it does not lie under docs/adr/accepted/, where the maintainer puts the accepted decisions;
#   - it matches the allowlist ($FREE_LIST, by default the one beside this script).
# A newline inside a name becomes an unprintable byte first, so it cannot split one name into two.
# An unreadable allowlist locks everything.
guarded() {
  LC_ALL=C tr '\n\000' '\001\n' | LC_ALL=C awk -v list="${FREE_LIST:-$here/free-paths.txt}" '
    BEGIN {
      while ((getline line < list) > 0) if (line != "" && line !~ /^#/) free[++n] = line
      if (n == 0) print "(the allowlist is missing or empty)"
    }
    $0 == "" { next }
    {
      ok = 0; low = tolower($0); name = $0; sub(/^.*\//, "", name)
      named = ($0 ~ /^loop\/state\/[A-Z]+\.md$/ || $0 == "README.md") # the allowlist names these exactly
      if ($0 ~ /^[A-Za-z0-9._\/+-]+$/ && $0 !~ /(^|\/)[.-]/ &&
          (named || name !~ /^[A-Z][A-Z0-9_.-]*\.[Mm][Dd]$/) &&
          low !~ /^docs\/adr\/accepted(\/|$)/ &&
          low !~ /(^|\/)((claude|agents?|gemini|qwen|warp|crush|iflow|codex|skill|conventions)((\.[^\/]*)?\.md|\.mdc|\.markdown|\.txt)?|copilot-instructions\.md)$/ &&
          low !~ /^docs\/(contributing|support|security|governance|code_of_conduct|accessibility)(\.[^\/]*)?$/ && # GitHub reads these at the root, in .github/ and here
          low !~ /(^|\/)(codeowners|funding\.yml|opencode\.jsonc?|staticcheck\.conf|(pull_request|issue)_template[^\/]*)(\/|$)/)
        for (i = 1; i <= n; i++) if ($0 ~ free[i]) { ok = 1; break }
      if (!ok) { gsub(/[^ -~]/, "?"); gsub(/::/, ": :"); gsub(/##\[/, "# #["); print }
    }'
}

# special_entries <tree-ish>: symbolic links and submodules, which are never free.
special_entries() { git ls-tree -r "$1" | LC_ALL=C awk '$1 == "120000" || $1 == "160000"'; }

# case_twins <tree-ish>: files and directories that differ only in case. They cannot both exist on a Mac.
case_twins() {
  git ls-tree -r -t -z --name-only "$1" | LC_ALL=C tr '\n\000' '\001\n' | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C sort | uniq -d
}

# only_new <label> <old file> <new file>: lines of the second sorted file that the first lacks.
only_new() {
  LC_ALL=C comm -13 "$2" "$3" >"$tmp/fresh" || die "comm failed; refusing to continue" 4
  sed "s/^/($1) /" "$tmp/fresh" | plain || die "sed failed; refusing to continue" 4
}

# guarded_between <old-tree-ish> <new-tree-ish>: everything locked that differs.
# Any failure is fatal: this function never reports "nothing" because of an error.
guarded_between() {
  local side
  git diff -z --text --no-renames --name-only "$1" "$2" >"$tmp/list" || die "git diff failed; refusing to continue" 4
  for side in 1 2; do
    special_entries "${!side}" >"$tmp/links$side" || die "git ls-tree failed; refusing to continue" 4
    LC_ALL=C sort -o "$tmp/links$side" "$tmp/links$side" || die "sort failed; refusing to continue" 4
    case_twins "${!side}" >"$tmp/twins$side" || die "git ls-tree failed; refusing to continue" 4
  done
  guarded <"$tmp/list" || die "the path filter failed; refusing to continue" 4
  only_new "link or submodule" "$tmp/links1" "$tmp/links2"
  only_new "two names that differ only in case" "$tmp/twins1" "$tmp/twins2"
}

# yours_between <old-tree-ish> <new-tree-ish>: what only the maintainer may change in two FREE files.
# One line per reason. Silence means "nothing of yours changed", so every error in here is fatal.
#   PLAN.md  (human gate)       headings, code fences, comment marks, gate lines, and the indented lines under
#                               a gate. They are compared in file order, so a line that moves or gains a twin counts.
#            (gate dependency)  a unit or gate that no longer waits for a gate, or for `above`. New ones are free.
#            (plan)             a NUL byte, or a new line that is not plain ASCII: it could say one thing to a
#                               reader and another to these rules.
#   LOG.md   (log), (resume)    the log is append only, and an added heading must be a result of the loop, such as
#                               "## 2026-10-31T10:15Z U-004 PASS ...". Any other heading is yours, RESUME included.
yours_between() {
  local side
  for side in 1 2; do
    state_text "${!side}" loop/state/PLAN.md "$tmp/plan$side"
    state_text "${!side}" loop/state/LOG.md "$tmp/log$side"
    sort -u "$tmp/plan$side" >"$tmp/lines$side" || die "sort failed; refusing to continue" 4
    plan_view <"$tmp/plan$side" >"$tmp/view$side" || die "the plan filter failed; refusing to continue" 4
    plan_pairs <"$tmp/plan$side" | sort -u >"$tmp/pairs$side" || die "the plan filter failed; refusing to continue" 4
  done
  if ! same "$tmp/plan1.raw" "$tmp/plan1" || ! same "$tmp/plan2.raw" "$tmp/plan2"; then echo "(plan) holds a NUL byte"; fi
  if ! same "$tmp/log1.raw" "$tmp/log1" || ! same "$tmp/log2.raw" "$tmp/log2"; then echo "(log) holds a NUL byte"; fi
  comm -13 "$tmp/lines1" "$tmp/lines2" | awk '/[^ -~\t]/' | say "plan, not plain ASCII" || die "the plan filter failed; refusing to continue" 4
  if ! same "$tmp/view1" "$tmp/view2"; then
    diff "$tmp/view1" "$tmp/view2" >"$tmp/fresh" || [ $? -eq 1 ] || die "diff failed; refusing to continue" 4
    [ -s "$tmp/fresh" ] || die "diff failed; refusing to continue" 4
    sed -n 's/^< //p' "$tmp/fresh" | say "human gate" || die "sed failed; refusing to continue" 4
    sed -n 's/^> //p' "$tmp/fresh" | say "human gate, new" || die "sed failed; refusing to continue" 4
  fi
  comm -23 "$tmp/pairs1" "$tmp/pairs2" | sed 's/ / no longer waits for /' | say "gate dependency" || die "comm failed; refusing to continue" 4
  log_news "$tmp/log1" "$tmp/log2" | plain | cut -c1-200 || die "the log filter failed; refusing to continue" 4
}

# state_text <tree-ish> <path> <file>: the file as the tree has it goes to <file>.raw, and without its NUL bytes
# to <file>. Both are empty if the tree has no such path. ls-tree is asked first, so that an entry that is
# there but cannot be read (a blob that a partial clone could not fetch) is an error, not an absent file.
state_text() {
  local entry
  entry="$(git ls-tree "$1" -- "$2")" || die "git ls-tree failed; refusing to continue" 4
  : >"$3.raw" || die "could not write a scratch file; refusing to continue" 4
  [ -z "$entry" ] || git cat-file blob "$1:$2" >"$3.raw" || die "could not read $2; refusing to continue" 4
  tr -d '\000' <"$3.raw" >"$3" || die "tr failed; refusing to continue" 4
}

# word(line): a plan line without its bullet and its box, so "- [x] H-103 | ..." gives "H-103 | ...". It is loose
# on purpose: "* [x] H-103" or "> 1. H-103" would read as the gate's line to a person or a model too.
# shellcheck disable=SC2016 # awk's own dollars and backticks
plan_word='function word(s) {
  sub(/^[^A-Za-z[]*/, "", s)
  if (s ~ /^\[/) { sub(/^\[[^]]*\]/, "", s); sub(/^[^A-Za-z]*/, "", s) }
  return s
}'

# plan_view: a plan on stdin. Prints the lines that are the maintainer's, in file order.
plan_view() {
  # shellcheck disable=SC2016
  awk "$plan_word"'
    /^[ \t]*#/ || /^[ \t]*(```|~~~)/ || /<!--|-->/ { print; own = 0; next }
    word($0) ~ /^H-[0-9]/ { print; own = 1; next }
    own && /^[ \t]+[^ \t]/ { print; next }
    { own = 0 }'
}

# plan_pairs: a plan on stdin. Prints "<ID> <dep>" for every unit or gate and each of its deps that is a gate or the
# word above. `above` also stands for every gate above that line, so a line that moves up loses pairs. If an ID
# has several lines, a pair counts only if all of them have it, so a twin with other deps cannot hide behind the
# original. A line with two deps fields has no pairs.
plan_pairs() {
  awk "$plan_word"'
    function note(pair) { if (seen[pair] != NR) { seen[pair] = NR; count[pair]++ } }
    {
      line = word($0)
      if (line !~ /^([A-Z]-[0-9]+[a-z]?|S-F[0-9]+)([^A-Za-z0-9-]|$)/) next
      id = line; sub(/[^A-Za-z0-9-].*$/, "", id)
      lines[id]++
      fields = split(line, field, "|"); found = 0
      for (i = 1; i <= fields; i++) { gsub(/[ \t]/, "", field[i]); if (field[i] ~ /^deps:/) { found++; deps = substr(field[i], 6) } }
      if (found == 1) {
        many = split(deps, dep, ",")
        for (i = 1; i <= many; i++) {
          if (dep[i] ~ /^H-[0-9]+[a-z]?$/) note(id " " dep[i])
          if (dep[i] == "above") { note(id " above"); for (g = 1; g <= gates; g++) note(id " " gate[g]) }
        }
      }
      if (id ~ /^H-/) gate[++gates] = id
    }
    END { for (pair in count) { split(pair, part, " "); if (count[pair] == lines[part[1]]) print pair } }'
}

# log_news <old log> <new log>: prints what the new log may not hold without the maintainer's signature.
log_news() {
  awk '
    side == 1 { was[++old] = $0; next }
    ++now <= old { if ($0 != was[now] && !lost) lost = now; next }
    {
      bare = $0; gsub(/[^ -~]/, "", bare) # a heading stays one to a reader, whatever unprintable bytes stand before or inside it
      if (bare ~ /^ *##/) {
        if ($0 !~ /^## [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]Z ([A-GI-Z]-[0-9]+[a-z]?|S-F[0-9]+) (START|PASS|FAIL|BLOCKED|SPLIT)( [ -~]*)?$/)
          print (toupper(bare) ~ /RESUME/ ? "(resume) " : "(log) not a result of the loop: ") $0
        next
      }
      bare = $0; gsub(/\t/, "", bare)
      if (bare ~ /[[:cntrl:]]/) print "(log) holds a control character: " $0
    }
    END {
      if (now < old && !lost) lost = now + 1
      if (lost) print "(log) is append only, but its line " lost " was changed or removed: " was[lost]
    }' side=1 "$1" side=2 "$2"
}

maintainer_fingerprint() {
  local f
  f="$(tr -d ' \n' <"$here/../.github/maintainer.fpr" 2>/dev/null || true)"
  [[ "$f" =~ ^[0-9A-F]{40}$ ]] || die "no valid fingerprint beside these scripts (.github/maintainer.fpr)" 4
  printf '%s' "$f"
}

# signed_by <fingerprint> commit|tag <object>: git must accept the signature AND it must come from that
# key. Uses whatever keyring GNUPGHOME points at. gpg says both on one line, which holds no text that a signer chooses:
#   [GNUPG:] VALIDSIG <the key that signed> <date> <seconds since 1970> ... <its primary key>
# The time is when the signature was made. It is part of what was signed, and it is left in $signed_at.
# shellcheck disable=SC2034 # guard.sh reads it
signed_by() {
  local report line
  signed_at=""
  report="$(git "verify-$2" --raw "$3" 2>&1)" || return 1
  line="$(printf '%s\n' "$report" | LC_ALL=C grep -a -E -- "^\[GNUPG:\] VALIDSIG .*$1\$")" || return 1
  case "$line" in *$'\n'*) return 1 ;; esac # one signature, one line
  line="${line#\[GNUPG:\] VALIDSIG * * }"
  [[ "${line%% *}" =~ ^[1-9][0-9]{0,11}$ ]] || return 1
  signed_at="${line%% *}"
}

# signed_by_maintainer commit|tag <object>: the same, for the pinned key.
signed_by_maintainer() {
  local fingerprint
  fingerprint="$(maintainer_fingerprint)" || return 1
  signed_by "$fingerprint" "$1" "$2"
}

# reviewed_by_maintainer <commit>: signed, and the LAST line of the signed message says that the
# maintainer read the locked paths. land.sh writes that line only after showing the diff and
# hearing "y", so a signature given to ordinary work never authorises a locked change.
REVIEWED="Locked-paths: reviewed"
reviewed_by_maintainer() {
  signed_by_maintainer commit "$1" || return 1
  [ "$(git cat-file commit "$1" | tail -n 1)" = "$REVIEWED" ]
}

# differs_from_kit <tree-ish>: prints every locked file that is not the same in the tree and in the kit: the
# same bytes, a plain file, the same executable bit. The whole kit is searched, so a locked file that main has
# lost is noticed wherever it lay. What the Finder or an editor left in the kit is passed over, as in setup-1.
# Any failure is fatal, so that silence always means "identical".
differs_from_kit() {
  local root path entry mode blob
  root="$(dirname "$here")"
  git ls-tree -r -z --name-only "$1" >"$tmp/kit-list" || die "git ls-tree failed" 4
  guarded <"$tmp/kit-list" >"$tmp/kit-names" || die "the path filter failed" 4
  while IFS= read -r path; do
    entry="$(git ls-tree "$1" -- "$path")" || die "git ls-tree failed" 4
    mode="${entry%% *}" blob="${entry#* * }"
    if [ ! -f "$root/$path" ] || [ -L "$root/$path" ]; then echo "only in the repository: $path"
    elif [ "$mode" != 100644 ] && [ "$mode" != 100755 ]; then echo "not a plain file in the repository: $path"
    elif [ "${blob%%[!0-9a-f]*}" != "$(git hash-object --no-filters "$root/$path")" ]; then echo "differs: $path"
    elif [ "$mode" = 100755 ] && [ ! -x "$root/$path" ]; then echo "executable only in the repository: $path"
    elif [ "$mode" = 100644 ] && [ -x "$root/$path" ]; then echo "executable only in the kit: $path"; fi
  done <"$tmp/kit-names"
  sort -o "$tmp/kit-names" "$tmp/kit-names" || die "sort failed" 4
  (cd "$root" && find . -type f ! -name .DS_Store ! -name '._*' ! -name '*.swp' ! -name '*~' -print0) | tr '\n\000' '\001\n' | sed 's/^\.\///' | tr '\001\n' '\n\000' >"$tmp/kit-list" ||
    die "could not list the kit" 4
  guarded <"$tmp/kit-list" | sort >"$tmp/kit-own" || die "the path filter failed" 4
  comm -13 "$tmp/kit-names" "$tmp/kit-own" | sed 's/^/only in the kit: /' || die "comm failed" 4
}

# nothing_open: stops while one of your own pull requests into main is open. land.sh could not finish beside it.
nothing_open() {
  local open
  open="$(gh pr list --repo "$slug" --base main --state open --author "@me" --json number,headRefName,isCrossRepository \
    --jq '.[] | select(.isCrossRepository | not) | "  #\(.number) \(.headRefName)"' | plain)" || die "gh could not list pull requests" 2
  [ -z "$open" ] || die "one of your pull requests into main is still open:
$open
Switch the scheduled task off and wait for it to finish. If it is a mac/ or selftest branch, or a try: whose run is dead, close it on GitHub and run this again" 3
}
