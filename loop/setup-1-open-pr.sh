#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# STEP 1 of 2, on the Mac. Fills the new, empty repository and opens ONE pull request that adds the kit.
#   ~/loopkit/loop/setup-1-open-pr.sh [directory]        (default: ~/workcell-v2)
# It makes two commits, both signed with your key:
#   main = v1's main, minus the v1 tree (a few reference packages move to _legacy/)
#   kit  = main, plus this kit          <- the pull request shows exactly these files
# It only ever reads omkhar/workcell. It asks before it pushes anything. It is safe to run again.
# It publishes one user ID of your key: the one with git's user.email, or with the address in LOOP_UID.
set -euo pipefail
kit="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$HOME/workcell-v2}"
case "$dir" in /*) ;; *) dir="$PWD/$dir" ;; esac
slug="${LOOP_SLUG:-omkhar/workcell-v2}"
url="${LOOP_URL:-https://github.com/$slug.git}"
v1_url="${LOOP_V1_URL:-https://github.com/omkhar/workcell.git}"
fingerprint="$(printf '%s' "${LOOP_KEY:-90554248C4F7CC086BB745D0DA5A8E9F536C42FD}" | tr -d ' ')"
stop() { echo "STOP: $1" >&2; exit 1; }
if terminal="$(tty 2>/dev/null)"; then export GPG_TTY="$terminal"; fi # lets a terminal pinentry ask for your passphrase
export COPYFILE_DISABLE=1 GIT_CONFIG_NOSYSTEM=1
# Network calls use the token that gh holds, so nothing depends on your keychain.
net() { git -c push.followTags=false -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"; }
next="$kit/loop/setup-2-after-merge.sh"
[ "$dir" = "$HOME/workcell-v2" ] || next="$next $dir"
open_pr() { # gh looks for the branch name alone, newest first. An outsider's fork can hold a branch called kit too, so only this repository's own counts
  gh pr list --repo "$slug" --base main --head kit --state all --json url,isCrossRepository --jq '[.[] | select(.isCrossRepository | not)][0].url // empty' | grep . ||
    gh pr create --repo "$slug" --base main --head kit --title "Add the loop kit" --body-file "$kit/loop/PR-BODY.md"
}
finish() {
  local link
  link="$(open_pr)" || stop "both branches are pushed, but the pull request could not be opened. It is safe to run this script again"
  echo
  echo "DONE. Read this pull request, then click \"Squash and merge\":"
  echo "  $link"
  echo "No checks run on it: the workflows it adds start to work only once they are on main."
  echo "Then run:  $next"
  exit 0
}
merged() { # GitHub says so, or main over there descends from this clone's main and holds exactly the kit's tree
  [ -z "$(gh pr list --repo "$slug" --base main --head kit --state merged --json url,isCrossRepository --jq '[.[] | select(.isCrossRepository | not)][0].url // empty' 2>/dev/null)" ] || return 0
  net fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main 2>/dev/null || return 1
  [ "$(git rev-parse refs/remotes/origin/main)" != "$(git rev-parse refs/heads/main)" ] || return 1
  git merge-base --is-ancestor refs/heads/main refs/remotes/origin/main || return 1
  [ "$(git rev-parse 'refs/remotes/origin/main^{tree}')" = "$(git rev-parse 'refs/heads/kit^{tree}')" ]
}

echo "loop kit, version 4"
for tool in git gpg gh jq; do command -v "$tool" >/dev/null || stop "$tool is not installed (brew install $tool)"; done
gh auth status >/dev/null 2>&1 || stop "gh is not signed in (run: gh auth login)"
scopes="$(gh auth status 2>&1 | grep -i 'token scopes' || true)"
case "$scopes" in
  "" | *workflow*) ;;
  *) stop "gh may not push workflow files yet. Run this, then start again:  gh auth refresh -h github.com -s workflow" ;;
esac
gpg --list-secret-keys "$fingerprint" >/dev/null 2>&1 || stop "your signing key $fingerprint is not in this Mac's keyring"
email="$(git config user.email || true)"
[ -n "$(git config user.name || true)" ] && [ -n "$email" ] ||
  stop "git does not know who you are. Set user.name and user.email with: git config --global"
case "$dir/" in "$kit"/*) stop "choose a directory outside the kit" ;; esac
[ "$(gh api "repos/$slug" --jq .visibility 2>/dev/null || true)" = public ] ||
  stop "the repository $slug does not exist yet, or is not public. Create it first: START-HERE.md step 1"
heads="$(net ls-remote --heads "$url" | awk '{ print $2 }' | LC_ALL=C sort | tr '\n' ' ')" || stop "cannot read $url"
probe="$(mktemp -d)" # scratch files, and the keyring of the proof below: gpg needs a short path for its socket
trap 'rm -rf "$probe"' EXIT
# Claude Code's project settings travel under a plain name, and take their real name here, on your Mac.
if [ -f "$kit/loop/claude-settings.json" ]; then mv "$kit/loop/claude-settings.json" "$kit/.claude/settings.json"; fi
again="Move $dir away and run this again" made=no

if [ -d "$dir/.git" ]; then # a second run: carry on from where the first one stopped
  cd "$dir"
  if merged; then
    echo "The kit pull request is already merged, so there is nothing left to do here."
    echo "Next:  $next"
    exit 0
  fi
  if [ -n "$heads" ]; then # something has been published. Starting afresh means a new repository, unless this one is in use
    marks="$(net ls-remote "$url" 'refs/checkpoints/*')" || stop "cannot read $url"
    again="Delete the repository on GitHub, create it again, move $dir away, and run this again"
    [ -z "$marks" ] || again="GitHub holds checkpoints, so that repository is in use. Do not delete it. This script is only for a new, empty repository"
  fi
  git verify-commit refs/heads/kit >/dev/null 2>&1 || stop "$dir exists but holds no signed kit branch. $again"
  for head in $heads; do # whatever has already arrived must be exactly what this clone holds
    case "$head" in
      refs/heads/main | refs/heads/kit)
        [ "$(net ls-remote "$url" "$head" | cut -f1)" = "$(git rev-parse "$head")" ] || stop "$head on GitHub is not the commit in $dir. $again"
        ;;
      *) stop "$slug holds a branch this script did not make ($head). $again" ;;
    esac
  done
else
  [ ! -e "$dir" ] || stop "$dir exists and is not a clone made by this script; move it away or pass another directory"
  [ -z "$heads" ] || stop "$slug is not empty ($heads). This script needs a new, empty repository: no README, no licence"
  # The public key, stripped to what a signature check needs: one user ID, signing keys, no third-party signatures.
  uid="${LOOP_UID:-$email}"
  [[ "$uid" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] || stop "'$uid' is not a plain e-mail address. Set LOOP_UID to the e-mail address of the user ID you want published"
  gpg --armor --export-options export-minimal --export-filter "keep-uid=mbox = $uid" \
    --export-filter 'drop-subkey=usage !~ s' --export "$fingerprint" >"$probe/export.asc"
  [ "$(gpg --show-keys --with-colons "$probe/export.asc" 2>/dev/null | grep -c '^uid:')" != 0 ] ||
    stop "no user ID on your key has the e-mail address $uid. Set LOOP_UID to the e-mail address of the user ID you want published, and run this again"

  echo "1/5 copying v1's history into $dir (read only; nothing is ever pushed to v1)"
  net clone --quiet --origin v1 --no-tags "$v1_url" "$dir"
  cd "$dir"
  git remote set-url --push v1 "no-push-to-v1"
  git remote add origin "$url"
  git config user.signingkey "$fingerprint"
  git config gpg.format openpgp
  for path in scripts/workcell docs/threat-model.md policy/provider-bumps.toml internal/metadatautil/provider_bumps.go \
    internal/metadatautil/upstream_fetch.go internal/egressproxy internal/credbroker internal/rootio internal/secretfile \
    internal/jsonstrict internal/ocsf internal/host/auditlog internal/host/auditseal internal/host/keystore \
    LICENSE NOTICE SECURITY.md CODE_OF_CONDUCT.md CITATION.cff; do
    [ -e "$path" ] || { cd /; rm -rf "${dir:?}"; stop "v1 has changed: $path is gone. This kit was made for commit 21a8fc1. Nothing was pushed"; }
  done

  echo "2/5 branch main: removing the v1 tree, keeping reference code in _legacy/"
  git switch --quiet --no-track -C main refs/remotes/v1/main
  mkdir -p _legacy/bump
  grep -oE '^[[:space:]]+--[a-z0-9-]+' scripts/workcell | tr -d ' \t' | LC_ALL=C sort -u >_legacy/flags.txt
  for package in egressproxy credbroker rootio secretfile jsonstrict ocsf \
    host/auditlog host/auditseal host/keystore; do
    git mv "internal/$package" "_legacy/$(basename "$package")"
  done
  for adapter in adapters/*/adapter.toml; do # data only: no dotfiles, no agent instruction files
    mkdir -p "_legacy/$(dirname "$adapter")"
    git mv "$adapter" "_legacy/$adapter"
  done
  git mv docs/threat-model.md _legacy/threat-model.md
  git mv policy/provider-bumps.toml internal/metadatautil/provider_bumps.go \
    internal/metadatautil/upstream_fetch.go scripts/verify-upstream-*-release.sh _legacy/bump/
  git rm -rq -- . ':(exclude)_legacy' ':(exclude)LICENSE' ':(exclude)NOTICE' \
    ':(exclude)SECURITY.md' ':(exclude)CODE_OF_CONDUCT.md' ':(exclude)CITATION.cff'
  git -c core.excludesFile=/dev/null add -A # your own global ignore list must not decide what is published
  git commit --quiet -S -m "Remove the v1 tree; keep reference code in _legacy/"

  echo "3/5 branch kit: adding the kit"
  git switch --quiet -c kit
  (cd "$kit" && tar -cf - --exclude .DS_Store --exclude '._*' --exclude '*.swp' --exclude '*~' .) | tar -xf - -C "$dir"
  printf '%s\n' "$fingerprint" >.github/maintainer.fpr
  cp "$probe/export.asc" .github/maintainer.asc
  git -c core.excludesFile=/dev/null add -A
  git commit --quiet -S -m "Add the loop kit"
  made=yes
fi

# Both kinds of run meet here. What you signed must be this kit, byte for byte.
[ "$(git rev-parse --quiet --verify 'refs/heads/kit^' || true)" = "$(git rev-parse refs/heads/main)" ] ||
  stop "the kit branch in $dir was never finished: it is not one commit on top of main. $again"
# From now on the kit holds a copy of every locked file, so that it can notice if one changes. These were written above, or
# kept from v1. A later run hands over only what the kit lacks: whatever it holds already is compared, like all the rest.
for path in .github/maintainer.asc .github/maintainer.fpr LICENSE NOTICE SECURITY.md CODE_OF_CONDUCT.md CITATION.cff; do
  if [ "$made" = no ] && [ -e "$kit/$path" ]; then continue; fi
  git cat-file blob "refs/heads/kit:$path" >"$probe/blob" || stop "the kit branch in $dir lacks $path. $again"
  cp "$probe/blob" "$kit/$path"
done
(cd "$kit" && find . -type f ! -name .DS_Store ! -name '._*' ! -name '*.swp' ! -name '*~' -print) | sed 's#^\./##' | LC_ALL=C sort >"$probe/in-kit" ||
  stop "could not list the files of the kit"
git diff --no-renames --name-only refs/heads/main refs/heads/kit >"$probe/in-commit" || stop "could not list the files of the kit branch"
odd=""
while IFS= read -r path; do
  [ "$(git rev-parse --quiet --verify "refs/heads/kit:$path" || true)" = "$(git hash-object --no-filters "$kit/$path")" ] || odd="$odd
        $path"
done <"$probe/in-kit"
while IFS= read -r path; do
  [ -f "$kit/$path" ] || odd="$odd
        $path"
done <"$probe/in-commit"
[ -z "$odd" ] || stop "these files are not the same in your kit and in the kit branch that you signed:$odd
Put them back as they were. Or start afresh: $again"

# Prove now what guard will need later: the published key alone verifies your signature.
git cat-file blob refs/heads/kit:.github/maintainer.asc >"$probe/key.asc" || stop "the kit branch in $dir holds no public key. $again"
GNUPGHOME="$probe" gpg --quiet --batch --import "$probe/key.asc" 2>/dev/null || stop "gpg cannot import the public key in the kit branch. $again"
GNUPGHOME="$probe" git verify-commit --raw refs/heads/kit 2>&1 | grep -c "VALIDSIG .*$fingerprint\$" >/dev/null ||
  stop "the public key in the kit branch does not verify your own signature on it. $again"
[ "$heads" != "refs/heads/kit refs/heads/main " ] || finish # both branches have arrived already

echo "4/5 ready to publish to $slug:"
echo "      main  $(git ls-tree -r --name-only refs/heads/main | wc -l | tr -d ' ') files (v1's main has $(git ls-tree -r --name-only refs/remotes/v1/main | wc -l | tr -d ' '))"
echo "      kit   adds these $(wc -l <"$probe/in-commit" | tr -d ' ') files:"
sed 's/^/        /' "$probe/in-commit"
echo "      the public key in .github/maintainer.asc:"
gpg --show-keys "$probe/key.asc" 2>/dev/null | sed 's/^/        /'
printf '    Push both branches to %s and open the pull request? [y/N] ' "$slug"
read -r answer || answer=""
[ "$answer" = y ] || stop "nothing was pushed. Run this script again when you are ready"
# From the first moment there is a main to aim at, only you can open a pull request. setup-2 sets this again and reads it back, so a failure here is not fatal.
gh api -X PATCH "repos/$slug" -f pull_request_creation_policy=collaborators_only >/dev/null 2>&1 || true
net push --quiet --atomic -u origin refs/heads/main refs/heads/kit

echo "5/5 opening the pull request"
finish
