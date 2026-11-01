#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# guard.sh <base-commit> <head-commit>
# Run from a checkout of the live tip of the base branch. It reads the pull request's objects and
# never executes them. Every pull request must sit on that tip, so that the tree judged here is
# exactly the tree a squash merge will produce. Anything outside loop/free-paths.txt passes only
# as one commit that the maintainer signed after reviewing it, in the last two hours. Every error is a failure.
set -euo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo"
base="$(git rev-parse --verify --quiet "${1:?base commit}^{commit}")" || die "GUARD FAIL: the base commit is missing"
head="$(git rev-parse --verify --quiet "${2:?head commit}^{commit}")" || die "GUARD FAIL: the head commit is missing"
git merge-base --is-ancestor "$base" "$head" ||
  die "GUARD FAIL: the branch is not built on the current tip of the base; start again from the tip"

locked="$(guarded_between "$base" "$head")" || die "GUARD FAIL: could not compare the trees"
yours="$(yours_between "$base" "$head")" || die "GUARD FAIL: could not compare the plan"
if [ -z "$locked$yours" ]; then
  echo "GUARD PASS: only free paths changed"
  exit 0
fi
echo "Only the maintainer may change these:"
printf '%s\n' "$locked" "$yours" | sed -e '/^$/d' -e 's/^/  /'

[ "$(git rev-list --parents -n 1 "$head")" = "$head $base" ] ||
  die "GUARD FAIL: such a change must be exactly one commit, with the base tip as its only parent"
# A keyring that holds the pinned key and nothing else. It sits in the ordinary temporary folder
# because gpg needs a short path for its socket; nothing from the pull request runs on this machine.
GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'rm -rf "$tmp" "$GNUPGHOME"' EXIT
gpg --quiet --batch --import "$here/../.github/maintainer.asc" || die "GUARD FAIL: could not import the maintainer key"
if [ -n "$locked" ]; then
  reviewed_by_maintainer "$head" || die "GUARD FAIL: locked paths need the maintainer's reviewed signature"
  how="signed by the maintainer as reviewed"
else
  signed_by_maintainer commit "$head" || die "GUARD FAIL: gates, gate dependencies and the log's past need the maintainer's signature"
  how="signed by the maintainer"
fi
# A signature has a short life. land.sh gives the checks forty minutes. If the maintainer gave up on a landing,
# the signed commit stays public, and nobody else shall land it for as long as main happens to stand still.
# This binds only a new run: a green guard that the commit already has stays on it (REFERENCE.md section 9).
now="$(date +%s)" || die "GUARD FAIL: could not read the clock"
[[ "$now" =~ ^[1-9][0-9]*$ ]] || die "GUARD FAIL: could not read the clock"
[ "$((now - signed_at))" -le 7200 ] || die "GUARD FAIL: the signature is more than two hours old. Run land.sh again to sign the change afresh"
[ "$((signed_at - now))" -le 600 ] || die "GUARD FAIL: the signature is dated more than ten minutes ahead of this machine's clock"
echo "GUARD PASS: one commit, on the current base, $how"
