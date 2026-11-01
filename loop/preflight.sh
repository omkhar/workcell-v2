#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only, from your unpacked kit, inside your own clone: is this Mac ready to sign, and are the
# locked files on main still the ones you signed? It changes nothing. Run it whenever you like.
set -uo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo" || exit 1
bad=0
ok() { printf '  ok    %s\n' "$1"; }
no() { printf '  FAIL  %s\n' "$1"; bad=1; }

for tool in git gpg gh jq; do
  if command -v "$tool" >/dev/null; then ok "$tool"; else no "$tool is not installed (brew install $tool)"; fi
done
if gh auth status >/dev/null 2>&1; then ok "gh is signed in"; else no "gh is not signed in (gh auth login)"; fi
case "$here/" in
  "$repo"/*) no "you are running the copy inside the repository; run the one in your unpacked kit" ;;
  *) ok "running from $here, outside the repository" ;;
esac
if [ "$(git branch --show-current)" = main ]; then ok "on branch main"; else no "not on branch main"; fi
fetch_refs "$TRUNK_SPEC" || no "could not fetch main"
if ! stale="$(differs_from_kit "$TRUNK")"; then
  no "could not compare your kit with main"
elif [ -z "$stale" ]; then
  ok "the locked files on main are identical to your kit"
else
  no "the locked files on main differ from your kit. See REFERENCE.md section 8, 'If something locked changed without you':"
  printf '%s\n' "$stale" | sed 's/^/          /'
fi
name="$(git config user.name || true)" email="$(git config user.email || true)"
if [ -n "$name" ] && [ -n "$email" ]; then ok "identity: $name <$email>"; else no "set git user.name and user.email"; fi
if object="$(signing commit-tree -S -m 'preflight signing test' 'HEAD^{tree}' 2>/dev/null)" && signed_by_maintainer commit "$object"; then
  ok "a test object was signed by $(maintainer_fingerprint) (it is unreferenced, and git will prune it)"
else
  no "a test signature did not verify against .github/maintainer.fpr. Try: gpg --clearsign <<< test"
fi
exit "$bad"
