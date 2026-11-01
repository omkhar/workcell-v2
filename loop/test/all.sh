#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Runs every test in this folder, one after the other, and says at the end which passed.
# Nothing here touches the network, GitHub, your keys or your git settings. It takes about twenty minutes.
#   suite.sh                 the scripts that lock, land, adopt and checkpoint   needs git, gpg, jq
#   gate-test.sh             loop/gate.sh                                        needs git, and go as new as go.mod asks
#   check-prompt.sh          the commands that loop/PROMPT.md hands to the loop  needs git, jq
#   check-plan.py            the format of the plan, and a dry run of the loop   needs python3
#   check-plan-selftest.py   that check-plan.py can fail                         needs python3
#   check-rules.py           the halt, resume and retry rules of PROMPT.md       needs python3
#   check-deny.py            Claude Code's deny rules against PROMPT.md          needs python3
# A test whose tool is missing is reported as SKIPPED, which is not a pass.
set -uo pipefail
export GOTOOLCHAIN=local # an older go must say so and stop. Left alone, it would download the toolchain that go.mod names
here="$(cd "$(dirname "$0")" && pwd)" || exit 2
passed=0 failed=0 skipped=0 report=""

run() { # run <tool it needs> <name> <command>...
  local tool="$1" name="$2" verdict
  shift 2
  echo
  echo "=== $name"
  if ! command -v "$tool" >/dev/null 2>&1; then
    verdict="SKIPPED ($tool is not installed)" skipped=$((skipped + 1))
  elif "$@"; then
    verdict="passed" passed=$((passed + 1))
  else
    verdict="FAILED" failed=$((failed + 1))
  fi
  report="$report$(printf '  %-24s %s' "$name" "$verdict")
"
}

cd "$here/../.." || exit 2
run gpg suite.sh "$here/suite.sh"
run go gate-test.sh "$here/gate-test.sh"
run jq check-prompt.sh "$here/check-prompt.sh"
for check in check-plan.py check-plan-selftest.py check-rules.py check-deny.py; do
  run python3 "$check" python3 -I "$here/$check"
done

echo
echo "=== all.sh"
printf '%s' "$report"
echo "ALL: $passed passed, $failed failed, $skipped skipped"
[ "$failed" -eq 0 ] && [ "$skipped" -eq 0 ]
