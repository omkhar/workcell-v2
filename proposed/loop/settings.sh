#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only, from your unpacked kit, inside your own clone.
#   settings.sh apply   set every GitHub setting the lock depends on, then read each one back
#   settings.sh check   only read them back (checkpoint.sh does this every time)
# Everything that 'apply' sets needs Administration access. You have it. The Claude GitHub App does not.
# A setting counts as right only if GitHub itself reports it so. A failed read is a failure.
set -uo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
mode="${1:-check}"
case "$mode" in apply | check) ;; *) die "usage: settings.sh apply|check" 2 ;; esac
bad=0
want() { # want <what it means> <expected> <what GitHub reports>
  if [ -n "$2" ] && [ "$3" = "$2" ]; then
    printf '  ok    %s\n' "$1"
  else
    printf '  WRONG %s\n          GitHub reports: %s\n          expected:       %s\n' "$1" \
      "$(printf '%s' "${3:-(nothing; the read failed)}" | plain)" "${2:-(nothing; the file in your kit could not be read)}"
    bad=1
  fi
}
ask() { gh api "$@" 2>/dev/null || true; } # an empty answer never equals an expected value
ours() { jq -r "$2" "$here/$1" 2>/dev/null || true; } # ours <payload file> <jq expression>: what the file in your kit says
as_in_kit() { # as_in_kit <what it means> <payload file> <path below the repository> <jq expression>: GitHub must report what that file says
  want "$1" "$(ours "$2" "$4")" "$(ask "repos/$slug/$3" --jq "$4")"
}
id_of() { ask "repos/$slug/$1" --jq "$2 | select(.name == \"$(jq -r .name "$here/$3")\") | .id" | head -n 1; }
upsert() { # upsert <collection> <jq path to the list> <payload file> [<file to send in its place>]: update the one with this name, or create it
  local id body="${4:-$here/$3}"
  id="$(id_of "$1" "$2" "$3")"
  if [ -n "$id" ]; then gh api -X PUT "repos/$slug/$1/$id" --input "$body" >/dev/null 2>&1
  else gh api -X POST "repos/$slug/$1" --input "$body" >/dev/null 2>&1; fi
}

if [ "$mode" = apply ]; then # failures show up in the read-back below
  gh api -X PATCH "repos/$slug" -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
    -F allow_auto_merge=false -F delete_branch_on_merge=true -F has_wiki=false >/dev/null 2>&1
  gh api -X PATCH "repos/$slug" -f pull_request_creation_policy=collaborators_only >/dev/null 2>&1 # this one does not expire
  gh api -X POST "repos/$slug/labels" -f name=loop-halt -f color=D93F0B -f description="Stops the loop while open" >/dev/null 2>&1
  gh api -X PUT "repos/$slug/actions/permissions/workflow" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null 2>&1
  gh api -X PUT "repos/$slug/interaction-limits" -f limit=collaborators_only -f expiry=six_months >/dev/null 2>&1
  # GitHub's API description says that targeting by workflow path can be unavailable. If the condition is refused,
  # send the policy without it: a policy that stores no condition covers every workflow file.
  if ! upsert actions/policies '.policies[]' github-actions-policy.json; then
    jq 'del(.conditions)' "$here/github-actions-policy.json" >"$tmp/policy.json" 2>/dev/null
    upsert actions/policies '.policies[]' github-actions-policy.json "$tmp/policy.json"
  fi
  upsert rulesets '.[]' github-main.json
  upsert rulesets '.[]' github-tags-all.json
fi

want "public, default branch main, squash merges only, no auto-merge, merged branches deleted, no wiki, pull requests from collaborators only" \
  "public main true false false false true false collaborators_only" \
  "$(ask "repos/$slug" --jq '[.visibility, .default_branch, .allow_squash_merge, .allow_merge_commit, .allow_rebase_merge, .allow_auto_merge,
    .delete_branch_on_merge, .has_wiki, .pull_request_creation_policy] | map(tostring) | join(" ")')"

# What a rule is aimed at counts as much as what it says: a rule that is aimed at nothing protects nothing.
aim='"\(.target) include=\(.conditions.ref_name.include | sort | join(",")) exclude=\(.conditions.ref_name.exclude | sort | join(","))"'
id="$(id_of rulesets '.[]' github-main.json)"
want "main: pull request, squash, up to date, gate, gate-macos and guard from GitHub Actions, no force push, no bypass for anyone" \
  "active 0 deletion+non_fast_forward+pull_request+required_linear_history+required_status_checks squash true gate-macos:15368+gate:15368+guard:15368" \
  "$(ask "repos/$slug/rulesets/${id:-0}" --jq '[.enforcement, (.bypass_actors | length), ([.rules[].type] | sort | join("+")),
    (.rules[] | select(.type == "pull_request") | .parameters.allowed_merge_methods | join("+")),
    (.rules[] | select(.type == "required_status_checks") | .parameters | .strict_required_status_checks_policy,
      ([.required_status_checks[] | "\(.context):\(.integration_id)"] | sort | join("+")))] | map(tostring) | join(" ")')"
as_in_kit "those rules are aimed at the default branch, with no exception" github-main.json "rulesets/${id:-0}" "$aim"
want "and GitHub counts exactly those rules as in force on main" "$(ours github-main.json '[.rules[].type] | sort | join("+")')" \
  "$(ask "repos/$slug/rules/branches/main" --jq '[.[].type] | sort | join("+")')"

id="$(id_of actions/policies '.policies[]' github-actions-policy.json)"
want "only workflows from the default branch can run (events: pull_request_target, schedule)" "active pull_request_target+schedule" \
  "$(ask "repos/$slug/actions/policies/${id:-0}" --jq '[.enforcement, ([.rules[] | select(.type == "restrict_action_events") | .parameters.allowed_events[]] | sort | join("+"))] | join(" ")')"
as_in_kit "that policy covers every workflow file, with no exception" github-actions-policy.json "actions/policies/${id:-0}" \
  '(.conditions.workflow_path // {"include": ["~ALL"], "exclude": []}) | "include=\(.include | sort | join(",")) exclude=\(.exclude | sort | join(","))"'

id="$(id_of rulesets '.[]' github-tags-all.json)"
want "nobody can create, move or delete a tag, so nobody can publish a release" "active 0 creation+deletion+update" \
  "$(ask "repos/$slug/rulesets/${id:-0}" --jq '[.enforcement, (.bypass_actors | length), ([.rules[].type] | sort | join("+"))] | map(tostring) | join(" ")')"
as_in_kit "those rules are aimed at every tag, with no exception" github-tags-all.json "rulesets/${id:-0}" "$aim"
# Those rules take away no tag that came before them, and a release can be published on any tag that exists.
want "GitHub holds no tag at all" "0" "$(ask "repos/$slug/tags" --jq 'if type == "array" then length else "not a list" end')"

want "only you can open issues or comment (until $(ask "repos/$slug/interaction-limits" --jq '.expires_at // "?"' | cut -c1-10 | plain); 'settings.sh apply' renews it)" \
  "collaborators_only" "$(ask "repos/$slug/interaction-limits" --jq '.limit // "none"')"
want "workflow tokens are read-only unless a workflow asks for more" "read false" \
  "$(ask "repos/$slug/actions/permissions/workflow" --jq '[.default_workflow_permissions, .can_approve_pull_request_reviews] | map(tostring) | join(" ")')"
# Checked, not set. Each of these would be a way in, or a way out, that goes round the rules above.
want "no Actions secrets" "0" "$(ask "repos/$slug/actions/secrets" --jq .total_count)"
want "no releases, not even a draft" "0" "$(ask "repos/$slug/releases" --jq 'if type == "array" then length else "not a list" end')"
want "no deploy keys" "0" "$(ask "repos/$slug/keys" --jq 'if type == "array" then length else "not a list" end')"
want "nobody but you is a collaborator" "0" \
  "$(ask "repos/$slug/collaborators" --jq "if type == \"array\" then [.[] | select((.login | ascii_downcase) != (\"${slug%%/*}\" | ascii_downcase))] | length else \"not a list\" end")"
# A webhook here sees only what is public anyway, and the Claude app may make one for the task's trigger. So it is shown, not refused.
hooks="$(ask "repos/$slug/hooks" --jq 'if type == "array" then length else "not a list" end')"
case "$hooks" in
  0) printf '  ok    no webhooks\n' ;;
  '' | *[!0-9]*) want "the webhooks can be read" "a number" "$hooks" ;;
  *)
    printf '  NOTE  webhooks: %s, sending to: %s\n' "$hooks" \
      "$(ask "repos/$slug/hooks" --jq '[.[] | (.config.url // "") | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | sub("[/?#].*$"; "") | sub("^.*@"; "") | sub(":[0-9]*$"; "") | if . == "" then "(no address)" else . end] | unique | join(" ")' | plain)"
    printf '          The Claude app may have made one for the scheduled task. If you do not know a host, delete that webhook: REFERENCE.md section 2\n'
    ;;
esac
# GitHub opens a check suite on every push for each App installed here with checks: write, so the newest commit of main lists the
# Apps that could report a check. GitHub Actions appears there only once a workflow has run on that commit, and its checks are
# required above, so it is tolerated here and not expected. Any other App is a way to report checks that the kit does not know.
want "no App but claude and GitHub Actions has a check suite on the newest commit of main" "claude" \
  "$(ask "repos/$slug/commits/heads/main/check-suites?per_page=100" --jq '[.check_suites[].app.slug | select(. != "github-actions")] | sort | unique | join("+") | if . == "" then "none" else . end')"
want "no environments" "0" "$(ask "repos/$slug/environments" --jq '[.environments[].name] | length')"
want "the label loop-halt exists" "loop-halt" "$(ask "repos/$slug/labels/loop-halt" --jq .name)"
exit "$bad"
