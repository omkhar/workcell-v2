#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Mac only, from your unpacked kit, inside your own clone. Capture how v1's CI behaves, so that
# v2 has something honest to beat. It only reads omkhar/workcell. Writes loop/baseline/ci.tsv.
set -euo pipefail
# shellcheck source=loop/lib.sh
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
cd "$repo"
gh run list --repo "${1:-omkhar/workcell}" --limit 500 \
  --json workflowName,event,conclusion,headBranch,attempt,createdAt,updatedAt >"$tmp/runs.json"
{
  printf 'workflow\truns\tfailed\tcancelled\treruns\tmedian_min\tp90_min\n'
  # Only runs that v1's own branches started: an outsider's pull request can bring a workflow, and choose its name.
  # Only names that are plainly names: this text goes into the repository, under your signature, and an agent reads it.
  jq -r 'map(select((.event == "push" or .event == "schedule") and (.workflowName // "" | test("\\A[A-Za-z0-9 ._-]{1,40}\\z"))))
    | group_by(.workflowName)[]
    | (map(((.updatedAt | fromdate) - (.createdAt | fromdate)) / 60) | sort) as $d
    | [.[0].workflowName, length,
       (map(select(.conclusion == "failure")) | length),
       (map(select(.conclusion == "cancelled")) | length),
       (map(select(.attempt > 1)) | length),
       ($d[(length / 2 | floor)] | floor), ($d[(length * 0.9 | floor)] | floor)]
    | @tsv' "$tmp/runs.json"
} >"$tmp/ci.tsv"
mkdir -p loop/baseline
rm -f loop/baseline/ci.tsv
plain <"$tmp/ci.tsv" >loop/baseline/ci.tsv # workflow names are someone else's text
cat loop/baseline/ci.tsv
