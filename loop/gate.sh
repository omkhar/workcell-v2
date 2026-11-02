#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# The only definition of "green". Developers, the loop and CI all run this file.
# Order matters. The whole file is parsed before it starts. Sections 1 and 2 read the tree and keep
# what section 3 needs in variables. Section 3 compiles and lints first, then runs the VM suite, then
# the tests. So no code under test can rewrite a check, a list or the suite before it is used.
# On a Mac nothing from the repository is executed unless GATE_MACOS=1. Where ~/loopkit exists, which
# marks the maintainer's own account, nothing from the repository is executed on any system.
set -euo pipefail

main() {
  export LC_ALL=C # for bash itself and for every tool: a byte is a character, and a range such as [ -~] goes by byte value
  CDPATH='' cd "$(dirname "$0")/.."
  local start=$SECONDS module=github.com/omkhar/workcell/v2 code='\.(go|c|h|s|S|m|cc|cpp)$' nl='
'
  local os base list old new lost only_linux only_macos first odd tools_old tools_new tool checkers=''
  local all gone hidden files product long goroot gofmt unformatted pkgs ours linked smuggled only where vm unit
  fail() { # in CI the reason also becomes an annotation, which a session that cannot download logs can still read
    local why
    why="GATE FAIL: ${*//$nl/ }"
    why="${why//[^ -~]/?}" # plain characters only, and with no outside tool: this must work when one of them is broken
    echo "$why" >&2
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error::$why"; fi
    exit 1
  }
  must() { "$@" || fail "$*"; }
  # match: grep -E, except that "no line matches" is not an error. A real error still is.
  match() { grep -E "$@" || [ $? -eq 1 ]; }
  # missing <lines> <lines>: every line of the first list that the second list lacks.
  missing() {
    local a b
    a="$(printf '%s\n' "$1" | LC_ALL=C sort -u)" || return 1
    b="$(printf '%s\n' "$2" | LC_ALL=C sort -u)" || return 1
    LC_ALL=C comm -23 <(printf '%s\n' "$a") <(printf '%s\n' "$b")
  }
  ratchet() { # ratchet <complaint> <lines in the base> <lines here>: nothing may be lost
    lost="$(missing "$2" "$3")" || fail "cannot compare with the base ($1)"
    [ -z "$lost" ] || fail "$1: $lost"
  }
  in_base() { # in_base <path>: the file as the base has it, or nothing if the base has none
    local entry
    entry="$(git ls-tree "$base" -- "$1")" || return 1
    [ -z "$entry" ] || git cat-file blob "$base:$1"
  }

  # --- 1. Ratchets: what the base enforces, this tree enforces too (SPEC T7) ---
  os="$(uname -s)" || fail "uname failed"
  base="$(git rev-parse --verify --quiet "${GATE_BASE:-refs/remotes/origin/main}^{commit}")" ||
    fail "cannot find ${GATE_BASE:-refs/remotes/origin/main} to compare with"
  for list in escape/enforced.txt escape/enforced-macos.txt; do
    old="$(in_base "$list")" || fail "cannot read $list in the base"
    new='' odd=0
    if [ -e "$list" ]; then
      new="$(cat "$list")" || fail "cannot read $list"
      odd="$(tr -d '\t\n -~' <"$list" | wc -c | tr -d ' ')" || fail "cannot read $list" # how many other bytes it holds
    fi
    ratchet "invariants removed from $list" "$old" "$new"
    [ "$odd" = 0 ] || fail "$list may hold only printable ASCII, tabs and newlines"
    new="$(printf '%s\n' "$new" | match . | paste -sd, -)" || fail "cannot read $list" # I1,I2,... for -only
    if [ "$list" = escape/enforced.txt ]; then only_linux="$new"; else only_macos="$new"; fi
  done

  # go.mod is free. So it may hold nothing that swaps code (replace, exclude) or hides it (ignore).
  [ -f go.mod ] || fail "go.mod is missing"
  first="$(awk '!/^[[:space:]]*(\/\/.*)?$/ { print; exit }' go.mod)" || fail "cannot read go.mod"
  [ "$first" = "module $module" ] || fail "go.mod must start with the line: module $module"
  flat() { # a go.mod on stdin; one directive per line on stdout, without comments, with blocks unrolled
    tr '\r' ' ' | awk ' # to go a carriage return is a blank
      { sub(/\/\/.*/, ""); gsub(/[()]/, " & ") } # and "tool(" is "tool ("
      NF == 0 { next }
      { $1 = $1 } # squeeze the blanks
      verb != "" && $1 == ")" { verb = ""; next }
      verb != "" { print verb, $0; next }
      NF == 2 && $2 == "(" { verb = $1; next }
      { print }'
  }
  odd="$(flat <go.mod | match -v '^(module|go|toolchain|godebug|require|retract|tool) ')" || fail "cannot read go.mod"
  [ -z "$odd" ] || fail "go.mod may not hold a directive that swaps or hides code: $odd"
  # Once go.mod pins a tool it stays pinned, under its full import path. A known checker that is pinned will run.
  tools() { flat | sed -n 's/^tool //p' | tr -d "\"\`"; } # the import paths, with or without quotes
  tools_old="$(in_base go.mod | tools)" || fail "cannot read go.mod in the base"
  tools_new="$(tools <go.mod)" || fail "cannot read go.mod"
  ratchet "go.mod no longer pins" "$tools_old" "$tools_new"
  for tool in honnef.co/go/tools/cmd/staticcheck golang.org/x/vuln/cmd/govulncheck; do
    case "$nl$tools_old$nl$tools_new$nl" in
      *"$nl$tool$nl"*) checkers="$checkers $tool" ;;
      *) echo "GATE NOTE: go.mod does not pin $tool yet" ;;
    esac
  done

  # --- 2. Tree checks and size budgets (SPEC section 7) ---------------------
  all="$(git ls-files -co --exclude-standard)" || fail "git ls-files failed"
  gone="$(git ls-files -d)" || fail "git ls-files failed" # deleted here, not yet in the index
  all="$(missing "$all" "$gone")" || fail "cannot list the files"
  hidden="$(printf '%s\n' "$all" | LC_ALL=C awk '
    /\.(syso|cxx|hh|hpp|hxx|sx|f|F|for|f90|swig|swigcxx)$/ { print; next } # go build takes it, no budget counts it
    $0 == "go.mod" || /^_legacy\// { next }             # the module itself; v1 code, kept for reference
    { rest = $0; sub(/^escape\/_pending\//, "", rest) } # parked tests: the only other underscore directory
    rest ~ /(^|\/)_/ ||                                 # "./..." skips it, yet an import finds it
    /(^|\/)go\.(mod|work)$/ || /^vendor\// ||           # a second module, a workspace, local copies of pinned modules
    /[^A-Za-z0-9._\/+-]/ || /^-/                        # a name that the lists below could misread
  ')" || fail "cannot search the list of files"
  [ -z "$hidden" ] || fail "these files hide code from the checks or the budgets: $hidden"

  files="$(printf '%s\n' "$all" | match -v '^(loop/|_legacy/|spikes/|proposed/|\.claude/)')" || fail "cannot list the files"
  pick() { printf '%s\n' "$files" | match "$1" | match -v "${2:-^$}"; } # pick <include> [exclude]
  text() { pick "$@" | xargs cat; }
  lines() { text "$@" | wc -l | tr -d ' '; }
  budget() { # budget <label> <limit> <command that prints the number>
    local label="$1" limit="$2" n
    shift 2
    if ! n="$("$@")" || ! [ "$n" -ge 0 ]; then fail "cannot measure: $label"; fi
    printf '  %-26s %6s / %s\n' "$label" "$n" "$limit"
    [ "$n" -le "$limit" ] || fail "budget exceeded: $label is $n, limit $limit"
  }
  echo "Budgets:"
  product="$(lines "$code" '(_test\.go$|^escape/)')" || fail "cannot measure: product code"
  budget "product code" 15000 echo "$product"
  budget "test code" $((product * 3 / 2 + 5000)) lines "(_test\.go\$|^escape/.*$code)"
  budget "bump tool" 800 lines "^(cmd/bump|internal/pins)/.*$code" '_test\.go$'
  budget "shell" 300 lines '\.(sh|bash|zsh)$'
  budget "workflow YAML" 500 lines '^\.github/.*\.ya?ml$'
  budget "Markdown" 2500 lines '\.md$'
  variables() { text "$code" | match -ao 'WORKCELL_[A-Z0-9_]+' | sort -u | wc -l | tr -d ' '; }
  budget "WORKCELL_* variables" 12 variables
  long="$(pick '\.go$' | xargs wc -l | awk '$1 > 800 && $2 != "total" { print $2 " has " $1 " lines;" }')" ||
    fail "cannot measure: single Go files"
  [ -z "$long" ] || fail "$long limit 800"

  # --- 3. Execute -----------------------------------------------------------
  if [ "$os" = Darwin ] && [ "${GATE_MACOS:-0}" != 1 ]; then
    budget "direct dependencies" 15 match -c '^[[:space:]]+[^ ]+ v[0-9][^ ]*$' go.mod # a rough count: go may not run
    echo "GATE NOTE: this is a Mac, so nothing was executed. Code runs in hosted CI and, on a Mac, only in the second account"
    echo "GATE PASS (tree checks only) in $((SECONDS - start))s"
    exit 0
  fi
  # Loop only: H-905 removes this check. From here on go is called, and after it code from the repository.
  [ ! -e "${HOME:-/}/loopkit" ] || fail "this account holds your kit and your key." \
    'Code from the repository runs only in the second account (START-HERE.md, "What lives where")'
  # 3a. What only go can tell. It reads, compiles and lints. Nothing from the repository runs yet.
  type -P go >/dev/null || fail "go is not installed, or not on PATH"
  goroot="$(go env GOROOT)" || fail "go env GOROOT"
  gofmt="$goroot/bin/gofmt" # the one that came with this go. Another one on PATH may be older and refuse valid code
  if [ -z "$goroot" ] || [ ! -x "$gofmt" ]; then fail "go's own gofmt is missing: $gofmt"; fi
  unformatted="$(pick '\.go$' | xargs "$gofmt" -l)" || fail "gofmt cannot read every Go file"
  [ -z "$unformatted" ] || fail "gofmt: $unformatted"
  direct() { go list -m -f '{{if not (or .Main .Indirect)}}{{.Path}}{{end}}' all | match -c .; }
  budget "direct dependencies" 15 direct
  pkgs="$(go list ./...)" || fail "go list ./..." # every package that vet, build and the tests will see
  ours="$(printf '%s\n' "$pkgs" | match -v "^$module/(loop|escape|spikes|proposed)(/|\$)")" || fail "cannot list the packages"
  linked="$(printf '%s\n' "$ours" | xargs go list -deps | match "^$module(/|\$)")" || fail "go list -deps"
  smuggled="$(missing "$linked" "$ours")" || fail "cannot compare the packages"
  [ -z "$smuggled" ] || fail "product code imports what the checks or the product budget do not cover: $smuggled"
  must go vet ./...
  must go build ./...
  for tool in $checkers; do must go tool "$tool" ./...; done # by full path, so that no look-alike can stand in

  # 3b. The escape suite on a real VM. It goes first: no repository code has run yet, so none can have touched it.
  if [ "$os" = Darwin ]; then
    only="$only_macos" where="a real Mac" vm="$(sysctl -n kern.hv_support 2>/dev/null || true)" # 1: it can start a VM
  else
    only="$only_linux" where="hosted CI" vm=0
    if [ -w /dev/kvm ]; then vm=1; fi
  fi
  if [ "$vm" != 1 ]; then
    [ "${GATE_REQUIRE_VM:-0}" != 1 ] || fail "no hypervisor, and GATE_REQUIRE_VM=1"
    echo "GATE NOTE: no hypervisor here; the VM suite is deferred to $where"
  elif [ -z "$only" ]; then
    echo "GATE NOTE: no invariant is enforced yet, so there is no VM suite to run"
  else
    must go run ./escape/cmd/escape -sandbox workcell -only "$only"
  fi

  # 3c. Unit tests, without the experiments, so that those run only once.
  unit="$(printf '%s\n' "$pkgs" | match -v "^$module/spikes(/|\$)")" || fail "cannot list the packages"
  [ -n "$unit" ] || fail "there is no package to test"
  printf '%s\n' "$unit" | xargs go test -race -count=1 || fail "go test -race -count=1"
  # Experiments print their measurements, so that a session with no hypervisor can read them in the CI log.
  if [ "$unit" != "$pkgs" ]; then must go test -count=1 -v ./spikes/...; fi # only if some of them build on this system

  budget "gate seconds" 900 echo "$((SECONDS - start))"
  echo "GATE PASS in $((SECONDS - start))s"
}

main "$@"
