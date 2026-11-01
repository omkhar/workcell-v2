#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ] || shopt -oq posix; then exec bash "$0" "$@"; fi # started with sh or zsh? carry on in bash
# Tests for loop/gate.sh. Usage: loop/test/gate-test.sh
# It makes a scratch git repository, breaks it in one way per case, and checks what the gate says.
# The gate compiles and runs the Go code of the tree it stands in. So this test writes that tree itself,
# and takes one file from the kit: loop/gate.sh. You may run it in your own account. A kit that was rebuilt
# from the repository can hold the loop's Go code, and that code must never run there.
# GATE_UNDER_TEST=<file> tests that file in place of the kit's own gate.sh. It is run, so it must be a file you trust.
# GATE_TEST_VERBOSE=1 also prints the gate's output for every case that goes wrong.
# It needs git, a POSIX userland, and go 1.27 or newer. It needs no network: go may not fetch another
# go, and the modules that some cases depend on are made here and served from a folder. Stand-ins for
# uname and sysctl say which system this is, so the results are the same on a Mac and on Linux. All it
# writes lies in one temporary folder, removed at the end.
set -uo pipefail

die() { echo "gate-test.sh: $*" >&2; exit 2; }
[ $# -eq 0 ] || die "it takes no argument. To test another gate.sh: GATE_UNDER_TEST=<file> gate-test.sh"
here="$(cd "$(dirname "$0")" && pwd)" || die "cannot find the folder of this script"
[ "${GATE_TEST_NESTED:-$here}" = "$here" ] || die "GATE_TEST_NESTED is for this test's own use. Unset it"
under_test="${GATE_UNDER_TEST:-$here/../gate.sh}"
[ -f "$under_test" ] || die "no such file: $under_test"
under_test="$(cd "$(dirname "$under_test")" && pwd)/$(basename "$under_test")"
for tool in git go; do type -P "$tool" >/dev/null || die "$tool is not installed"; done
work="$(mktemp -d)" || die "mktemp failed"
work="$(cd "$work" && pwd -P)" || die "cannot enter the temporary folder"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
trap 'exit 130' HUP INT TERM

# Nothing of yours is read or written: not your git settings, not your go settings, not your caches.
unset GATE_BASE GATE_MACOS GATE_REQUIRE_VM CDPATH XDG_CONFIG_HOME XDG_CACHE_HOME GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE \
  GOOS GOARCH GOWORK GOEXPERIMENT GOPRIVATE GONOSUMDB GONOPROXY GOINSECURE CGO_ENABLED
export HOME="$work/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GOENV=off GOTOOLCHAIN=local GOFLAGS=-modcacherw GOPROXY="file://$work/proxy" GOSUMDB=off
export GOPATH="$work/gopath" GOMODCACHE="$work/modcache" GOCACHE="$work/gocache"
# The first go command comes only now, with GOTOOLCHAIN=local in force, and in a folder that holds no go.mod of yours.
goroot="$(cd "$work" && go env GOROOT)" || die "go env GOROOT failed"
module=github.com/omkhar/workcell/v2
plain_mod="module $module\\n\\ngo 1.27.0\\n" # in printf form, like all go.mod text below
staticcheck=honnef.co/go/tools/cmd/staticcheck govulncheck=golang.org/x/vuln/cmd/govulncheck
nl='
'

# --- Stand-ins ------------------------------------------------------------------
stub() { # stub <file> <one line of sh>
  mkdir -p "$(dirname "$1")" || die "cannot write $1"
  printf '#!/bin/sh\n%s\n' "$2" >"$1" || die "cannot write $1"
  chmod +x "$1" || die "cannot write $1"
}
stub "$work/linux/uname" 'echo Linux'
stub "$work/mac/uname" 'echo Darwin'
stub "$work/mac/sysctl" 'echo 1' # kern.hv_support: this Mac can start virtual machines
stub "$work/novm/sysctl" 'echo 0' # a hosted Mac cannot
stub "$work/nogo/go" 'echo GO WAS CALLED >&2; exit 1' # on standard error, so that no $( ) in the gate can swallow it
stub "$work/nogo/gofmt" 'echo GO WAS CALLED >&2; exit 1'
export PATH="$work/linux:$goroot/bin:$PATH"
mac="PATH=$work/mac:$PATH"

src() { # src <file>: standard input becomes that file
  mkdir -p "$(dirname "$1")" || die "cannot write $1"
  cat >"$1" || die "cannot write $1"
}
many() { awk -v n="$1" -v text="$2" 'BEGIN { for (i = 1; i <= n; i++) print text, i }'; } # many <count> <text>
serve() { # serve <module> [directory]: GOPROXY offers v0.0.1 of that module, with the files in that directory
  local at="$work/proxy/$1/@v"
  echo v0.0.1 | src "$at/list"
  echo '{"Version":"v0.0.1"}' | src "$at/v0.0.1.info"
  echo "module $1" | src "$at/v0.0.1.mod"
  if [ -n "${2:-}" ]; then
    echo "module $1" | src "$2/go.mod"
    (cd "$2" && git init -q . && git add -A &&
      git archive --format=zip --prefix="$1@v0.0.1/" -o "$at/v0.0.1.zip" "$(git write-tree)") || die "cannot pack $1"
  fi
}
checker() { # checker <name> <file>: a program that says it ran, and that finds fault if docs/finding-<name> exists
  src "$2" <<EOF
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("$1 RAN:", os.Args[1:])
	if _, err := os.Stat("docs/finding-$1"); err == nil {
		os.Exit(1)
	}
}
EOF
}
mkdir -p "$HOME" || die "cannot write $HOME"
checker staticcheck "$work/src/tools/cmd/staticcheck/main.go"
checker govulncheck "$work/src/vuln/cmd/govulncheck/main.go"
serve honnef.co/go/tools "$work/src/tools"
serve golang.org/x/vuln "$work/src/vuln"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do serve "example.com/d$i"; done

# --- The scratch repository -------------------------------------------------------
repo="$work/repo"
mkdir -p "$repo/loop" || die "cannot write $repo"
cp "$under_test" "$repo/loop/gate.sh" || die "cannot copy $under_test"
chmod +x "$repo/loop/gate.sh" || die "cannot copy $under_test"
cd "$repo" || die "cannot enter $repo"
printf '%b' "$plain_mod" >go.mod || die "cannot write go.mod"
why="$(go list -m 2>&1 >/dev/null)" ||
  die "the installed go refuses a go.mod that says go 1.27.0, and this test fetches no other go. Install go 1.27 or newer. go says: $why"
src cmd/workcell/main.go <<EOF
// Command workcell stands in for the product.
package main

import (
	"fmt"

	"$module/internal/version"
)

func main() { fmt.Println(version.String()) }
EOF
src internal/version/version.go <<'EOF'
// Package version stands in for the product's packages.
package version

// String returns what "workcell --version" prints.
func String() string { return "workcell v2-test" }
EOF
src internal/version/version_test.go <<'EOF'
package version

import "testing"

func TestString(t *testing.T) {
	if got := String(); got != "workcell v2-test" {
		t.Errorf("String() = %q", got)
	}
}
EOF
echo '# A stand-in' | src README.md
echo '# A stand-in' | src docs/notes.md
echo 'name: stand-in' | src .github/workflows/ci.yml
git -c init.defaultBranch=main init -q . || die "git init failed"
for setting in "user.name tester" "user.email tester@example.com" "commit.gpgsign false"; do
  git config "${setting% *}" "${setting#* }" || die "git config failed"
done

state='' # the commit that every case starts from, and that is the base
base() { # base <message>: the tree as it is now becomes that commit
  if ! { git add -A && git commit -qm "$1" && state="$(git rev-parse HEAD)"; }; then die "cannot commit: $1"; fi
  back
}
back() { # the tree and refs/remotes/origin/main are $state again
  if ! { git reset -q --hard "$state" && git clean -qfdx && git update-ref refs/remotes/origin/main "$state"; }; then
    die "cannot go back to $state"
  fi
}

ok=0 wrong=0 out='' from="$repo" never='' keep=''
tally() { # tally <name> <problem, or nothing> <detail>
  local mark=ok
  if [ -z "$2" ]; then ok=$((ok + 1)); else wrong=$((wrong + 1)) mark=WRONG; fi
  printf '  %-5s %-78s %s\n' "$mark" "$1" "${2:-$3}"
}
# t <name> <exit code> <lines that the output must hold> [VAR=value ...] [interpreter]
# Runs the gate, judges it, prints one line, and puts the tree back. To set for one call: from=<directory to
# start in>, never=<text that the output must not hold>, keep=1 (leave the tree as it is, for a second run).
t() {
  local name="$1" want="$2" must="$3" rc line problem=''
  shift 3
  out="$(cd "$from" && env "$@" "$repo/loop/gate.sh" 2>&1)"
  rc=$?
  [ "$rc" = "$want" ] || problem="exit code $rc, not $want"
  while IFS= read -r line; do
    case "$out" in *"$line"*) ;; *) problem="${problem:+$problem; }does not say: $line" ;; esac
  done <<EOF
$must
EOF
  if [ -n "$never" ]; then
    case "$out" in *"$never"*) problem="${problem:+$problem; }says: $never" ;; esac
  fi
  tally "$name" "$problem" "$(printf '%s\n' "$out" | grep -E '^GATE (FAIL|PASS)' | tail -n 1 | cut -c 1-100)"
  if [ -n "$problem" ] && [ -n "${GATE_TEST_VERBOSE:-}" ]; then printf '%s\n' "$out" | sed 's/^/        | /'; fi
  [ -n "$keep" ] || back
}
same() { # same <name> <got> <wanted>
  if [ "$2" = "$3" ]; then tally "$1" '' "$2"; else tally "$1" "got $2, not $3" ''; fi
}
row() { printf '  %-26s %6s / %s' "$1" "$2" "$3"; } # row <label> <number> <limit>: a line of the gate's table

# --- Things to put in the tree ------------------------------------------------------
name_of() { basename "$1" | tr -cd 'A-Za-z'; } # a package name for that directory
package() { printf 'package %s\n\nfunc F() {}\n' "$(name_of "$1")" | src "$1/f.go"; } # package <directory>
import() { # import <directory>: product code now imports the package in that directory
  printf 'package version\n\nimport "%s/%s"\n\nfunc init() { %s.F() }\n' "$module" "$1" "$(name_of "$1")" |
    src internal/version/smuggle.go
}
failing_test() { # failing_test <directory> [what it shouts]
  printf 'package %s\n\nimport "testing"\n\nfunc TestNo(t *testing.T) { t.Fatal("%s") }\n' "$(name_of "$1")" "${2:-no}" |
    src "$1/no_test.go"
}
look_alike() { # look_alike <directory>: a program that only says it ran
  printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("THE LOOK-ALIKE RAN") }\n' | src "$1/main.go"
}
saboteur() { # saboteur <Go expression> ...: a unit test that evaluates them before its package's tests run
  {
    printf 'package version\n\nimport (\n\t"os"\n\t"testing"\n)\n\nfunc TestMain(m *testing.M) {\n'
    printf '\t_ = %s\n' "$@"
    printf '\tos.Exit(m.Run())\n}\n'
  } | src internal/version/setup_test.go
}
rewrite() { printf 'os.WriteFile("../../%s", []byte("%s"), 0o755)' "$1" "$2"; } # rewrite <file> <inside of a Go string>
forge="$(rewrite loop/gate.sh '#!/bin/sh\necho GATE PASS (forged)\nexit 0\n')"
requires="require (\n\tgolang.org/x/vuln v0.0.1 // indirect\n\thonnef.co/go/tools v0.0.1 // indirect\n)\n"
add() { printf '%b' "$1" >>go.mod; }
refused() { # refused <name> <text>: go.mod with that text at its end must not pass
  add "$2"
  t "go.mod: $1" 1 "GATE FAIL: go.mod may not hold a directive that swaps or hides code"
}
both_ran="staticcheck RAN: [./...]${nl}govulncheck RAN: [./...]${nl}GATE PASS in"
unpinned="GATE FAIL: go.mod no longer pins:"
hides="GATE FAIL: these files hide code from the checks or the budgets:"
smuggled="GATE FAIL: product code imports what the checks or the product budget do not cover:"
over="GATE FAIL: budget exceeded:"

echo "=== gate.sh under $(bash --version | head -n 1), $(go env GOVERSION)"
base "a small tree"

echo "--- how it starts"
t "a small tree with nothing wrong" 0 "GATE PASS in"
if [ "${GATE_TEST_NESTED:-}" = "$here" ]; then # the copy that the last section of this test starts: it has shown what it had to
  echo "GATE RESULT: $ok ok, $wrong wrong"
  exit "$wrong"
fi
if [ -w /dev/kvm ]; then
  t "as CI runs it, on a machine with KVM" 0 "GATE PASS in" GATE_REQUIRE_VM=1
else
  t "as CI runs it, with no hypervisor" 1 "GATE FAIL: no hypervisor, and GATE_REQUIRE_VM=1" GATE_REQUIRE_VM=1
fi
from=/ t "started from another directory" 0 "GATE PASS in"
mkdir -p "$work/cdpath/loop"
from="$repo" t "started by a relative path, with CDPATH set" 0 "GATE PASS in" CDPATH="$work/cdpath" bash -c 'exec loop/gate.sh'
t "started with sh" 0 "GATE PASS in" sh
t "started with bash in POSIX mode, which is sh on a Mac" 0 "GATE PASS in" bash --posix
shell='zsh'
type -P zsh >/dev/null || shell='sh' # so that the number of cases is the same everywhere
t "started with zsh" 0 "GATE PASS in" "$shell"
utf8=C.UTF-8 # a locale in which letters do not sort between the blank and the tilde, if this machine has it
if [ "$(LC_ALL=en_US.UTF-8 locale charmap 2>/dev/null)" = UTF-8 ]; then utf8=en_US.UTF-8; fi
sorting=(bash) # and a bash whose ranges follow the locale's order, as the bash 3.2 of a Mac does
if bash +O globasciiranges -c : 2>/dev/null; then sorting=(bash +O globasciiranges); fi
t "in CI, in a UTF-8 locale: the reason can be read, as an annotation too" 1 \
  "GATE FAIL: cannot find nonsense to compare with${nl}::error::GATE FAIL: cannot find nonsense to compare with" \
  GATE_BASE=nonsense GITHUB_ACTIONS=true LC_ALL="$utf8" "${sorting[@]}"

echo "--- the base"
t "an unknown base to compare with" 1 "GATE FAIL: cannot find nonsense to compare with" GATE_BASE=nonsense
git update-ref refs/remotes/origin/v2 HEAD
git update-ref -d refs/remotes/origin/main
keep=1 t "no refs/remotes/origin/main, and the old default is no help" 1 \
  "GATE FAIL: cannot find refs/remotes/origin/main to compare with"
t "no refs/remotes/origin/main, but GATE_BASE names a commit" 0 "GATE PASS in" GATE_BASE=HEAD
git update-ref -d refs/remotes/origin/v2

echo "--- go.mod"
rm go.mod
echo 'package main; func broken( {' >cmd/workcell/broken.go
keep=1 t "go.mod deleted, code does not compile" 1 "GATE FAIL: go.mod is missing"
t "the same, as CI runs it" 1 "GATE FAIL: go.mod is missing" GATE_REQUIRE_VM=1
printf '%b' "$plain_mod" | sed 's,/v2$,/two,' >go.mod
t "another module path, so that imports from spikes/ look foreign" 1 "GATE FAIL: go.mod must start with the line: module $module"
printf '%b' "$plain_mod" | sed 's,^module \(.*\),module "\1",' >go.mod
t "the module path in quotes" 1 "GATE FAIL: go.mod must start with"
printf '%b' "$plain_mod" | sed 's,^module \(.*\),module ( \1 ),' | tr ' ' '\n' >go.mod
t "the module path in a block" 1 "GATE FAIL: go.mod must start with"
printf '%b' "$plain_mod" | sed 's,^module .*,& // v2,' >go.mod
t "a comment after the module path" 1 "GATE FAIL: go.mod must start with"
printf '%b' "$plain_mod" | sed 's,^module .*,&	,' >go.mod
t "a tab after the module path" 1 "GATE FAIL: go.mod must start with"
printf '%b' "$plain_mod" | sort >go.mod
t "the module line is not the first" 1 "GATE FAIL: go.mod must start with"
printf '%b' "// Workcell.\n\n \t// replace nothing, exclude nothing, ignore nothing\n$plain_mod" >go.mod
add "\ntoolchain go1.99.0\n\nretract v2.0.0 // never made\n\ngodebug (\n\tdefault=go1.27\n)\n"
t "comments first, then harmless directives" 0 "GATE PASS in"
refused "replace, to a local path" '\nreplace example.com/lib => ./proposed/lib\n'
refused "replace, to another version" '\nreplace example.com/lib v1.0.0 => example.com/lib v1.0.1\n'
refused "replace, in a block" '\nreplace (\n\texample.com/lib => ./proposed/lib\n)\n'
refused "replace, with no blank before the bracket" '\nreplace(\n\texample.com/lib => ./proposed/lib\n)\n'
refused "replace, indented, after a carriage return" '\n\r \treplace example.com/lib => ./proposed/lib\n'
refused "replace, after a block that a comment seems to leave open" '\nrequire ( // )\n)\nreplace example.com/lib => ./proposed/lib\n'
refused "replace, after a block that ends behind a carriage return" '\ngodebug (\n\tpanicnil=1\n\r)\nreplace example.com/lib => ./proposed/lib\n'
refused "exclude" '\nexclude example.com/lib v1.0.0\n'
refused "exclude, in a block" '\nexclude (\n\texample.com/lib v1.0.0\n)\n'
refused "ignore, in a block" '\nignore (\n\t./internal/proxy\n)\n'
refused "a directive that the gate does not know" '\nconceal ./internal/proxy\n'
package internal/proxy
failing_test internal/proxy
import internal/proxy
keep=1 t "a package with a failing test" 1 "GATE FAIL: go test -race -count=1"
refused "ignore, which hides that package from the tests" '\nignore ./internal/proxy\n'

echo "--- pinned tools"
look_alike internal/quiet/staticcheck
add "\ntool $module/internal/quiet/staticcheck\n"
never="THE LOOK-ALIKE RAN" t "a look-alike where nothing was pinned is not taken for the checker" 0 \
  "GATE NOTE: go.mod does not pin $staticcheck yet${nl}GATE PASS in"
go get -tool "$staticcheck@v0.0.1" "$govulncheck@v0.0.1" >/dev/null 2>&1 || die "go get -tool failed"
keep=1 t "both checkers newly pinned: both run" 0 "$both_ran"
base "pin both checkers"
t "both checkers pinned in the base: both run" 0 "$both_ran"
touch docs/finding-staticcheck
t "staticcheck finds fault" 1 "GATE FAIL: go tool $staticcheck ./..."
touch docs/finding-govulncheck
t "govulncheck finds fault" 1 "GATE FAIL: go tool $govulncheck ./..."
printf '%b' "$plain_mod\n$requires" >go.mod
t "both pins dropped" 1 "$unpinned $govulncheck $staticcheck"
printf '%b' "$plain_mod\ntool $govulncheck\n\n$requires" >go.mod
t "one pin dropped" 1 "$unpinned $staticcheck"
printf '%b' "$plain_mod\n// staticcheck and govulncheck moved to nightly:\n// tool $staticcheck\n// tool $govulncheck\n\n$requires" >go.mod
t "the pins replaced by a comment that mentions them" 1 "$unpinned $govulncheck $staticcheck"
printf '%b' "$plain_mod\ntool $govulncheck\n\ttool   $staticcheck // pinned\n\n$requires" >go.mod
t "the same pins, one per line" 0 "$both_ran"
printf '%b' "$plain_mod\ntool(// both\n$govulncheck\n\n$staticcheck// pinned\n)\n\n$requires" >go.mod
t "the same pins, in a block with odd spacing" 0 "$both_ran"
printf '%b' "$plain_mod\ntool \"$govulncheck\"\ntool (\n\t\"$staticcheck\"\n)\n\n$requires" >go.mod
t "the same pins, in quotes" 0 "$both_ran"
printf '%b' "$plain_mod\nretract (\n\ttool $govulncheck\n\ttool $staticcheck\n)\n\n$requires" >go.mod
t "the pins moved into a block of another kind" 1 "$unpinned $govulncheck $staticcheck"
look_alike internal/quiet/staticcheck
look_alike internal/quiet/govulncheck
printf '%b' "$plain_mod\ntool (\n\t$module/internal/quiet/govulncheck\n\t$module/internal/quiet/staticcheck\n)\n" >go.mod
never="THE LOOK-ALIKE RAN" t "the pins swapped for look-alikes of the same name" 1 "$unpinned $govulncheck $staticcheck"
look_alike internal/quiet/staticcheck
add "\ntool $module/internal/quiet/staticcheck\n"
never="THE LOOK-ALIKE RAN" t "a look-alike pinned beside the real checker: the real one runs" 0 "$both_ran"
printf 'module honnef.co/go/tools\n' | src "$work/stub/go.mod"
printf 'package main\n\nfunc main() {}\n' | src "$work/stub/cmd/staticcheck/main.go"
touch docs/finding-staticcheck
refused "replace, which points a pinned checker at a stub" "\nreplace honnef.co/go/tools => $work/stub\n"
go mod vendor >/dev/null 2>&1 || die "go mod vendor failed"
printf 'package main\n\nfunc main() {}\n' >vendor/honnef.co/go/tools/cmd/staticcheck/main.go
touch docs/finding-staticcheck
t "a vendor directory, which swaps a pinned checker for a stub" 1 "$hides vendor/"
saboteur "$(rewrite go.mod "$plain_mod")" 'os.Remove("../../docs/finding-staticcheck")'
touch docs/finding-staticcheck
t "a test that unpins the checkers and removes what they would find" 1 "GATE FAIL: go tool $staticcheck ./..."
pinned="$state"
git rm -q go.mod && echo x | src go.mod/x
base "a base in which go.mod is a directory"
rm -rf go.mod && git show "$pinned:go.mod" >go.mod
t "a base whose go.mod cannot be read" 1 "GATE FAIL: cannot read go.mod in the base"
state="$pinned"
back

echo "--- enforced invariants"
t "a Mac with a hypervisor and nothing enforced yet says so" 0 "GATE NOTE: no invariant is enforced yet" "$mac" GATE_MACOS=1
src escape/cmd/escape/main.go <<'EOF'
// Command escape stands in for the real suite. It fails when it is asked for I2.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	line := strings.Join(os.Args[1:], " ")
	fmt.Println("THE SUITE RAN:", line)
	if strings.Contains(line, "I2") {
		os.Exit(1)
	}
}
EOF
printf 'I3\nI5\nI7\n' >escape/enforced.txt
printf 'I3\nI4\n' >escape/enforced-macos.txt
base "enforce some invariants"
removed="GATE FAIL: invariants removed from"
printf 'I5\n' >escape/enforced.txt
keep=1 t "invariants removed" 1 "$removed escape/enforced.txt: I3 I7"
saboteur "$forge"
never=forged t "invariants removed, and a test rewrites gate.sh" 1 "$removed escape/enforced.txt: I3 I7"
printf 'I4\n' >escape/enforced-macos.txt
t "invariants removed from the macOS list" 1 "$removed escape/enforced-macos.txt: I3"
rm escape/enforced.txt
t "the list deleted" 1 "$removed escape/enforced.txt: I3 I5 I7"
: >escape/enforced.txt
t "the list emptied" 1 "$removed escape/enforced.txt: I3 I5 I7"
printf 'I3\r\nI5\r\nI7\r\n' >escape/enforced.txt
t "the list with carriage returns" 1 "$removed escape/enforced.txt: I3 I5 I7"
printf 'I3 \nI5\nI7\n' >escape/enforced.txt
t "a line with a trailing blank" 1 "$removed escape/enforced.txt: I3"
printf '#I3\nI5\nI7\n' >escape/enforced.txt
t "a line commented out" 1 "$removed escape/enforced.txt: I3"
plain="may hold only printable ASCII, tabs and newlines"
printf 'I3\377\nI3\nI4\n' >escape/enforced-macos.txt
keep=1 t "nothing removed, but a new first line holds a byte that is no text" 1 "GATE FAIL: escape/enforced-macos.txt $plain"
t "the same on a Mac, whose paste would end the list at that byte" 1 "GATE FAIL: escape/enforced-macos.txt $plain" \
  "$mac" GATE_MACOS=1 LC_ALL="$utf8"
printf 'I3\nI5\nI7\nI9\r\n' >escape/enforced.txt
t "nothing removed, but a new line ends in a carriage return" 1 "GATE FAIL: escape/enforced.txt $plain"
printf 'I3\nI5\nI7\n\0' >escape/enforced.txt
t "nothing removed, but a NUL byte at the end" 1 "GATE FAIL: escape/enforced.txt $plain"
rm escape/enforced.txt && mkdir escape/enforced.txt && touch escape/enforced.txt/I3
t "the list swapped for a directory" 1 "GATE FAIL: cannot read escape/enforced.txt"
printf 'I9\nI7\n\nI5\nI3\n' >escape/enforced.txt
t "the list reordered and longer" 0 "GATE PASS in"
saboteur "$forge"
never=forged t "a test rewrites gate.sh while it runs; nothing else is wrong" 0 "GATE PASS in"

echo "--- hidden code"
for dir in cmd/hidden proposed/lib spikes/lib loop/lib .claude/lib escape/_pending/lib; do
  printf 'module x\n' | src "$dir/go.mod"
  echo 'package hidden; func broken( {' >"$dir/x.go"
  t "a nested module in $dir" 1 "$hides $dir/go.mod"
done
echo 'go 1.27.0' >go.work
t "a go.work file" 1 "$hides go.work"
echo 'go 1.27.0' | src proposed/go.work
t "a go.work file further down" 1 "$hides proposed/go.work"
printf 'module x\n' | src _legacy/lib/go.mod
echo 'go 1.27.0' >_legacy/go.work
echo 'package hidden; func broken( {' >_legacy/lib/x.go
touch "_legacy/an odd name"
package _legacy/_deep
t "all of that under _legacy/, which nothing imports" 0 "GATE PASS in"
package internal/_proxy
failing_test internal/_proxy
t "an underscore directory with a failing test" 1 "$hides internal/_proxy/f.go internal/_proxy/no_test.go"
for dir in _other internal/_legacy spikes/_x cmd/escape/_pending escape/_pending/_deep escape/x/_pending; do
  package "$dir"
  t "an underscore directory: $dir" 1 "$hides $dir/f.go"
done
printf 'package version\n' >internal/version/_off.go
t "a file whose name starts with an underscore" 1 "$hides internal/version/_off.go"
package escape/_pending/S-F1
failing_test escape/_pending/S-F1
t "a failing test parked under escape/_pending/" 0 "GATE PASS in"
for file in internal/version/blob.syso spikes/x/blob.syso escape/_pending/blob.syso _legacy/lib/blob.syso; do
  : | src "$file"
  t "a .syso file: $file" 1 "$hides $file"
done
for ext in cxx hh hpp hxx sx f F for f90 swig swigcxx; do
  : >"internal/version/x.$ext"
  t "a .$ext file, which go build takes and no budget counts" 1 "$hides internal/version/x.$ext"
done
for name in 'a blank|a b.go' 'a quote|a"b.go' 'a semicolon|a;b.go' 'a backslash|a\b.go' $'a letter outside ASCII|\303\251.go'; do
  printf 'package version\n' >"internal/version/${name#*|}"
  t "a file name with ${name%|*}" 1 "$hides"
done
printf 'package main\n' >./-n.go
t "a file name that starts with a dash" 1 "$hides -n.go"
for dir in _legacy/big spikes/big proposed/big escape/big escape/_pending/big loop/big internal/testdata/big internal/.big; do
  package "$dir"
  import "$dir"
  t "product code that imports from $dir" 1 "$smuggled $module/$dir"
done
package _legacy/big
ln -s ../_legacy/big internal/big
import internal/big
t "product code that imports from _legacy/ through a symbolic link" 1 "$smuggled $module/internal/big"
package spikes/big
printf 'package pins\n\nimport "%s/spikes/big"\n\nfunc init() { big.F() }\n' "$module" | src pins/pins.go
t "product code outside cmd/ and internal/ that imports from spikes/" 1 "$smuggled $module/spikes/big"
package spikes/big
printf 'package lib\n\nimport "%s/spikes/big"\n\nfunc init() { big.F() }\n' "$module" | src escape/lib/lib.go
t "the suite may import from spikes/" 0 "GATE PASS in"

echo "--- budgets"
go_file() { printf 'package %s\n\n' "$1" && many "$2" '// line'; } # go_file <package> <lines of comment>
many 301 '#' | src cmd/z/big.sh
t "301 lines of shell" 1 "$over shell is 301, limit 300"
many 301 '#' | src cmd/z/big.bash
t "301 lines of shell in a .bash file" 1 "$over shell is 301, limit 300"
go_file version 900 >internal/version/big.go
t "a Go file of 902 lines" 1 "GATE FAIL: internal/version/big.go has 902 lines; limit 800"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do go_file pins 790 | src "pins/a$i.go"; done
t "15,840 lines of Go outside cmd/ and internal/" 1 "$over product code is"
for ext in c h s S m cc cpp; do
  many 15000 '//' >"internal/version/big.$ext"
  t "15,000 lines in a .$ext file" 1 "$over product code is"
done
many 15000 '//' | src spikes/x/big.c
many 15000 '//' | src proposed/x/big.c
many 600 '#' | src proposed/dot-github/workflows/x.yml
t "large files under spikes/ and proposed/ hit no budget" 0 "GATE PASS in"
for i in 1 2 3 4; do go_file version 790 >"internal/version/a${i}_test.go"; done
t "3,168 lines of tests for a small product" 1 "$over test code is"
many 3000 '//' | src escape/native/big.c
t "3,000 lines of C under escape/" 1 "$over test code is"
for i in 1 2; do go_file main 400 | src "cmd/bump/a$i.go"; done
t "804 lines in cmd/bump" 1 "$over bump tool is 804, limit 800"
many 501 '#' >.github/workflows/big.yml
t "too much workflow YAML" 1 "$over workflow YAML is"
many 2501 '-' >docs/big.md
t "too much Markdown" 1 "$over Markdown is"
go_file version 13 | sed 's,// line ,// WORKCELL_V,' >internal/version/env.go
t "13 WORKCELL_* variables" 1 "$over WORKCELL_* variables is 13, limit 12"
{ printf 'package pins\n\nfunc f() { x := 0; ' && many 5000 'x++;' | tr -d '0-9\n' && printf ' _ = x }\n'; } | src pins/dense.go
t "5,000 statements on one line, outside cmd/, internal/ and escape/" 1 "GATE FAIL: gofmt: pins/dense.go"
printf 'package version\nfunc  x() {}\n' >internal/version/bad.go
t "badly formatted Go" 1 "GATE FAIL: gofmt: internal/version/bad.go"
echo 'package x; func broken( {' | src escape/_pending/x/x.go
t "Go that does not parse, parked where go build does not look" 1 "GATE FAIL: gofmt cannot read every Go file"
sums() { GOFLAGS="-mod=mod $GOFLAGS" go list -m all >/dev/null 2>&1 || die "cannot write go.sum"; }
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do add "require example.com/d$i v0.0.1 // needed\n"; done
sums
keep=1 t "15 direct dependencies, one per line, each with a comment" 0 "$(row "direct dependencies" 15 15)"
add "require example.com/d16 v0.0.1\n"
sums
keep=1 t "16 direct dependencies, one per line" 1 "$over direct dependencies is 16, limit 15"
t "the same on a Mac, where go may not run: the rough count misses them" 0 "$(row "direct dependencies" 0 15)" "$mac"
add "require (\n"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do add "\texample.com/d$i v0.0.1\n"; done
add ")\n"
t "16 direct dependencies in a block, on a Mac" 1 "$over direct dependencies is 16, limit 15" "$mac"
rm README.md
t "a file deleted here and not yet in the index" 0 "GATE PASS in"

echo "--- what runs"
printf 'package version\n\nfunc x() { undefined() }\n' >internal/version/bad.go
t "Go that does not compile" 1 "GATE FAIL: go vet ./..."
printf 'package version\n\nimport "fmt"\n\nfunc x() { fmt.Printf("%%d", "x") }\n' >internal/version/bad.go
t "Go that go vet objects to" 1 "GATE FAIL: go vet ./..."
printf 'package main\n\nfunc x()\n' >cmd/workcell/bad.go
t "Go that only the compiler objects to" 1 "GATE FAIL: go build ./..."
failing_test internal/version
t "a failing unit test" 1 "GATE FAIL: go test -race -count=1"
src spikes/count/count_test.go <<'EOF'
package count

import (
	"os"
	"testing"
)

func TestCount(t *testing.T) {
	f, err := os.OpenFile(os.Getenv("GATE_TEST_TALLY"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("ran\n"); err != nil {
		t.Fatal(err)
	}
	t.Log("MEASURED: 42 ms")
}
EOF
t "an experiment under spikes/ prints what it measured" 0 "MEASURED: 42 ms${nl}GATE PASS in" GATE_TEST_TALLY="$work/tally"
same "and it ran exactly once" "$(grep -c ran "$work/tally")" 1
failing_test spikes/bad
t "a failing experiment" 1 "GATE FAIL: go test -count=1 -v ./spikes/..."
other=darwin
if [ "$(go env GOOS)" = darwin ]; then other=linux; fi
printf '//go:build %s\n\npackage vm\n\nfunc F() {}\n' "$other" | src spikes/vm/vm.go
printf '//go:build %s\n\npackage vm\n\nimport "testing"\n\nfunc TestNo(t *testing.T) { t.Fatal("no") }\n' "$other" >spikes/vm/vm_test.go
t "spikes/ holds only code for another system" 0 "GATE PASS in"
echo notes | src spikes/notes.txt
t "spikes/ holds no Go at all" 0 "GATE PASS in"

echo "--- on a Mac"
failing_test internal/version "RAN ON THE MAC"
echo 'package main; func broken( {' >cmd/workcell/broken.go
never="GO WAS CALLED" t "nothing from the repository runs, and go is not even called" 0 \
  "GATE NOTE: this is a Mac, so nothing was executed${nl}GATE PASS (tree checks only) in" "PATH=$work/nogo:$work/mac:$PATH"
never="GATE_MACOS" t "and the note names no switch that would run code here" 0 "on a Mac, only in the second account" "$mac"
failing_test internal/version "RAN ON THE MAC"
never="RAN ON THE MAC" t "GATE_MACOS=0 is the same as unset" 0 "GATE PASS (tree checks only) in" "$mac" GATE_MACOS=0
printf 'I5\n' >escape/enforced.txt
t "the ratchets still hold" 1 "$removed escape/enforced.txt: I3 I7" "$mac"
package internal/_proxy
t "the tree checks still hold" 1 "$hides internal/_proxy/f.go" "$mac"
many 301 '#' | src cmd/z/big.sh
t "the budgets still hold" 1 "$over shell is 301, limit 300" "$mac"
failing_test internal/version "RAN ON THE MAC"
t "GATE_MACOS=1 runs the tests" 1 "RAN ON THE MAC${nl}GATE FAIL: go test -race -count=1" "$mac" GATE_MACOS=1
t "GATE_MACOS=1 runs the checkers, and the suite with the macOS list" 0 \
  "THE SUITE RAN: -sandbox workcell -only I3,I4${nl}$both_ran" "$mac" GATE_MACOS=1
suite_failed="THE SUITE RAN: -sandbox workcell -only I3,I4,I2${nl}GATE FAIL: go run ./escape/cmd/escape -sandbox workcell -only I3,I4,I2"
echo I2 >>escape/enforced-macos.txt
t "the suite fails" 1 "$suite_failed" "$mac" GATE_MACOS=1
echo I2 >>escape/enforced-macos.txt
saboteur "$(rewrite escape/enforced.txt '')" "$(rewrite escape/enforced-macos.txt '')" \
  "$(rewrite escape/cmd/escape/main.go 'package main\n\nfunc main() {}\n')"
t "a test that empties both lists and guts the suite while it runs" 1 "$suite_failed" "$mac" GATE_MACOS=1
never="THE SUITE RAN" t "a hosted Mac has no hypervisor: the suite is deferred, out loud" 0 \
  "GATE NOTE: no hypervisor here; the VM suite is deferred to a real Mac${nl}GATE PASS in" "PATH=$work/novm:$work/mac:$PATH" GATE_MACOS=1
t "the same with GATE_REQUIRE_VM=1" 1 "GATE FAIL: no hypervisor, and GATE_REQUIRE_VM=1" \
  "PATH=$work/novm:$work/mac:$PATH" GATE_MACOS=1 GATE_REQUIRE_VM=1

echo "--- which go, and whose gofmt"
mkdir "$work/bare" || die "cannot write $work/bare" # everything that the gate calls, except go and gofmt
for tool in awk bash cat comm dirname git grep paste sed sort tr wc xargs; do
  ln -s "$(type -P "$tool")" "$work/bare/$tool" || die "cannot write $work/bare/$tool"
done
no_go="GATE FAIL: go is not installed, or not on PATH"
t "go is not on PATH" 1 "$no_go" "PATH=$work/linux:$work/bare"
t "go is not on PATH, on a Mac with GATE_MACOS=1" 1 "$no_go" "PATH=$work/mac:$work/bare" GATE_MACOS=1
t "go is not on PATH, on a Mac that executes nothing: it is not missed" 0 "GATE PASS (tree checks only) in" "PATH=$work/mac:$work/bare"
stub "$work/old/gofmt" 'echo ANOTHER GOFMT RAN >&2; exit 2' # as an older one does with syntax that it does not know
never="ANOTHER GOFMT RAN" t "another gofmt stands first in PATH: it is not used" 0 "GATE PASS in" "PATH=$work/old:$PATH"
stub "$work/lax/gofmt" 'exit 0'
printf 'package version\nfunc  x() {}\n' >internal/version/bad.go
t "another gofmt, which finds no fault, hides no badly formatted Go" 1 "GATE FAIL: gofmt: internal/version/bad.go" "PATH=$work/lax:$PATH"
t "go cannot say where it lives" 1 "GATE FAIL: go env GOROOT" "PATH=$work/nogo:$PATH"
stub "$work/mute/go" 'exit 0'
t "go gives an empty answer: no gofmt is looked for elsewhere" 1 "GATE FAIL: go's own gofmt is missing: /bin/gofmt" "PATH=$work/mute:$PATH"
t "go has no gofmt beside it" 1 "GATE FAIL: go's own gofmt is missing: $HOME/bin/gofmt" GOROOT="$HOME"

echo "--- the account that holds the kit"
mkdir -p "$work/yours/loopkit" || die "cannot write $work/yours"
yours="GATE FAIL: this account holds your kit and your key. Code from the repository runs only in the second account"
yours="$yours (START-HERE.md, \"What lives where\")"
never="GO WAS CALLED" t "a Mac with GATE_MACOS=1: refused, and go is not even called" 1 "$yours" \
  HOME="$work/yours" "PATH=$work/nogo:$work/mac:$PATH" GATE_MACOS=1
never="GO WAS CALLED" t "Linux: refused, and go is not even called" 1 "$yours" HOME="$work/yours" "PATH=$work/nogo:$PATH"
t "a Mac that executes nothing: the tree checks work there as everywhere" 0 "GATE PASS (tree checks only) in" HOME="$work/yours" "$mac"
# With no home folder to look in, the gate must neither crash nor refuse. It goes on to its next line, which looks for go.
never="unbound variable" t "HOME is empty" 1 "$no_go" HOME= "PATH=$work/linux:$work/bare"
never="unbound variable" t "HOME is not set" 1 "$no_go" -u HOME "PATH=$work/linux:$work/bare"

echo "--- a tool that fails must never lead to a pass"
for tool in awk cat comm git go grep paste sed sort tr uname wc xargs; do
  stub "$work/broken-$tool/$tool" 'exit 1'
  never="GATE PASS" t "$tool fails" 1 "GATE FAIL:" "PATH=$work/broken-$tool:$PATH"
  case "$tool" in go) continue ;; esac # a Mac does not call it
  never="GATE PASS" t "$tool fails, on a Mac" 1 "GATE FAIL:" "PATH=$work/broken-$tool:$work/mac:$PATH"
done
stub "$work/broken-gofmt/bin/gofmt" 'exit 1'
never="GATE PASS" t "gofmt fails" 1 "GATE FAIL: gofmt cannot read every Go file" GOROOT="$work/broken-gofmt"

echo "--- Go code that lies in the kit folder"
# A copy of this test, in a folder that also holds what a rebuilt kit could hold: a go.mod, and a Go test that leaves a mark.
mkdir -p "$work/kit/loop/test" || die "cannot write $work/kit"
cp "$under_test" "$work/kit/loop/gate.sh" || die "cannot copy $under_test"
cp "$here/gate-test.sh" "$work/kit/loop/test/gate-test.sh" || die "cannot copy $here/gate-test.sh"
printf '%b' "$plain_mod" >"$work/kit/go.mod" || die "cannot write $work/kit/go.mod"
src "$work/kit/cmd/evil/evil_test.go" <<EOF
package evil

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.WriteFile("$work/mark", []byte("it ran"), 0o600)
	os.Exit(m.Run())
}
EOF
mark() { cat "$work/mark" 2>/dev/null || echo "no mark"; }
copy() { GATE_TEST_NESTED="$work/kit/loop/test" "$work/kit/loop/test/gate-test.sh" "$@" 2>&1; } # it stops after its first case
(cd "$work/kit" && go test ./...) >/dev/null 2>&1
same "a Go test in that folder leaves its mark when go runs it" "$(mark)" "it ran"
rm -f "$work/mark"
same "the copy of this test passes there" "$(copy | tail -n 1)" "GATE RESULT: 1 ok, 0 wrong"
same "the copy takes no folder to test as an argument" "$(copy "$work/kit" | cut -c 1-35)" "gate-test.sh: it takes no argument."
same "and neither of the two ran that Go test" "$(mark)" "no mark"

echo "GATE RESULT: $ok ok, $wrong wrong"
[ "$wrong" -eq 0 ]
