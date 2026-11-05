# Contributing to Workcell v2

## Build and test

You need the Go version that `go.mod` names (`go 1.27.0`). Then run these three
commands from a shell:

    git clone https://github.com/omkhar/workcell-v2
    cd workcell-v2
    go build -o bin/workcell ./cmd/workcell
    loop/gate.sh

The build prints nothing when it works. `bin/` is git-ignored. The gate is the
test: it checks formatting, file names and size budgets, runs `go vet`, builds,
and runs the unit tests. Output from a fresh clone, on a machine with no
`/dev/kvm`, cut to the lines that matter:

    Budgets:
      product code                10584 / 15000
      ...
    GATE NOTE: no hypervisor here; the VM suite is deferred to hosted CI
    ...
    GATE PASS in 43s

Hosted CI and a machine with `/dev/kvm` also run the VM suite, the `escape/`
tests. At cutover `loop/gate.sh` becomes `scripts/check.sh` (SPEC W2), so the
commands above change then.

On macOS the gate runs only the tree checks unless `GATE_MACOS=1` is set. That
path was not run when this file was written.

## What you may change

Only the paths in `loop/free-paths.txt` change without the maintainer's
signature. Everything else lands only signed. `docs/` is free, but
`docs/adr/accepted/` is locked. A design decision counts as accepted only when
its file is in that folder (see the top of `loop/SPEC.md`).

## How a change is proven

- Prove behaviour by running it.
- Invariants are proven only by `escape/` tests: black-box, on a real VM (T1).
  Each one must first fail against the `control` adapter (T2).
- Unit tests cover pure logic only (T5). A bug fix ships with one regression
  test at the lowest level that reproduces it (T6).
- No test reads this repository's own source, scripts, workflows or docs as
  text and asserts on it (T3).

## Review and sunset

- One review round, then at most one fix round (R1). A finding counts only if
  it names an invariant or target ID, an in-scope attacker (SPEC section 2) and
  concrete steps to reproduce (R2).
- A new check, rule or option must replace an existing one, or cite a defect
  that escaped to a user (W15).

## Size budgets

The limits are in `loop/SPEC.md` section 7. The gate enforces them.

## Reporting a weakness

Report it privately, as `SECURITY.md` says. This repository is public, so a
weakness never goes into an issue, pull request, branch name, commit or log.
