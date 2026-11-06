# Workcell v2 (under construction)

A local sandbox for coding agents: one short-lived microVM per session, nothing in the guest trusted, network and
credentials enforced on the host.

**This is not ready to use.** The released product is at <https://github.com/omkhar/workcell>.

v2 is being built here by a coding-agent loop, one small piece at a time, under rules the loop cannot change. This
repository is a building site. When v2 is finished, the maintainer will propose it as version 2 of `omkhar/workcell`, and
archive this repository.

| To see | Read |
|--------|------|
| What v2 must be | `loop/SPEC.md` |
| What is done and what is next | `loop/state/PLAN.md` |
| How the loop is run and kept in check | `loop/START-HERE.md`, `loop/REFERENCE.md` |

Pull requests, issues and comments from outside are switched off while the loop runs.

**This repository never publishes a release, a tag or a download.** If you see one here, do not use it. Please report it
(`SECURITY.md`).

## If you open this repository in Claude Code

`.claude/settings.json` and `.claude/agents/` are made for the loop, and Claude Code applies them to anyone who works in a clone.

- If your model is overloaded, the fallback chain here replaces yours. It starts with Fable 5.1, which costs more than Opus,
  Sonnet or Haiku.
- Eight agents are defined here: `architect`, `auditor`, `builder`, `redteam`, `reviewer`, `scout`, `scribe` and `verifier`. Five of
  them run on the top tier. They take the place of agents of yours that have the same names.
- The rest only forbids or leaves out. There is a list of commands and paths that Claude is told to leave alone. Agents may
  not start agents of their own. Commits made from the cloud carry no link to the session. One variable,
  `LOOP_SETTINGS_LOADED`, only shows the loop that these settings were loaded.

To use your own fallback chain, set `fallbackModel` in `.claude/settings.local.json`, which git ignores here.

## What it is

`workcell` runs a coding agent, or any command, in a short-lived microVM. Each session gets a fresh guest and a copy of
your working directory. The guest is not trusted. Its network, its secrets and its audit log live on the host, and a
denied connection says what to allow. One binary, no daemon.

## Install

Nothing is released yet, so none of these lines has been tested. They stay untested until v2.0.0.

```
go install github.com/omkhar/workcell/v2/cmd/workcell@latest   # untested until v2.0.0
```

Homebrew and an install script arrive with the release (untested until v2.0.0). Until then the guest files (kernel,
init, root image, Firecracker) are not downloaded for you. The test in `spikes/readme/` builds them in a temporary
directory, and its log is the source of the output below.

## First session

Every command below was run by `spikes/readme/readme_test.go` on a Linux host with KVM. The directory you run
`workcell run` in is copied into the guest as `/workspace`.

```
$ workcell --version
<output: pending hosted run>

$ workcell run -- sh -c 'echo hello from the guest; id -u; uname -m'
<output: pending hosted run>

$ workcell run -- sh -c 'exit 7'
<output: pending hosted run>

$ workcell explain
<output: pending hosted run>

$ workcell run -- sh -c 'getent hosts example.invalid || echo denied'
<output: pending hosted run>

$ workcell log
<output: pending hosted run>

$ workcell ls
<output: pending hosted run>

$ workcell rm <id>
<output: pending hosted run>
```

`workcell run` exits with the command's exit code. It exits 125 when the session itself fails. To allow a host, use
`workcell run --allow HOST ...` or list it under `[network] allow` in `config.toml`. `workcell explain` prints the
config path. The other verbs are `attach`, `stop`, `diff`, `pull`, `verify`, `update`, `doctor` and `bench`.

## How it works

```
 host
 +-----------------------------------------------------------+
 |  workcell run  (supervisor: owns the VM, no daemon)       |
 |    |                                                      |
 |    |  vsock                  +-----------------------+    |
 |    |                         | host proxy            |    |
 |    |   +-------------+  TCP  |  allowlist by name    |--> | allowed
 |    +---| microVM     |------>|  resolver (DNS)       |    | hosts only
 |        |  guest init |  DNS  |  secret broker        |    |
 |        |  /workspace |------>+-----------------------+    |
 |        +-------------+                |                   |
 |   copy of your directory       audit.log (workcell log)   |
 +-----------------------------------------------------------+
```

The guest has no other way out. The supervisor, proxy, resolver and broker are one host process. Secrets are swapped
in by the proxy; the guest holds a placeholder. The rules are in `loop/SPEC.md`.

## Limits

- Linux amd64 with KVM is the host that runs sessions today. macOS support is not finished: its network path is not
  there yet. Linux arm64 is untested.
- There is no release. See the top of this file.
- A session works on a copy of your directory. `workcell pull` brings the work back, and `workcell diff` lists it first.
  With `--mount` the guest writes straight into the real directory, and there is nothing to pull back.
- Only invariants listed in `escape/enforced.txt` have a passing test on a real VM. Nothing else is promised.
