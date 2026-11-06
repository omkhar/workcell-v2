# Migrating from v1

v2 is one binary that runs each session in its own microVM. The host enforces the network and the secrets, the
guest gets placeholder credentials only, and one TOML file holds the policy. Nothing in v2 is released yet, so this
page describes v2 as built today. See the [README](../README.md), [policy](policy.md) and
[providers](providers.md).

## Flag map

The v2 flags are `--mount`, `--cpus`, `--memory`, `--disk`, `--allow` and `--cache` (on `run`; `explain` takes `--mount`, `--allow`
and `--cache`), `--to` and `--rollback` (on `update`), `-f` and `--format` (on `log`), and `--version`.

| v1 flag | v2 | why |
|---------|----|-----|
| `--ack-arbitrary-command` | removed | no modes |
| `--ack-breakglass` | removed | no modes |
| `--ack-control-plane-vcs` | removed | no modes |
| `--ack-repo-mcp` | removed | no modes |
| `--agent` | `workcell run -- CMD` | any command runs the same way |
| `--agent-arg` | words after `--` | same |
| `--agent-autonomy` | removed | no modes |
| `--allow-arbitrary-command` | removed | no modes |
| `--allow-control-plane-vcs` | removed | no modes |
| `--allow-nongit-workspace` | removed | any directory is copied |
| `--allow-repo-mcp` | removed | no modes |
| `--allow-uncertified-agent` | removed | no tiers |
| `--audit-transcript` | `workcell log` | log lives on the host (A1) |
| `--auth-status` | `workcell explain` | lists secrets, never values (I5) |
| `--backend` | removed | one VM backend per OS |
| `--build-arg` | removed | no image build on the host |
| `--builder` | removed | no image build on the host |
| `--cache-profile` | `--cache NAME[:rw]` | named dependency cache |
| `--cap-add` | removed | no container options |
| `--cap-drop` | removed | no container options |
| `--codex-rules-mutability` | removed | no guest-side rules |
| `--colima-bin` | removed | no Colima |
| `--colima-home` | removed | no Colima |
| `--colima-profile` | removed | no Colima |
| `--colima-state-root` | removed | no Colima |
| `--commit` | removed | `workcell pull` copies the tree back (A5) |
| `--commit-message-file` | removed | `workcell pull` copies the tree back (A5) |
| `--connect-timeout` | removed | internal tool option |
| `--container-cpu` | `--cpus` | one resource flag |
| `--container-memory` | `--memory` | one resource flag |
| `--container-mutability` | removed | no modes |
| `--context-name` | removed | no Docker contexts |
| `--cpu` | `--cpus` | renamed |
| `--credential` | `[[secret]]` in config.toml | placeholders only (A4) |
| `--cwd` | the directory you run in | one workspace rule |
| `--debug-log` | removed | `workcell log` (A1) |
| `--disk` | `--disk` | kept |
| `--doctor` | `workcell doctor` | verb |
| `--dry-run` | `workcell explain` | verb |
| `--egress-proxy` | removed | proxy is always on the host (A1) |
| `--env-file` | removed | no real secrets in the guest (A4) |
| `--file-trace-log` | removed | `workcell log` (A1) |
| `--format` | `workcell log --format ocsf` | OCSF export only |
| `--gc` | `workcell rm ID` | verb |
| `--get-regexp` | removed | internal tool option |
| `--git-bin` | removed | internal tool option |
| `--git-head` | removed | internal tool option |
| `--head` | removed | internal tool option |
| `--host-arch` | removed | one image per host |
| `--id` | positional ID | `attach`, `stop`, `rm`, `log`, `verify` |
| `--injection-policy` | config.toml, workcell.toml | one TOML format (section 5) |
| `--input-kinds` | removed | internal tool option |
| `--inspect` | `workcell ls`, `explain` | verbs |
| `--json` | `workcell log --format ocsf` | one output format |
| `--load` | removed | no image build on the host |
| `--log-level` | removed | no log levels |
| `--logs` | `workcell log` | verb |
| `--max-time` | removed | internal tool option |
| `--memory` | `--memory` | kept |
| `--mode` | removed | no modes |
| `--mount` | `--mount` | now the live workspace; default is a copy (A5) |
| `--mount-type` | removed | one mount kind |
| `--name` | removed | sessions have IDs; see `workcell ls` |
| `--no-default-injection-policy` | removed | no default policy: no entry, no network (I2) |
| `--no-spinner` | removed | no UI options |
| `--origin-hash` | removed | internal tool option |
| `--output` | removed | internal tool option |
| `--parallel` | removed | one VM per session |
| `--pids-limit` | removed | no container options |
| `--policy` | config.toml, workcell.toml | one TOML format (section 5) |
| `--prepare` | removed | no host-side prepare step |
| `--prepare-only` | removed | no host-side prepare step |
| `--profile` | removed | no profiles |
| `--provenance` | removed | internal tool option |
| `--provider-ready-states` | removed | internal tool option |
| `--read-only` | removed | the default copy is the safe path (A5) |
| `--real-home` | removed | the guest never sees your home (A4) |
| `--rebuild` | removed | no image build on the host |
| `--repair-profile` | removed | no profiles |
| `--repo-root` | the directory you run in | one workspace rule |
| `--resolution-states` | removed | internal tool option |
| `--resolvers` | removed | internal tool option |
| `--retry` | removed | internal tool option |
| `--retry-all-errors` | removed | internal tool option |
| `--retry-delay` | removed | internal tool option |
| `--root` | removed | internal tool option |
| `--runtime` | removed | one VM backend per OS |
| `--sbom` | removed | internal tool option |
| `--security-opt` | removed | no container options |
| `--session-id` | positional ID | `attach`, `stop`, `rm`, `log`, `verify` |
| `--session-workspace` | the directory you run in | one workspace rule |
| `--snapshot-id` | removed | internal tool option |
| `--store-root` | removed | one data directory |
| `--target` | removed | one target per OS |
| `--target-id` | removed | one target per OS |
| `--test-fail-after-profile-refresh` | removed | internal tool option |
| `--text` | removed | one output format |
| `--title-file` | removed | internal tool option |
| `--tmpfs` | removed | no container options |
| `--tree` | removed | internal tool option |
| `--ui` | removed | no UI options |
| `--user` | removed | no container options |
| `--verbose` | removed | no log levels |
| `--version` | `--version` | kept |
| `--vm-cpu` | `--cpus` | renamed |
| `--vm-disk` | `--disk` | renamed |
| `--vm-memory` | `--memory` | renamed |
| `--vm-type` | removed | one VM backend per OS |
| `--workdir` | the directory you run in | one workspace rule |
| `--workspace` | the directory you run in | one workspace rule |

"Internal tool option" marks a flag whose meaning comes from its name and from v1's build and release tooling
rather than from a user-facing command. None has a v2 counterpart.

## What was removed and why

- Modes, profiles, tiers and acknowledgement flags. v2 has no modes, profiles, tiers or assurance labels
  (section 5). Every session gets the same enforcement, and a repository can only narrow your grants (I13).
- Container, Colima and Docker options. A session is a microVM (Firecracker on Linux, Virtualization.framework on
  macOS), so there is no runtime, context, builder or container setting to choose. The guest image is prebuilt and
  pulled by digest (A6), not built on the host.
- Guest-side rules and shims. Nothing in the guest is trusted, so policy is enforced on the host (A1).
- Staged real secrets. The guest holds a placeholder; the host swaps in the value on the wire for the one host and
  header you bound (A4). There is no `--env-file` and no way to hand the guest a real key.
- Daemon. v2 has none (A9). Sessions are children of the `workcell` process and end with it.
- Live workspace by default. The default is a copy; `--mount` is the labelled live option, and it is not yet
  available on macOS (A5).

Not built yet: the `secret` verb (see [policy](policy.md) for the `source` forms), and the `[workspace]`,
`[resources]` and `[update]` keys of config.toml.

## Remove v1 state

The v1 launcher is not in this repository, so only what its helper code names is confirmed. A path marked
untested is a guess; check it against your v1 install before you delete anything.

- Keychain items (macOS), from v1's credential broker. Remove each with `security delete-generic-password -s NAME`
  for `workcell-claude-api-key`, `workcell-gemini-api-key` and `workcell-codex-api-key`. Skip an item a v2
  `[[secret]]` `source` still names; v2 reads `keychain:SERVICE/ACCOUNT`.
- Colima profile VM of v1 (macOS): `colima list` shows it; remove it with `colima delete PROFILE`. The profile name
  is set by v1's `--colima-profile`; the default is untested.
- Audit logs, session records, and the per-host signing key directory (mode 0700): v1 takes their locations from its
  launcher, which is not here. Untested: look under `~/.config/workcell`, `~/.local/state/workcell` and
  `~/.cache/workcell`, and remove what you find with `rm -r`.
- Docker images and containers named for workcell: `docker images | grep workcell`, then `docker rmi ID`. Untested.
- v1 binary and Homebrew formula: `brew uninstall workcell` (untested). Install v2 from the README.

v2 keeps its own state in its data directory and `~/.config/workcell/config.toml`; `workcell rm ID` removes a session.
