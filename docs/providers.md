# Providers

A provider is a coding-agent CLI that Workcell knows. Each one is a single TOML file in
[`internal/provider/`](../internal/provider/), compiled into the binary. The policy reader parses these
files, in the same subset as [policy](policy.md). A provider CLI is guest content, not part of the trusted
base (A10): it holds only placeholders, and the network list and secret bindings in [policy](policy.md)
limit what it can reach (I2, I5).

## What a file declares

- `[provider]`: `name` (the file's name), `binary` (the executable's name, not a path) and `hosts`, the
  bare DNS names the CLI reaches.
- `[install]`: `method = "binary"` with a `pin` that names a row in `pins/`, or `method = "npm"` with a
  `package`. No version appears in a provider file (A10).
- `[[secret]]`: one row per API-key credential, with `name`, `host` (one of the provider's hosts),
  `header` (lower case), `env` (the variable that holds the placeholder) and an optional `prefix` of
  `""` or `"Bearer "`.

| File | Binary | Install | Hosts | Secret row: name, header, env | Sign-in |
|------|--------|---------|-------|-------------------------------|---------|
| `claude.toml` | `claude` | binary, pin `claude-code` | `api.anthropic.com`, `claude.ai`, `console.anthropic.com` | `anthropic`, `x-api-key`, `ANTHROPIC_API_KEY` | API key only |
| `codex.toml` | `codex` | binary, pin `codex` | `api.openai.com`, `auth.openai.com`, `chatgpt.com` | `openai`, `authorization` with `Bearer `, `OPENAI_API_KEY` | API key only |
| `copilot.toml` | `copilot` | binary, pin `copilot-cli` | `api.githubcopilot.com`, `api.individual.githubcopilot.com`, `api.github.com`, `github.com` | `github`, `authorization` with `Bearer `, `COPILOT_GITHUB_TOKEN` | token only |
| `gemini.toml` | `gemini` | npm, package `@google/gemini-cli` | `generativelanguage.googleapis.com`, `ai.google.dev` | `gemini`, `x-goog-api-key`, `GEMINI_API_KEY` | API key only |

Sign-in with a subscription account (Claude, ChatGPT, Copilot or Google) is not supported for any provider. It was
not tested against a real provider, and a `signin:HOST/PATH` source is proven against the suite's test endpoint only.

A provider's hosts do not open the network. A session reaches them only if `[network] allow` lists them
too (I2).

## Bind a secret to a provider

A `[[secret]]` row with a provider's secret name, and no `host` or `header`, takes those and its `env`
from the provider. You still choose the `source`:

    [network]
    allow = ["api.anthropic.com"]

    [[secret]]
    name   = "anthropic"
    source = "keychain:workcell/anthropic"

`workcell explain` then prints the binding:

```
  anthropic: in x-api-key to https://api.anthropic.com, as $ANTHROPIC_API_KEY
```

If the host is not in `[network] allow`, the command stops and names the line. For a name no provider
knows, give `host` and `header` yourself. Give both or neither; one alone is refused.

## Install a provider CLI

`workcell update [--to VERSION | --rollback] [AGENT]` installs the pinned release of one provider, or of
every provider that has a release.

- The row in `pins/`, such as [`pins/claude-code.json`](../pins/claude-code.json), names the version, and
  for each architecture a URL and a SHA-256 digest.
- The host fetches the artifact from that URL. It unpacks it only if its SHA-256 is the row's (B8). A
  mismatch leaves no file behind.
- The result is an ext4 layer image in the data directory (`$XDG_DATA_HOME/workcell`, or
  `~/.local/share/workcell`). A session attaches it read-only, and the guest finds the CLI in
  `/opt/<name>/bin`.
- `--to` takes the row's current or previous release. `--rollback` returns to the layer kept before.

Not yet: today only `claude` has a release in `pins/`. The `codex` and `copilot-cli` rows name no release,
and `gemini` is an npm package, which `update` does not install yet. Running `update` for those gives:

```
workcell update: codex: provider codex names pin codex, whose row pins no release yet
workcell update: gemini: provider gemini is installed by npm; update installs binaries only
```

## Add a provider

Add one file to `internal/provider/`, with a `[provider]`, an `[install]` and any `[[secret]]` rows (B15).
A binary provider also needs its row in `pins/`. The loader checks the whole set and refuses any fault
with the file and line. [`provider_test.go`](../internal/provider/provider_test.go) covers the one-file case.
