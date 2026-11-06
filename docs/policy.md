# Policy

Policy says what a session can reach and which secret goes to which host. The rules are in section 5 of the
specification. Run `workcell explain` to see the result for your directory.

## Where it lives

- Your grants: `~/.config/workcell/config.toml`, or `$XDG_CONFIG_HOME/workcell/config.toml` when that is set.
  A missing file grants nothing.
- The repository's file: `workcell.toml` in the directory you start the session in. It can only narrow
  your grants (I13). See [Narrowing](#narrowing).

## Tables

### [network]

    [network]
    allow = ["api.anthropic.com", "github.com", "example.org:8443"]

A bare name allows port 443, and the session proxy terminates that TLS connection. `name:port` forwards
that one TCP port as it is. IP addresses are refused. With no entry, the guest has no network (I2).

### [[secret]]

    [[secret]]
    name   = "anthropic"
    source = "keychain:workcell/anthropic"
    host   = "api.anthropic.com"
    header = "x-api-key"
    env    = "ANTHROPIC_API_KEY"

- `name` and `source` are required. `source` is one of the forms in [Secret sources](#secret-sources).
- `host` must be a bare name in `[network] allow`. `header` is the header that carries the value. Give
  both, or neither and let a provider fill them in ([providers](providers.md)). A host and header pair
  can be bound once.
- `env` is the guest variable that holds the placeholder. Leave it out and the guest gets no variable.
- `method` and `path` narrow the swap to requests with that method, under that path prefix. Any other
  request gets a 403, and the value is not read.
- `repos` is a list of `owner/name` repositories. It narrows the swap to git requests for them, and
  cannot be combined with `method` or `path`.

### [workspace], [resources], [update]

The reader checks the syntax of these tables, but not their keys yet. A typo in them passes silently.
Use the flags instead:

- `--mount` makes the workspace live. Without it the guest gets a copy (A5).
- `--cpus` (1 to 32, default 2), `--memory` (at least 128MiB, default 1GiB) and `--disk` (default 1GiB).
- `workcell update` installs provider CLIs. The `[update]` channel and cool-off of SPEC B10 are not read yet.

## File format

The reader takes a subset of TOML: `[table]` and `[[table]]` headers, bare keys, double-quoted strings,
integers, arrays of strings (which may span lines), and `#` comments. A file is at most 1 MiB. It refuses
the rest and names the line: literal `'strings'`, `"""multi-line"""` strings, inline tables, dotted keys,
floats, booleans, dates, nested arrays, duplicate keys or tables, unknown tables, and unknown keys in
`[network]` and `[[secret]]`. The full list is in
[`internal/policy/policy_test.go`](../internal/policy/policy_test.go). Example (paths shortened):

    workcell explain: $SCRATCH/c4/workcell/config.toml:2: literal strings ('...') are not supported: use double quotes

## Narrowing

A repository's `workcell.toml` narrows your grants. It cannot widen them (I13).

- An `allow` array keeps only your entries whose text is exactly the same. Other hosts it names are
  reported as not granted.
- `[[secret]]` rows, if it has any, keep only your rows with a name it also names. Your row whose host
  the narrowed allow list drops goes too.
- Its `[workspace]`, `[resources]` and `[update]` tables are ignored. Of its `[[secret]]` rows only the
  `name` is used, but `source` is still required.

A `workcell.toml` that is a symbolic link, a pipe or a directory is ignored, with a line on stderr. One
that does not parse stops the session before anything starts.

`--allow HOST` (or `HOST:PORT`) adds an entry for one run, and you can repeat it. You type it on the host,
so a repository cannot add one, and the repository's narrowing does not apply to it.

## workcell explain

`workcell explain` takes the same `--mount`, `--allow` and `--cache` flags as `workcell run`. It prints
what a session started here can reach, and starts nothing. It never reads a secret's source, so it never
shows a value (I5).

The output below is from a directory whose `workcell.toml` allows `api.anthropic.com` and `example.com`,
run with `--allow extra.example.net`. The user's file allows `api.anthropic.com` and binds an `anthropic`
secret.

```
workspace: a copy of $SCRATCH/repo
  The agent works in the copy; the real tree does not change until workcell pull brings
  the work back, and workcell diff lists it first.
network: from $SCRATCH/cfg/workcell/config.toml and --allow
  https://api.anthropic.com  (443, terminated by the session proxy)
  https://extra.example.net  (443, terminated by the session proxy)
  Everything else is refused, and DNS answers only these names.
workcell.toml asks for "example.com": not granted; allow it in $SCRATCH/cfg/workcell/config.toml or with --allow
secrets: swapped in by the session proxy; the guest holds a placeholder
  anthropic: in x-api-key to https://api.anthropic.com, as $ANTHROPIC_API_KEY
```

## Secret sources

- `file:/abs/path` reads a regular file of at most 64 KiB. Its value is its one line.
- `cmd:/abs/program args` runs a program with no shell. Arguments are split on spaces, with no quoting.
  The environment is cleared, except `PATH`, `LC_ALL`, `HOME`, the D-Bus address and `XDG_RUNTIME_DIR`.
  The program has two minutes.
- `secret-service:SERVICE/ACCOUNT` runs `/usr/bin/secret-tool lookup` (Linux).
- `keychain:SERVICE/ACCOUNT` runs `/usr/bin/security find-generic-password -w` (macOS login keychain).

The value is read on each use, never at start. An error never prints the value or a program's stderr.
A `signin:HOST/PATH` source is a sign-in flow, which this page does not cover.

## How a secret reaches the guest

The guest holds a placeholder: `wcph-` and 32 hex digits, in the variable named by `env`. When the guest
sends it to the bound host, in the bound header, the proxy swaps in the real value on the way out. The swap
happens only on a connection the proxy terminates (I6). A placeholder sent to another host, or in another
header, is not swapped (I5, A4). The guest never holds the value.
