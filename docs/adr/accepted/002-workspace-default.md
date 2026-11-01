# ADR-002: default workspace mode

status: accepted (maintainer, 2026-10-31)

The default workspace mode is `clone`. A session works on a copy-on-write copy of
the repository, and results return through `workcell diff` and `workcell pull`.
A live mount is available only through the explicit `--mount` flag.

Reversal cost: one default value and one paragraph of documentation.
