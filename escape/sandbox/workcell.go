// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
)

// The workcell adapter drives the product through its CLI alone: one
// `workcell run` per Exec, each a fresh microVM carrying the payload in
// through stdin (SPEC T1, A8), with the test's export as its working
// directory, and one `workcell pull` per Pull. It runs on Linux and macOS;
// elsewhere every operation reports ErrNotImplemented. The session policy
// goes in as the product's own config.toml under a directory of the
// session's own (XDG_CONFIG_HOME), a secret's value in a file beside it,
// outside any export. What the CLI cannot honour yet is refused at Start
// with ErrNotImplemented, so that such a test is never a false pass.

// Prepare does the one-time setup the named adapter needs, under dir, which
// the caller removes when the process ends. For workcell that is the four
// artifacts `workcell run` wants and the binary itself, which takes longer
// than one test may, so it runs once, outside any test's context.
func Prepare(ctx context.Context, name, dir string) error {
	if name == "workcell" {
		return prepareWorkcell(ctx, dir)
	}
	prefix = filepath.Join(dir, "layers")
	return nil
}

// prefix is where a plain container installs every provider, as /usr/local: on every session's PATH, writable.
var prefix string

// unsupported says why the CLI cannot honour cfg today, "" when it can: it
// takes an export, a network policy, a secret, any caps (a zero meaning the
// CLI's default; one outside its bounds it refuses itself), and on Linux a
// resolver of the test's own and, with one, a network of its own.
func unsupported(cfg Config) string {
	switch {
	case cfg.Resolver != "" && !steersResolver:
		return "a resolver of its own"
	case cfg.Isolated && (cfg.Resolver == "" || !steersResolver):
		return "a network of its own"
	}
	return ""
}

// policyFile is where, under the session's config directory, the product
// reads its policy: `$XDG_CONFIG_HOME/workcell/config.toml`.
const policyFile = "workcell/config.toml"

// policyTOML is the session policy of SPEC section 5 for cfg: a [network]
// table whose allow array holds each of cfg.Allow (a bare name is port 443
// by SNI; `name:port` a forward entry), and, for cfg.Secret, one [[secret]]
// table binding it to its host and header, with its value in the file source
// (or the source the entry names, such as a sign-in flow), the guest's
// placeholder in its variable, and any method, path prefix and repositories.
// A quote, a backslash or a byte outside printable ASCII would change what
// the file says, so such an entry is refused. It is written even with no
// entry, so that nothing under the runner's ~/.config reaches a session.
// cfg.Deny writes nothing, since a file that does not name a host is all the
// product needs; a name in both lists is a mistake in the table, and refused.
func policyTOML(cfg Config, source string) ([]byte, error) {
	for _, name := range cfg.Allow {
		if slices.Contains(cfg.Deny, name) {
			return nil, fmt.Errorf("policy: %q is both allowed and denied", name)
		}
	}
	b, err := array([]byte("[network]\nallow = ["), "allowed name", cfg.Allow)
	if err != nil {
		return nil, err
	}
	if sec := cfg.Secret; sec != nil {
		if !slices.Contains(cfg.Allow, sec.Host) {
			return nil, fmt.Errorf("policy: the secret's host %q is not an allowed name", sec.Host)
		}
		b = append(b, "\n[[secret]]\n"...)
		for _, kv := range []struct{ key, value string }{{"name", sec.Name}, {"source", cmp.Or(sec.Source, "file:"+source)}, {"host", sec.Host}, {"header", sec.Header}, {"env", sec.Env}, {"method", sec.Method}, {"path", sec.Path}} {
			if kv.value == "" {
				continue // an optional key, or one the product defaults
			}
			if b, err = quoted(append(b, kv.key+" = "...), "secret "+kv.key, kv.value); err != nil {
				return nil, err
			}
			b = append(b, '\n')
		}
		if len(sec.Repos) > 0 {
			if b, err = array(append(b, "repos = ["...), "secret repo", sec.Repos); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// array appends names to b as the rest of a TOML array of basic strings.
func array(b []byte, what string, names []string) ([]byte, error) {
	for i, n := range names {
		if i > 0 {
			b = append(b, ", "...)
		}
		var err error
		if b, err = quoted(b, what, n); err != nil {
			return nil, err
		}
	}
	return append(b, "]\n"...), nil
}

// quoted appends s to b as a TOML basic string, refusing a byte that would
// change what the file says.
func quoted(b []byte, what, s string) ([]byte, error) {
	for j := 0; j < len(s); j++ {
		if c := s[j]; c < ' ' || c > '~' || c == '"' || c == '\\' {
			return nil, fmt.Errorf("policy: %s %q has a byte %#x that cannot go in the file", what, s, c)
		}
	}
	return append(append(append(b, '"'), s...), '"'), nil
}

// runArgs is the argv of one `workcell run` for a session with cfg's mode
// and caps: `--mount` for a live export, each non-zero cap as its flag,
// all before `--`, then the guest's loader shell and the test's arguments.
func runArgs(cfg Config, loader string, args ...string) []string {
	argv := []string{"run"}
	if cfg.Mount {
		argv = append(argv, "--mount")
	}
	if cfg.CPUs != 0 {
		argv = append(argv, "--cpus", strconv.Itoa(cfg.CPUs))
	}
	if cfg.MemoryMiB != 0 {
		argv = append(argv, "--memory", fmt.Sprintf("%dMiB", cfg.MemoryMiB))
	}
	if cfg.DiskMiB != 0 {
		argv = append(argv, "--disk", fmt.Sprintf("%dMiB", cfg.DiskMiB))
	}
	argv = append(argv, "--", "/bin/sh", "-c", loader, "sh")
	return append(argv, args...)
}

// cpioEntry writes one newc ("070701") cpio entry: a header of the magic and
// thirteen 8-digit hex fields, the name with its NUL, and the data, each of
// the last two padded to four bytes. A trailer is the entry named
// "TRAILER!!!" with no data.
func cpioEntry(w io.Writer, name string, mode uint32, data []byte) error {
	const magic = "070701"
	ino := uint32(1)
	if name == "TRAILER!!!" {
		ino = 0
	}
	fields := []uint32{ino, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	b := []byte(magic)
	for _, f := range fields {
		b = fmt.Appendf(b, "%08X", f)
	}
	b = append(b, name...)
	b = append(b, 0)
	b = pad4(b)
	b = append(b, data...)
	_, err := w.Write(pad4(b))
	return err
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// Channel is where the guest's init dialled the host: AF_VSOCK, the host's
// CID 2, port 5000. Nothing else of the channel is known here; a probe finds
// the init's connection by that peer and may dial the same port afresh.
func (*workcell) Channel(context.Context) (Channel, error) { return Channel{Addr: "vsock:2:5000"}, nil }

// Relay is where the guest's init opens one vsock stream per relayed
// connection (ADR-003): the host's CID 2, port 5001.
func (*workcell) Relay(context.Context) (Channel, error) { return Channel{Addr: "vsock:2:5001"}, nil }
