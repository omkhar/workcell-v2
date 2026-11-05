// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
)

// The workcell adapter drives the product through its CLI alone: one
// `workcell run` per Exec, each a fresh microVM, with the payload carried in
// through stdin (SPEC T1, A8), with the test's export as the product's
// working directory, and one `workcell pull` per Pull, which brings the
// newest session's work tree back. It runs on Linux and on macOS, the two
// hosts with a hypervisor the product drives; elsewhere every operation
// reports ErrNotImplemented. The session policy goes in as the product's
// own file (SPEC section 5): the adapter writes config.toml under a
// directory of the session's own and points XDG_CONFIG_HOME at it. What the
// CLI cannot honour yet, a secret, a cap outside its range, is refused at
// Start with ErrNotImplemented, so that such a test is never a false pass.

// Prepare does the one-time setup the named adapter needs, under dir, which
// the caller removes when the process ends. For workcell that is the four
// artifacts `workcell run` wants and the binary itself, which takes longer
// than one test may, so it runs once, outside any test's context.
func Prepare(ctx context.Context, name, dir string) error {
	if name == "workcell" {
		return prepareWorkcell(ctx, dir)
	}
	return nil
}

// unsupported says why the CLI cannot honour cfg today, "" when it can: it
// takes an export, a network policy, a CPU count of 1 to 32, memory of at
// least 128 MiB and any disk cap, a zero meaning the CLI's default, and on
// Linux a resolver of the test's own, but no secret.
func unsupported(cfg Config) string {
	switch {
	case cfg.Secret != nil:
		return "a secret"
	case cfg.Resolver != "" && !steersResolver:
		return "a resolver of its own"
	case cfg.CPUs < 0 || cfg.CPUs > 32:
		return fmt.Sprintf("%d CPUs", cfg.CPUs)
	case cfg.MemoryMiB < 0 || (cfg.MemoryMiB > 0 && cfg.MemoryMiB < 128):
		return fmt.Sprintf("%d MiB of memory", cfg.MemoryMiB)
	case cfg.DiskMiB < 0:
		return fmt.Sprintf("%d MiB of disk", cfg.DiskMiB)
	}
	return ""
}

// policyFile is where, under the session's config directory, the product
// reads its policy: `$XDG_CONFIG_HOME/workcell/config.toml`.
const policyFile = "workcell/config.toml"

// policyTOML is the session policy of SPEC section 5 for cfg: a [network]
// table whose allow array holds each of cfg.Allow as a TOML basic string. A
// bare name is port 443 by SNI; `name:port` is a forward entry for that one
// port. Every entry comes from the test table, but a quote, a backslash or a
// byte outside printable ASCII would change what the file says, so such an
// entry is refused. With no entry the file says so, which relays no port, as
// no file would; it is written all the same so that nothing the runner's
// user keeps under ~/.config reaches a session.
//
// cfg.Deny names hosts the policy must not allow. A file that does not name
// them is all the product needs, so Deny writes nothing; a name in both
// lists is a mistake in the table and is refused. Making an allowed or a
// denied name resolve to the test host, for a positive path, is the host
// resolver's (U-304, U-305), not this adapter's: it only writes the policy.
func policyTOML(cfg Config) ([]byte, error) {
	b := []byte("[network]\nallow = [")
	for i, name := range cfg.Allow {
		if slices.Contains(cfg.Deny, name) {
			return nil, fmt.Errorf("policy: %q is both allowed and denied", name)
		}
		for j := 0; j < len(name); j++ {
			if c := name[j]; c < ' ' || c > '~' || c == '"' || c == '\\' {
				return nil, fmt.Errorf("policy: allowed name %q has a byte %#x that cannot go in the file", name, c)
			}
		}
		if i > 0 {
			b = append(b, ", "...)
		}
		b = append(append(append(b, '"'), name...), '"')
	}
	return append(b, "]\n"...), nil
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

// pullArgs is the argv of one `workcell pull` into dest, run in the export
// the session's runs started from, so that the newest session is theirs.
func pullArgs(dest string) []string { return []string{"pull", dest} }

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

func (*workcell) Audit(context.Context) (string, []string, error) { return "", nil, ErrNotImplemented }
func (*workcell) Verify(context.Context) error                    { return ErrNotImplemented }
func (*workcell) Helper(context.Context, string) (int, error)     { return 0, ErrNotImplemented }

// Channel is where the guest's init dialled the host: AF_VSOCK, the host's
// CID 2, port 5000. Nothing else of the channel is known here; a probe finds
// the init's connection by that peer and may dial the same port afresh.
func (*workcell) Channel(context.Context) (Channel, error) { return Channel{Addr: "vsock:2:5000"}, nil }

// Relay is where the guest's init opens one vsock stream per relayed
// connection (ADR-003): the host's CID 2, port 5001.
func (*workcell) Relay(context.Context) (Channel, error) { return Channel{Addr: "vsock:2:5001"}, nil }
func (*workcell) Update(context.Context, UpdateConfig) ([]byte, error) {
	return nil, ErrNotImplemented
}
