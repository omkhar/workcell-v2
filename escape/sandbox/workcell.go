// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"fmt"
	"io"
	"strconv"
)

// The workcell adapter drives the product through its CLI alone: one
// `workcell run` per Exec, each a fresh microVM, with the payload carried in
// through stdin (SPEC T1, A8). It is Linux only; elsewhere every operation
// reports ErrNotImplemented. What the CLI cannot honour yet, an export, a
// policy, a secret, a cap outside its range, is refused at Start
// with ErrNotImplemented, so that such a test is never a false pass.

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
// takes a CPU count of 1 to 32, memory of at least 128 MiB and any disk cap,
// a zero meaning the CLI's default, but no export, no policy, no secret.
func unsupported(cfg Config) string {
	switch {
	case cfg.Workspace != "":
		return "a workspace export"
	case cfg.Secret != nil:
		return "a secret"
	case len(cfg.Allow) > 0 || len(cfg.Deny) > 0:
		return "a network policy"
	case cfg.CPUs < 0 || cfg.CPUs > 32:
		return fmt.Sprintf("%d CPUs", cfg.CPUs)
	case cfg.MemoryMiB < 0 || (cfg.MemoryMiB > 0 && cfg.MemoryMiB < 128):
		return fmt.Sprintf("%d MiB of memory", cfg.MemoryMiB)
	case cfg.DiskMiB < 0:
		return fmt.Sprintf("%d MiB of disk", cfg.DiskMiB)
	}
	return ""
}

// runArgs is the argv of one `workcell run` for a session with cfg's caps:
// each non-zero cap as its flag before `--`, then the guest's loader shell
// and the test's arguments.
func runArgs(cfg Config, loader string, args ...string) []string {
	argv := []string{"run"}
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

func (*workcell) Pull(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Audit(context.Context) (string, []string, error) { return "", nil, ErrNotImplemented }
func (*workcell) Verify(context.Context) error                    { return ErrNotImplemented }
func (*workcell) Helper(context.Context, string) (int, error)     { return 0, ErrNotImplemented }

// Channel is where the guest's init dialled the host: AF_VSOCK, the host's
// CID 2, port 5000. Nothing else of the channel is known here; a probe finds
// the init's connection by that peer and may dial the same port afresh.
func (*workcell) Channel(context.Context) (Channel, error) { return Channel{Addr: "vsock:2:5000"}, nil }
func (*workcell) Update(context.Context, UpdateConfig) ([]byte, error) {
	return nil, ErrNotImplemented
}
