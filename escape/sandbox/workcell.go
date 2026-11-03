// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"fmt"
	"io"
)

// The workcell adapter drives the product through its CLI alone: one
// `workcell run` per Exec, each a fresh microVM, with the payload carried in
// through stdin (SPEC T1, A8). It is Linux only; elsewhere every operation
// reports ErrNotImplemented. What the CLI cannot honour yet, an export, a
// policy, a secret, a cap other than its fixed ones, is refused at Start
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
// runs with 2 CPUs, 1024 MiB, no disk cap, no export, no policy, no secret.
func unsupported(cfg Config) string {
	switch {
	case cfg.Workspace != "":
		return "a workspace export"
	case cfg.Secret != nil:
		return "a secret"
	case len(cfg.Allow) > 0 || len(cfg.Deny) > 0:
		return "a network policy"
	case cfg.CPUs != 0 && cfg.CPUs != 2:
		return fmt.Sprintf("%d CPUs", cfg.CPUs)
	case cfg.MemoryMiB != 0 && cfg.MemoryMiB != 1024:
		return fmt.Sprintf("%d MiB of memory", cfg.MemoryMiB)
	case cfg.DiskMiB != 0:
		return "a disk cap"
	}
	return ""
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
func (*workcell) Channel(context.Context) (Channel, error)        { return Channel{}, ErrNotImplemented }
func (*workcell) Update(context.Context, UpdateConfig) ([]byte, error) {
	return nil, ErrNotImplemented
}
