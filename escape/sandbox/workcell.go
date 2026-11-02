// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import "context"

// workcell drives the product. Until U-204b replaces it, every operation
// reports ErrNotImplemented. The real adapter uses only the workcell CLI.
type workcell struct{}

func (*workcell) Start(context.Context, Config) (string, error) { return "", ErrNotImplemented }

func (*workcell) Exec(context.Context, ...string) (Output, error) {
	return Output{}, ErrNotImplemented
}

func (*workcell) Pull(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Stop() error { return ErrNotImplemented }

func (*workcell) Audit(context.Context) (string, []string, error) { return "", nil, ErrNotImplemented }
func (*workcell) Verify(context.Context) error                    { return ErrNotImplemented }
func (*workcell) Helper(context.Context, string) (int, error)     { return 0, ErrNotImplemented }
func (*workcell) Channel(context.Context) (Channel, error)        { return Channel{}, ErrNotImplemented }
func (*workcell) Update(context.Context, UpdateConfig) ([]byte, error) {
	return nil, ErrNotImplemented
}
