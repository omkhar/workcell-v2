// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package sandbox

import "context"

// workcell on another OS: the product's guest runs under Firecracker, which is
// Linux only, so nothing here is implemented.
type workcell struct{}

func prepareWorkcell(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Start(context.Context, Config) (string, error) { return "", ErrNotImplemented }

func (*workcell) Exec(context.Context, ...string) (Output, error) {
	return Output{}, ErrNotImplemented
}

func (*workcell) Bench(context.Context) (Output, error) { return Output{}, ErrNotImplemented }

func (*workcell) Pull(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Stop() error { return nil }
