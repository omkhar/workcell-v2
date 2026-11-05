// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux && !darwin

package sandbox

import (
	"context"
	"net"
)

// workcell on another OS: the product has no hypervisor there, so nothing
// here is implemented.
type workcell struct{}

const steersResolver = false

func prepareWorkcell(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Start(context.Context, Config) (string, error) { return "", ErrNotImplemented }

func (*workcell) Exec(context.Context, ...string) (Output, error) {
	return Output{}, ErrNotImplemented
}

func (*workcell) Bench(context.Context) (Output, error) { return Output{}, ErrNotImplemented }

func (*workcell) Pull(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Helper(context.Context, string) (int, error) { return 0, ErrNotImplemented }

func (*workcell) Bind(context.Context, string, string) (net.Listener, net.PacketConn, error) {
	return nil, nil, ErrNotImplemented
}

func (*workcell) Install(context.Context, Layer) (string, error) { return "", ErrNotImplemented }

func (*workcell) Audit(context.Context) (string, []string, error) { return "", nil, ErrNotImplemented }

func (*workcell) Verify(context.Context) error { return ErrNotImplemented }

func (*workcell) Stop() error { return nil }
