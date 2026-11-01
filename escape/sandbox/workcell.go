// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import "context"

// workcell drives the product. Until U-204b replaces it, every operation
// reports ErrNotImplemented. The real adapter uses only the workcell CLI.
type workcell struct{}

func (*workcell) Start(context.Context, string) error { return ErrNotImplemented }

func (*workcell) Exec(context.Context, ...string) (Output, error) {
	return Output{}, ErrNotImplemented
}

func (*workcell) Stop() error { return ErrNotImplemented }
