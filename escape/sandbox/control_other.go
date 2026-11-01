// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package sandbox

import "errors"

func newControl() (Sandbox, error) {
	return nil, errors.New("control sandbox: Linux namespaces only; unsupported on this OS")
}
