// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"errors"
	"net"
)

// loopbackAddr adds a canary address to loopback on Linux only.
func loopbackAddr(net.IP) (func(), error) {
	return nil, errors.New("adding a canary address to loopback is Linux only")
}
