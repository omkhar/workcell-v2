// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"net"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// loopbackAddr adds nothing off Linux: a canary address is an alias the
// host's loopback interface already holds. It checks that; nothing to remove.
func loopbackAddr(ip net.IP) (func(), error) {
	if err := sandbox.LoopbackHolds(ip.String()); err != nil {
		return nil, err
	}
	return func() {}, nil
}
