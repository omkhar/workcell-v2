// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// privileged binds a port below 1024 through sudo on Linux only.
func privileged(network, addr, _ string) (net.Listener, net.PacketConn, error) {
	return nil, nil, fmt.Errorf("bind %s %s needs root: %w", network, addr, errors.New("Linux only"))
}

// Bind is the payload's privileged helper, on Linux only.
func Bind(network, addr, _ string) int {
	fmt.Fprintf(os.Stderr, "bind %s %s: Linux only\n", network, addr)
	return 1
}
