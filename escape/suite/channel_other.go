// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"errors"
	"net"
)

// The payload runs in a Linux guest; elsewhere a vsock channel is out of reach.
func dialVsock(string) (net.Conn, error) { return nil, errors.New("vsock is Linux only") }
