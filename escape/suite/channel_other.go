// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

import (
	"errors"
	"time"
)

// The payload runs in a Linux guest; elsewhere the channel is out of reach.
type rawConn struct{}

func (*rawConn) close()                            {}
func (*rawConn) write([]byte, time.Duration) error { return errors.New("the channel is Linux only") }

func stealChannel(string) (*rawConn, error) { return nil, errors.New("the channel is Linux only") }
func dialChannel(string) (*rawConn, error)  { return nil, errors.New("the channel is Linux only") }
