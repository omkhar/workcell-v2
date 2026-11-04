// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux || (darwin && arm64 && cgo)

package main

import "golang.org/x/sys/unix"

// rawMode puts the terminal on fd in raw mode, so the guest's terminal sees every key, and
// returns the function that restores it. ok is false when fd is not a terminal.
func rawMode(fd int) (restore func(), ok bool) {
	old, err := unix.IoctlGetTermios(fd, termiosGet)
	if err != nil {
		return nil, false
	}
	t := *old
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(fd, termiosSet, &t) != nil {
		return nil, false
	}
	return func() { _ = unix.IoctlSetTermios(fd, termiosSet, old) }, true
}

// windowSize is the size of the terminal on fd; zero if it cannot be read.
func windowSize(fd int) (rows, cols uint16) {
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return ws.Row, ws.Col
}
