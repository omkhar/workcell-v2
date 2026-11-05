// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package vmm is the backend interface of ADR-001: one microVM per session (A2),
// six methods (A7), nothing asked of the guest (A1). A backend's New(cfg) boots
// nothing. Stop, exit code and network go over the channel, not through here.
package vmm

import (
	"context"
	"io"
	"net"
)

// Machine is one guest. Listen comes before Start; Close ends the life of the value.
type Machine interface {
	// Check proves the host can run a guest (the hypervisor device and the pinned
	// binary) and boots nothing. doctor calls it alone.
	Check(ctx context.Context) error
	// Listen accepts guest-initiated vsock connections to one host port. It must be
	// called before Start. A caller that wants one connection closes the listener after it.
	Listen(port uint32) (net.Listener, error)
	// Start boots the guest. A second call is an error.
	Start(ctx context.Context) error
	// Wait blocks until the guest has stopped and says why: nil for a clean exit, an
	// error naming the signal or exit code otherwise, or ctx.Err() if the context
	// ends first, in which case nothing is killed.
	Wait(ctx context.Context) error
	// Kill destroys the VM now. It is idempotent and safe before Start.
	Kill() error
	// Close kills the guest if it still runs and removes the files the backend made
	// under Config.Dir, and nothing of the supervisor's (I7).
	Close() error
}

// Layer is one provider's current layer: the agent's name and its ext4 image on the host.
type Layer struct{ Name, Image string }

// Cache is a named dependency cache: an ext4 image on the host that the guest gets as a drive,
// read-only on the host's side unless Writable (A1).
type Cache struct {
	Name, Image string
	Writable    bool
}

// Config is everything a backend needs. The command line is built on the host and
// holds no secret (I5). Resource caps go here, not into a seventh method.
type Config struct {
	Binary    string // the pinned VMM binary
	Kernel    string
	Initrd    string  // optional initramfs
	Image     string  // read-only root drive, optional
	Workspace string  // read-write drive, optional
	Layers    []Layer // provider layers, one read-only drive each, attached after the two above in this order
	Caches    []Cache // dependency caches, one drive each, attached after the layers in this order
	Cmdline   string  // appended to the backend's own boot arguments
	CPUs      int
	MemoryMiB int
	CID       uint32
	Console   io.Writer // the guest's serial console; nil discards it
	// Dir is the session's directory. The backend keeps its sockets and config there.
	// Keep it short: a unix socket path is capped at 108 bytes and Firecracker
	// appends _<port> to its vsock path.
	Dir string
}
