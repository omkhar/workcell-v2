// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package vz

// bootArgs come first on the kernel command line; Config.Cmdline follows. The
// framework's console is the virtio console hvc0. A guest restart, which is how
// the init halts and what panic=-1 asks for, makes the framework boot the kernel
// again rather than stop the VM (measured in TestMachine), so a session ends by
// the supervisor's Kill, as ADR-001 has it.
const bootArgs = "console=hvc0 panic=-1 quiet"

// cmdline is the whole kernel command line for cfg's Cmdline.
func cmdline(extra string) string {
	if extra == "" {
		return bootArgs
	}
	return bootArgs + " " + extra
}
