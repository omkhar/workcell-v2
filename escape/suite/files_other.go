// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package suite

// The device, mount, handle and fork probes run only in a Linux guest.
func deviceProbe([]string) Result    { return linuxOnly("device") }
func mountProbe([]string) Result     { return linuxOnly("mount") }
func handleProbe([]string) Result    { return linuxOnly("handle") }
func forkProbe([]string) Result      { return linuxOnly("fork") }
func emulationProbe([]string) Result { return linuxOnly("emulation") }
func rebootGuest(string) Result      { return linuxOnly("reboot") }

func memoryBacked(string) bool { return true }

func linuxOnly(name string) Result {
	return Result{Status: "error", Detail: "the " + name + " probe is Linux only"}
}
