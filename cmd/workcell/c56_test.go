// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C56 of S-1008 (I1, I4, I7, I8), moved here from escape/_pending/S-F39/ by fix unit S-F39.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/relay"
	"golang.org/x/sys/unix"
)

// TestC56PullRewiresALiveSessionsRelaySocket (I1, I4, I7, I8): the operator's temp directory lies under the repository (TMPDIR from an
// allowed .envrc, or `cd /tmp`), so a running session B keeps its VMM directory and relay listener inside the tree. (a) A clone session A
// exports that directory, so A's guest learns B's random name and leaves a symlink in the listener's place, aimed at a host socket of the
// operator's uid outside every export; `workcell pull` unlinks B's live listener, plants the link, and the VMM's next connect for B's
// guest follows it. (b) A mount session run from a shell whose temp directory is elsewhere serves B's directory live, and is not refused.
func TestC56PullRewiresALiveSessionsRelaySocket(t *testing.T) {
	work, out := must(os.MkdirTemp("", "c56")), must(os.MkdirTemp("", "c56")) // out: outside every export. Both hold unix sockets, whose path has 104 bytes on macOS, and t.TempDir() carries this test's name
	t.Cleanup(func() { os.RemoveAll(work); os.RemoveAll(out) })
	data, config := filepath.Join(t.TempDir(), "workcell"), t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("TMPDIR", filepath.Join(work, "tmp"))
	must(0, os.Mkdir(os.TempDir(), 0o700))
	a := c19Data(t, data, "/elsewhere")
	serve := func(path, name string) { // a unix listener that tells every connection who it is
		ln, err := net.Listen("unix", path)
		must(0, err)
		t.Cleanup(func() { ln.Close() })
		go func() {
			for c, err := ln.Accept(); err == nil; c, err = ln.Accept() {
				c.Write([]byte(name))
				c.Close()
			}
		}()
	}
	victim := filepath.Join(out, "agent.sock")
	serve(victim, "victim")
	sessB := filepath.Join(data, "sessions", idOld) // session B runs, as boot makes it: its VMM directory under the temp directory, recorded, with its config file and relay listener
	dirB, err := os.MkdirTemp("", "wc")
	must(0, err)
	must(0, recordBoot(sessB, dirB))
	lock, err := holdSession(sessB)
	must(0, err)
	defer lock.Close()
	must(0, os.WriteFile(filepath.Join(dirB, "firecracker.json"), []byte(`{"vsock":{"guest_cid":3,"uds_path":"`+filepath.Join(dirB, "vsock")+`"}}`), 0o600))
	relayPath := filepath.Join(dirB, fmt.Sprintf("vsock_%d", relay.Port))
	serve(relayPath, "B")
	sessM := mkSession(t, filepath.Join(data, "sessions"), idNew, work) // M, a mount session of work, runs too: no image, lock held. A boot from a shell whose TMPDIR lies under work (a clone session anywhere, a pull of another repository, bench) is refused before a VMM directory is made there, which M's guest would serve live
	defer must(holdSession(sessM)).Close()
	if _, _, err := boot(a, defaults(), nil, sessB, nil, filepath.Join(sessB, "workspace.ext4"), "", nil, nil); err == nil || !strings.Contains(err.Error(), work) || !strings.Contains(err.Error(), os.TempDir()) || string(must(os.ReadFile(filepath.Join(sessB, "vmm")))) != dirB+"\n" { // as a pull of B's repository boots
		t.Errorf("boot returned %v, want a refusal naming the temp directory %s inside %s, which the running mount session serves live, before a VMM directory is recorded (I1, I4, I7)", err, os.TempDir(), work)
	}
	t.Chdir(work)
	t.Setenv("TMPDIR", out) // (b): the operator runs --mount here from a shell whose temp directory is elsewhere; without a VM it ends at boot, which records itself
	session([]string{"true"}, limits{DiskMiB: 16}, true, a, nil, nil)
	if s, _ := newest(filepath.Join(data, "sessions"), work); s != "" && exists(filepath.Join(s, "vmm")) {
		t.Errorf("a mount session of %s reached boot with the running session's VMM directory %s in its live export (I1, I4, I7)", work, dirB)
	}
	t.Setenv("TMPDIR", filepath.Join(work, "tmp")) // (a): the operator runs a clone session here while B runs; without a VM it ends at boot, after the export
	session([]string{"true"}, limits{DiskMiB: 16}, false, a, nil, nil)
	sessA, _ := newest(filepath.Join(data, "sessions"), work)
	img, _ := os.ReadFile(filepath.Join(sessA, "workspace.ext4"))
	if !bytes.Contains(img, []byte(filepath.Base(dirB))) {
		return // the clone session was refused, or its export leaves the VMM directory out: A's guest cannot learn B's name
	}
	rel, m := "tmp/"+filepath.Base(dirB), &manifest{limit: int64(len(img))} // A's guest's tree: the directories as they are, and the link where B's listener is
	for _, e := range []guest.Entry{{Path: "tmp", Kind: guest.KindDir}, {Path: rel, Kind: guest.KindDir}, {Path: rel + "/" + filepath.Base(relayPath), Kind: guest.KindLink, Target: victim}} {
		must(0, m.add(e))
	}
	before, _ := os.ReadFile(filepath.Join(sessA, "vmm")) // the operator runs `workcell pull` here while B runs: without a VM it ends at boot, which records itself
	_, err = fetch(".", func(int, *manifest, source) error { return nil })
	if after, _ := os.ReadFile(filepath.Join(sessA, "vmm")); err != nil && bytes.Equal(before, after) {
		return // refused before boot, so before the destination was touched
	}
	root, err := unix.Open(work, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	must(0, err)
	_ = write(root, m, func(int) ([]byte, error) { return nil, io.EOF }) // a refusal of the tree leaves B's listener in place, which the dial shows
	if c, err := net.Dial("unix", relayPath); err == nil {               // the VMM's connect for the next stream B's guest relays
		if got, _ := io.ReadAll(c); string(got) == "victim" {
			t.Errorf("pull into %s replaced the running session's relay socket %s with the guest's link: the VMM's connect for B's guest reached %s, a host socket outside every export (I1, I4, I7, I8)", work, relayPath, victim)
		}
	}
}
