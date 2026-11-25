// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C60 of S-1011, sweep 2 (I12), fixed by S-F43. It stays here as the regression test of C60 (S4).

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/provider"
)

// TestC60ZeroInstallerFailReadsTheRepository (I12, B9): the user's [update] ca is relative, so startup printed one line and handed run the zero installer, whose data directory is "". A first frame guest root chose, an Exit with an error, then has run call fail, which reads layers/<agent>/current for every provider
// against that directory: the repository the operator runs in. A symlink there to a FIFO parks `workcell run` for good, after the VM is closed; a regular file makes the repository's bytes the marker. The read must return, or never be made: fail takes a bounded time whatever the repository holds.
func TestC60ZeroInstallerFailReadsTheRepository(t *testing.T) {
	p, cfg, repo := must(provider.All())[0], t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700)
	os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nca = \"ca.pem\"\n"), 0o600)
	fifo, current := filepath.Join(repo, "fifo"), filepath.Join(repo, "layers", p.Name, "current") // the repository's: a FIFO, which an open for reading waits on until a writer comes
	must(0, syscall.Mkfifo(fifo, 0o600))
	os.MkdirAll(filepath.Dir(current), 0o700)
	os.Symlink(fifo, current)
	t.Chdir(repo)
	in := startup(io.Discard) // what run keeps for fail: on this config, one line on stderr and the zero installer
	done := make(chan struct{})
	go func() { in.fail(p.Binary, io.Discard); close(done) }() // the first frame was an Exit with an error, so run calls fail with the command's name
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		w, _ := os.OpenFile(fifo, os.O_WRONLY, 0) // frees the goroutine: the read sees EOF
		w.Close()
		t.Fatalf("fail with the installer startup returned under ca = \"ca.pem\" has read %s against the working directory for 3s: a FIFO the repository planted holds workcell run after the VM is closed", filepath.Join("layers", p.Name, "current"))
	}
}
