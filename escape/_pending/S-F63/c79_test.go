// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C79 of S-1009, sweep 3 (I14, I13): the user's [update] ca names, by an absolute path, a file under the directory the session runs in. It waits here under S4: move to cmd/workcell/c79_test.go in the fix unit and remove this folder.

package main

import (
	"cmp"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC79UpdateCAUnderTheWorkingDirectory (I14, I13): newInstaller refuses a relative ca (C59) but takes an absolute one wherever it lies, so `ca = "<cwd>/certs/corp-ca.pem"` makes the repository's file the installer's only root: a malicious repository ships it, or guest root under --mount rewrites it, and a TLS server holding that certificate (an httptest server on loopback) is trusted for the installer's fetches. A ca under cwd must be refused, or at least not trusted; the same ca outside cwd (the control arm) still works. Precondition the attacker does not control: the operator's [update] table names a file under the repository.
func TestC79UpdateCAUnderTheWorkingDirectory(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})) // the attacker's upstream: its self-signed certificate is its own root
	defer srv.Close()
	for _, under := range []bool{true, false} { // the ca under cwd, then beside the config, outside it: the control arm
		t.Run(map[bool]string{true: "ca under cwd", false: "control: ca outside cwd"}[under], func(t *testing.T) {
			cfg, repo := t.TempDir(), must(filepath.EvalSymlinks(t.TempDir())) // macOS: /var is /private/var
			ca := map[bool]string{true: filepath.Join(repo, "certs", "corp-ca.pem"), false: filepath.Join(cfg, "corp-ca.pem")}[under]
			t.Setenv("XDG_CONFIG_HOME", cfg)
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			must(0, cmp.Or(os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700), os.MkdirAll(filepath.Dir(ca), 0o700), os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644),
				os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nchannel = \""+srv.URL+"/channel.json\"\nkey = \""+strings.Repeat("00", 32)+"\"\nca = \""+ca+"\"\n"), 0o600)))
			t.Chdir(repo)
			in, err := newInstaller()
			if err == nil { // the ca was taken: does the transport built on it trust the server? A HEAD carries no body to close
				_, err = in.client.Head(srv.URL)
			}
			if trusted := err == nil; trusted == under {
				t.Errorf("I14: ca = %q, under cwd: %t: newInstaller and a fetch through its transport from the server holding that certificate gave %v; want trusted: %t", ca, under, err, !under)
			}
		})
	}
}
