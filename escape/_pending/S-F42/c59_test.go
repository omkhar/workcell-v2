// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C59 of S-1009, sweep 2 (I14). Fix unit S-F42 first moves this file to
// cmd/workcell/c59_test.go, as this comment says.

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestC59UpdateCAIsNotReadFromTheWorkingDirectory: the user's [update] ca names a relative file, and the repository that is the working directory
// holds a ca.pem of the attacker's. Building the installer must not read it: a relative ca is refused, or at least the roots are not the repository's (I14, I13).
func TestC59UpdateCAIsNotReadFromTheWorkingDirectory(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})) // the attacker's upstream: its self-signed certificate is its own root
	defer srv.Close()
	cfg, repo := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700)
	os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nchannel = \""+srv.URL+"/channel.json\"\nca = \"ca.pem\"\nkey = \""+strings.Repeat("00", 32)+"\"\n"), 0o600)
	os.WriteFile(filepath.Join(repo, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644)
	t.Chdir(repo)
	in, err := newInstaller()
	if err != nil {
		return // the relative ca was refused: the repository's file is no root
	}
	resp, gerr := in.client.Get(srv.URL) // nil: the installer's transport trusts the repository's root
	if gerr == nil {
		resp.Body.Close()
	}
	t.Fatalf("newInstaller accepted ca = \"ca.pem\" from the working directory; a fetch through its transport from the attacker's upstream gave %v; want the relative path refused", gerr)
}
