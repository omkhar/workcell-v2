// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C79 of S-1009, sweep 3 (I14, I13): the user's [update] ca names, by an absolute path, a file under the directory the session runs in. Fixed by S-F63.

package main

import (
	"cmp"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestC79UpdateCAUnderTheWorkingDirectory (I14, I13): newInstaller refuses a relative ca (C59) but takes an absolute one wherever it lies, so `ca = "<cwd>/certs/corp-ca.pem"` makes the repository's file the installer's only root: a malicious repository ships it, or guest root under --mount rewrites it, and a TLS server holding that certificate (an httptest server on loopback) is trusted for the installer's fetches. A ca whose path passes through cwd must be refused in an error that names ca, before anything is fetched: under cwd, spelled outside cwd as a symbolic link to the file inside it, spelled under cwd as the repository's link to a file outside it (which the repository then chooses), or spelled through a link outside cwd into a folder of the repository whose file is such a link; the same ca outside cwd (the control arm) still works. Precondition the attacker does not control: the operator's [update] table names a file under the repository.
func TestC79UpdateCAUnderTheWorkingDirectory(t *testing.T) {
	for _, arm := range []string{"ca under cwd", "ca outside cwd linked to a file under it", "ca under cwd linked to a file outside it", "ca through a folder link outside cwd into it", "control: ca outside cwd"} { // the ca in the repository; beside the config but a link into the repository; the repository's link to a file beside the config; beside the config, through a link to the repository's folder, whose file is that link out; beside the config for real: the control arm
		t.Run(arm, func(t *testing.T) {
			var hits atomic.Int32 // requests the attacker's upstream served: its self-signed certificate is its own root
			srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer srv.Close()
			cfg, repo := t.TempDir(), must(filepath.EvalSymlinks(t.TempDir()))                                                                                                                                                   // macOS: /var is /private/var
			under, inside, outside := !strings.HasPrefix(arm, "control"), filepath.Join(repo, "certs", "corp-ca.pem"), filepath.Join(cfg, "corp-ca.pem")                                                                         // inside: the file the repository ships; outside: one beside the config
			ca := cmp.Or(map[string]string{"ca under cwd": inside, "ca under cwd linked to a file outside it": inside, "ca through a folder link outside cwd into it": filepath.Join(cfg, "corp", "corp-ca.pem")}[arm], outside) // the path the table names
			file := cmp.Or(map[string]string{"ca under cwd": inside, "ca outside cwd linked to a file under it": inside}[arm], outside)                                                                                          // where the PEM is written
			t.Setenv("XDG_CONFIG_HOME", cfg)
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			must(0, cmp.Or(os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700), os.MkdirAll(filepath.Dir(inside), 0o700), os.Symlink(filepath.Dir(inside), filepath.Join(cfg, "corp")), os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644),
				os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nchannel = \""+srv.URL+"/channel.json\"\nkey = \""+strings.Repeat("00", 32)+"\"\nca = \""+ca+"\"\n"), 0o600)))
			if file != ca { // the link arms: the path the table names resolves to the file, in the folder-link arm by way of the repository's certs/, where the link is made
				must(0, os.Symlink(file, ca))
			}
			t.Chdir(repo)
			in, err := newInstaller()
			if err == nil { // the ca was taken: does the transport built on it trust the server? A HEAD carries no body to close
				_, err = in.client.Head(srv.URL)
			}
			if (err == nil) == under || under && (!strings.Contains(err.Error(), "ca") || hits.Load() > 0) { // the control arm is trusted; an attacking arm is refused in an error naming ca, with nothing fetched
				t.Errorf("I14: ca = %q, under cwd: %t: newInstaller, then a fetch through its transport from the server holding that certificate, gave %v after %d requests served; want refused in an error naming ca with none served: %t", ca, under, err, hits.Load(), under)
			}
		})
	}
}
