// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Candidate C84 of S-1011, sweep 3 (I14, I13): the user's [update] ca names a file under the data directory that a guest writes by design. Fix unit S-F68 first moves this file to cmd/workcell/c84_test.go and removes this folder (S4). It fails until the fix.
package main

import (
	"bytes"
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

// TestC84UpdateCAUnderTheDataDirectory (I14, I13): `workcell explain --cache npm:rw` says the cache persists in <data>/caches/npm.ext4, writable by the guest. A ca naming that image makes a certificate guest root wrote into it (after a newline, in a block among the filesystem's own bytes) the installer's only root, from every working directory, so a TLS server holding it (an httptest server on loopback) is trusted for the channel and artifact fetches. A ca under the data directory must be refused in an error naming ca, before anything is fetched; a ca beside the config, which the guest cannot write (the control arm), still works. Precondition the attacker does not control: the operator's [update] table names a file under the data directory.
func TestC84UpdateCAUnderTheDataDirectory(t *testing.T) {
	for _, arm := range []string{"ca is a rw cache image under the data directory", "control: ca beside the config"} {
		t.Run(arm, func(t *testing.T) {
			var hits atomic.Int32 // requests the attacker's upstream served: its self-signed certificate is its own root
			srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer srv.Close()
			cfg, data, under := t.TempDir(), t.TempDir(), !strings.HasPrefix(arm, "control")
			t.Setenv("XDG_CONFIG_HOME", cfg)
			t.Setenv("XDG_DATA_HOME", data)
			ca, file := filepath.Join(cfg, "corp-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
			if under { // the cache image: the PEM the guest wrote lies in one 4 KiB block among the filesystem's
				ca, file = filepath.Join(data, "workcell", "caches", "npm.ext4"), bytes.Join([][]byte{bytes.Repeat([]byte{0xff}, 4096), []byte("\n"), file, bytes.Repeat([]byte{0xff}, 4096)}, nil)
			}
			must(0, cmp.Or(os.MkdirAll(filepath.Join(cfg, "workcell"), 0o700), os.MkdirAll(filepath.Dir(ca), 0o700), os.WriteFile(ca, file, 0o644), os.WriteFile(filepath.Join(cfg, "workcell", "config.toml"), []byte("[update]\nchannel = \""+srv.URL+"/channel.json\"\nkey = \""+strings.Repeat("00", 32)+"\"\nca = \""+ca+"\"\n"), 0o600)))
			t.Chdir(t.TempDir()) // any working directory: no part of the ca lies in it
			in, err := newInstaller()
			if err == nil { // the ca was taken: does the transport built on it trust the server? A HEAD carries no body to close
				_, err = in.client.Head(srv.URL)
			}
			if (err == nil) == under || under && (!strings.Contains(err.Error(), "ca") || hits.Load() > 0) { // the control arm is trusted; the attacking arm is refused in an error naming ca, with nothing fetched
				t.Errorf("I14: ca = %q, a file the guest writes: %t: newInstaller, then a fetch through its transport from the server holding the certificate in that file, gave %v after %d requests served; want refused in an error naming ca with none served: %t", ca, under, err, hits.Load(), under)
			}
		})
	}
}
