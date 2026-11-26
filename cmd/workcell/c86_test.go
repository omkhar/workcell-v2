// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Finding C86 of S-1013, sweep 3 (I6, through it I5): SSL_CERT_FILE, or an entry of SSL_CERT_DIR, names by an absolute path a file under the directory the session runs in. The absolute sibling of C30 and C53.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"cmp"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/omkhar/workcell/v2/internal/proxy"
)

// TestC86SSLCertPathUnderTheWorkingDirectory (I6, I5): upstreamRoots refuses a relative SSL_CERT_FILE or SSL_CERT_DIR entry (C30, C53) but takes an absolute one wherever it lies, so SSL_CERT_FILE=<cwd>/certs/ca.pem makes a file of the repository a root of the proxy's upstream pool: a malicious repository ships it, or guest root under --mount writes it for every later session of the operator (modelled by a host write, as C54 does: no hypervisor here), and a leaf of that CA, from the network attacker as the host resolver's answer for an allowed name, verifies and is sent the real secret (the probe internal/proxy/c86_probe_test.go shows it leaving). The session must be refused before newSession in an error naming the variable, as an [update] ca under cwd is (C79); the same file under a directory outside cwd and the data directory (the control arm) is still accepted. The VMM is a dummy: an admitted session fails at boot, after its directory exists. The admission needs no load of the system pool, so the SSL_CERT_DIR arm runs in this process. Precondition the attacker does not control: the operator's environment names a path under the repository.
func TestC86SSLCertPathUnderTheWorkingDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, env    string
		mount, under bool
	}{{"clone, SSL_CERT_FILE under cwd", "SSL_CERT_FILE", false, true}, {"mount, SSL_CERT_FILE under cwd", "SSL_CERT_FILE", true, true}, {"clone, an SSL_CERT_DIR entry under cwd", "SSL_CERT_DIR", false, true}, {"control: SSL_CERT_FILE outside cwd and the data directory", "SSL_CERT_FILE", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			work, data, config := must(filepath.EvalSymlinks(t.TempDir())), filepath.Join(t.TempDir(), "workcell"), filepath.Join(t.TempDir(), "workcell") // macOS: /var is /private/var
			file := cmp.Or(map[bool]string{true: filepath.Join(work, "certs", "ca.pem")}[tc.under], filepath.Join(t.TempDir(), "corp", "roots.pem"))       // the attacker's file in the repository, or the operator's own authority elsewhere (the control arm)
			t.Setenv("XDG_DATA_HOME", filepath.Dir(data))
			t.Setenv("XDG_CONFIG_HOME", filepath.Dir(config))
			t.Setenv("TMPDIR", t.TempDir()) // --mount refuses a cwd under the temp directory
			t.Setenv(tc.env, cmp.Or(map[string]string{"SSL_CERT_DIR": "/etc/ssl/certs:" + filepath.Dir(file)}[tc.env], file))
			ca := must(proxy.NewSessionCA([]string{"api.example.com"}, time.Now().Add(time.Hour))) // the attacker's authority; it keeps the key
			must(0, cmp.Or(os.MkdirAll(filepath.Dir(file), 0o700), os.MkdirAll(config, 0o700), os.WriteFile(file, ca.CertPEM(), 0o600), os.WriteFile(filepath.Join(config, "config.toml"), []byte("[network]\nallow = [\"api.example.com\"]\n"), 0o600)))
			a := c19Data(t, data, "/elsewhere")
			t.Chdir(work)
			allow, secrets, _, _, err := loadPolicy(nil, io.Discard)
			if err == nil {
				err = session([]string{"true"}, limits{DiskMiB: 16}, tc.mount, a, allow, secrets).err
			}
			ents, _ := os.ReadDir(filepath.Join(data, "sessions"))
			started, refused := len(ents) > 1, err != nil && strings.Contains(err.Error(), tc.env) // started: a session directory beside the earlier session's, so newSession ran
			if started == tc.under || refused != tc.under {
				t.Errorf("I6: %s=%q, under cwd %t, --mount %t: session gave %v, a session directory made: %t; want refused before newSession in an error naming %s: %t", tc.env, os.Getenv(tc.env), tc.under, tc.mount, err, started, tc.env, tc.under)
			}
		})
	}
}
