// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Candidate C93 of S-1009 sweep 4 (I13; I5, I14, I6 by consequence): holds() judges a pull destination against the
// data directory, the config directory and the file config.toml resolves to, and knows nothing of the other paths the
// host later runs, opens or trusts from the user's config and environment: the program of a cmd: source, the file of
// a file: source, the [update] ca, SSL_CERT_FILE and the entries of SSL_CERT_DIR. So `workcell pull <home>/tools/bin`
// is admitted, the guest's getkey replaces the operator's, and the broker runs it on the host at the next session in
// any other directory, where loadPolicy judges cwd alone. Fails until the fix lands.
// Written by the redteam of S-1009 and recorded under C93 in loop/state/FINDINGS.md; re-created here by the fix unit
// S-F79, and lives in the suite from that unit on.

//go:build linux || (darwin && arm64 && cgo)

package main

import (
	"cmp"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/secret"
)

// TestC93PullDestinationHoldsATrustedPath: a user config.toml whose cmd: program, file: secret and [update] ca lie
// under the home directory, and an environment that names roots there. Each destination is judged as pull judges it.
// On the main arm the pull's writer then lands one executable entry getkey, the policy is loaded in another directory
// and the row's source is resolved as the broker resolves it; the arm fails when the guest's program ran on the host,
// whatever a fix does to prevent it. Controls: a destination that holds none of the paths is admitted, and the policy
// loaded in the program's own directory is refused, as today.
func TestC93PullDestinationHoldsATrustedPath(t *testing.T) {
	home := must(filepath.EvalSymlinks(t.TempDir())) // macOS: /var is /private/var
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("TMPDIR", t.TempDir())
	tools, keys, certs := filepath.Join(home, "tools", "bin"), filepath.Join(home, "keys"), filepath.Join(home, "certs")
	roots, proj := filepath.Join(home, "roots"), filepath.Join(home, "proj")
	cfg, marker := filepath.Join(home, ".config", "workcell"), filepath.Join(t.TempDir(), "C93-RAN-ON-THE-HOST")
	program, key, ca := filepath.Join(tools, "getkey"), filepath.Join(keys, "anthropic"), filepath.Join(certs, "ca.pem")
	for _, d := range []string{tools, keys, certs, roots, proj, cfg} {
		must(0, os.MkdirAll(d, 0o700))
	}
	config := "[network]\nallow = [\"api.anthropic.com\", \"api.openai.com\"]\n\n[[secret]]\nname = \"anthropic\"\n" +
		"source = \"cmd:" + program + "\"\n\n[[secret]]\nname = \"openai\"\nsource = \"file:" + key + "\"\n\n" +
		"[update]\nca = \"" + ca + "\"\n"
	must(0, cmp.Or(os.WriteFile(program, []byte("#!/bin/sh\necho honest-key\n"), 0o700), os.WriteFile(ca, nil, 0o600),
		os.WriteFile(key, []byte("honest\n"), 0o600), os.WriteFile(filepath.Join(cfg, "config.toml"), []byte(config), 0o600)))
	for _, tc := range []struct{ name, dest, env, val string }{
		{"the cmd: program", filepath.Dir(tools), "", ""}, {"the file: secret", keys, "", ""},
		{"the [update] ca", certs, "", ""},
		{"SSL_CERT_FILE", roots, "SSL_CERT_FILE", filepath.Join(roots, "roots.pem")},
		{"an SSL_CERT_DIR entry", roots, "SSL_CERT_DIR", "/etc/ssl/certs:" + roots},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv(tc.env, tc.val)
			}
			if err := holds(tc.dest); err == nil {
				t.Errorf("I13: the pull destination %s is admitted, and it holds %s", tc.dest, tc.name)
			}
		})
	}
	if err := holds(proj); err != nil {
		t.Errorf("control: the pull destination %s, which holds none of the paths, was refused: %v", proj, err)
	}
	t.Chdir(tools)
	if _, _, _, _, err := loadPolicy(nil, io.Discard); err == nil {
		t.Error("control: the policy loaded in the cmd: program's own directory was admitted")
	}
	if err := holds(tools); err != nil {
		return // the pull is refused: the invariant holds
	}
	script := "#!/bin/sh\necho ran > " + marker + "\necho C93-TOKEN\n" // the guest's getkey, pulled over the operator's
	entries := []guest.Entry{fileEntry("getkey", int64(len(script)), true)}
	must(0, write(openDir(t, tools), judged(t, entries), from([]byte(script))))
	t.Chdir(proj) // the operator's next session, in any other directory
	_, secrets, _, _, err := loadPolicy(nil, io.Discard)
	row := append(secrets, binding{})[0].grant
	v, runErr := secret.Resolve(t.Context(), row.Source) // what the broker runs at the first request on that host
	if exists(marker) {
		t.Errorf("I13, I5: pull into %s was admitted, the guest's getkey replaced the operator's, and a session in %s "+
			"loaded the row (%v) and ran it on the host: %+v gave %q, %v", tools, proj, err, row, v, runErr)
	}
}
