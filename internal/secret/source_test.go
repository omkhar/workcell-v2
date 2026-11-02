// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package secret

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveRefusesMalformedSources(t *testing.T) {
	for _, source := range []string{
		"", "svc", ":x", "env:HOME", "keychain:", "keychain:svc", "keychain:/acct", "keychain:svc/",
		"file:", "file:relative/path", "cmd:", "cmd:   ", "cmd:echo hi",
		"secret-service:", "secret-service:svc", "secret-service:/acct", "secret-service:svc/",
	} {
		if value, err := Resolve(context.Background(), source); err == nil || value != nil {
			t.Errorf("Resolve(%q) = %v, %v; want a refusal", source, value, err)
		}
	}
}

func TestResolveFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		path string
		want []byte // nil means the source must fail
	}{
		{"value", writeFile(t, "v", []byte("sk-file"), 0o600), []byte("sk-file")},
		{"one trailing newline", writeFile(t, "n", []byte("sk-file\n"), 0o600), []byte("sk-file")},
		{"two trailing newlines", writeFile(t, "nn", []byte("sk-file\n\n"), 0o600), nil},
		{"empty", writeFile(t, "e", nil, 0o600), nil},
		{"newline only", writeFile(t, "nl", []byte("\n"), 0o600), nil},
		{"multi-line", writeFile(t, "m", []byte("a\nb\n"), 0o600), nil},
		{"carriage return", writeFile(t, "cr", []byte("sk-file\r\n"), 0o600), nil},
		{"largest", writeFile(t, "max", bytes.Repeat([]byte("k"), maxFileBytes), 0o600), bytes.Repeat([]byte("k"), maxFileBytes)},
		{"oversized", writeFile(t, "big", bytes.Repeat([]byte("k"), maxFileBytes+1), 0o600), nil},
		{"missing", filepath.Join(dir, "absent"), nil},
		{"directory", dir, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(context.Background(), "file:"+tc.path)
			if tc.want == nil {
				if err == nil || got != nil {
					t.Fatalf("Resolve = %d bytes, %v; want a refusal", len(got), err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("Resolve = %d bytes, %v; want %d bytes", len(got), err, len(tc.want))
			}
		})
	}
}

func TestResolveCmdRunsProgramWithScrubbedEnv(t *testing.T) {
	t.Setenv("WORKCELL_LEAK_CANARY", "leak")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", "/home/someone")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	dir := t.TempDir()
	program := writeFile(t, "fake", []byte(`#!/bin/sh
printf '%s\n' "$@" > "`+dir+`/args"
env > "`+dir+`/env"
printf 'sk-from-cmd\n'
`), 0o700)
	got, err := Resolve(context.Background(), "cmd:"+program+"  show \tworkcell/anthropic")
	if err != nil || !bytes.Equal(got, []byte("sk-from-cmd")) {
		t.Fatalf("Resolve = %d bytes, %v", len(got), err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if !bytes.Equal(args, []byte("show\nworkcell/anthropic\n")) {
		t.Fatalf("argv = %q", args)
	}
	want := map[string]bool{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin": false,
		"LC_ALL=C":                           false,
		"HOME=/home/someone":                 false,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus": false,
		"XDG_RUNTIME_DIR=/run/user/1000":                        false,
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	for _, line := range strings.Split(strings.TrimSpace(string(env)), "\n") {
		if _, ok := want[line]; ok {
			want[line] = true
			continue
		}
		// sh itself may add PWD, SHLVL and _; anything else leaked through.
		if name, _, _ := strings.Cut(line, "="); name != "PWD" && name != "SHLVL" && name != "_" {
			t.Errorf("program saw unexpected environment entry %q", line)
		}
	}
	for entry, seen := range want {
		if !seen {
			t.Errorf("program environment lacks %q", entry)
		}
	}
}

func TestResolveCmdFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"two lines", "printf 'a\\nb\\n'"},
		{"nothing", "true"},
		{"newline only", "printf '\\n'"},
		{"carriage return", "printf 'canary\\r\\n'"},
		{"non-zero exit", "printf 'canary-stdout\\n'; echo 'canary-stderr' >&2; exit 44"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			program := writeFile(t, "fake", []byte("#!/bin/sh\n"+tc.body+"\n"), 0o700)
			got, err := Resolve(context.Background(), "cmd:"+program)
			if err == nil || got != nil {
				t.Fatalf("Resolve = %d bytes, %v; want a refusal", len(got), err)
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatalf("error carries program output: %v", err)
			}
		})
	}
	if _, err := Resolve(context.Background(), "cmd:"+filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing program accepted")
	}
}

func TestResolveCmdStopsAtDeadline(t *testing.T) {
	program := writeFile(t, "slow", []byte("#!/bin/sh\nexec sleep 30\n"), 0o700)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Resolve(ctx, "cmd:"+program); err == nil {
		t.Fatal("slow program accepted")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("Resolve returned after %v", elapsed)
	}
}

func TestResolveSecretServiceFailsClosedWithoutTool(t *testing.T) {
	if _, err := os.Stat(secretToolPath); err == nil {
		t.Skip(secretToolPath + " exists on this host")
	}
	if got, err := Resolve(context.Background(), "secret-service:a/b"); err == nil || got != nil {
		t.Fatalf("Resolve = %d bytes, %v; want a refusal", len(got), err)
	}
}

func TestZeroWipesResolvedValue(t *testing.T) {
	path := writeFile(t, "v", []byte("sk-zero-me\n"), 0o600)
	value, err := Resolve(context.Background(), "file:"+path)
	if err != nil || len(value) != len("sk-zero-me") {
		t.Fatalf("Resolve = %d bytes, %v", len(value), err)
	}
	Zero(value)
	if !bytes.Equal(value, make([]byte, len("sk-zero-me"))) {
		t.Fatalf("Zero left %v", value)
	}
}
