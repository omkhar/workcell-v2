// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: credbroker/cli.go

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// secretToolPath is fixed so a PATH entry cannot stand in for the tool.
const secretToolPath = "/usr/bin/secret-tool"

// securityPath is fixed for the same reason.
const securityPath = "/usr/bin/security"

// programTimeout leaves time to answer an unlock prompt.
const programTimeout = 2 * time.Minute

// maxFileBytes bounds a file: source.
const maxFileBytes = 64 << 10

// Resolve reads the secret named by a [[secret]] source: file:PATH,
// cmd:PROGRAM [ARGS...], secret-service:SERVICE/ACCOUNT or
// keychain:SERVICE/ACCOUNT (macOS login keychain). The value is one
// line without its trailing newline. The caller owns it and wipes it with
// Zero. An error never carries a byte of the value or a program's stderr.
func Resolve(ctx context.Context, source string) ([]byte, error) {
	scheme, rest, _ := strings.Cut(source, ":")
	switch scheme {
	case "file":
		return readFile(rest)
	case "cmd":
		argv := strings.Fields(rest)
		if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
			return nil, errors.New("secret source cmd: needs an absolute program path")
		}
		return run(ctx, argv[0], argv[1:])
	case "secret-service":
		service, account, _ := strings.Cut(rest, "/")
		if service == "" || account == "" {
			return nil, errors.New("secret source must be secret-service:SERVICE/ACCOUNT")
		}
		return run(ctx, secretToolPath, []string{"lookup", "service", service, "account", account})
	case "keychain":
		service, account, _ := strings.Cut(rest, "/")
		if service == "" || account == "" {
			return nil, errors.New("secret source must be keychain:SERVICE/ACCOUNT")
		}
		// -w prints only the password and a newline. One call, no retry.
		return run(ctx, securityPath, []string{"find-generic-password", "-s", service, "-a", account, "-w"})
	}
	return nil, fmt.Errorf("secret source scheme %q is not file, cmd, secret-service or keychain", scheme)
}

// Zero overwrites every byte of b with 0.
func Zero(b []byte) {
	clear(b)
}

func readFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("secret source file: needs an absolute path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secret file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("secret file %q is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("secret file %q: %w", path, err)
	}
	defer f.Close()
	// One buffer from the start, so no partial copy of the value is left behind.
	buf := make([]byte, maxFileBytes+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		Zero(buf)
		return nil, fmt.Errorf("read secret file %q: %w", path, err)
	}
	if n > maxFileBytes {
		Zero(buf)
		return nil, fmt.Errorf("secret file %q is larger than %d bytes", path, maxFileBytes)
	}
	return oneLine(buf[:n], "secret file "+path)
}

// run executes a fixed program with no shell and a scrubbed environment.
func run(ctx context.Context, program string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, programTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	// secret-tool finds the session bus only through the last two.
	for _, name := range []string{"HOME", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"} {
		if v, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+v)
		}
	}
	// A child that keeps stdout open must not outlive the timeout.
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		Zero(out)
		// %v, not %w: an *exec.ExitError carries the program's stderr.
		return nil, fmt.Errorf("secret program %q: %v", program, err)
	}
	return oneLine(out, "secret program "+program)
}

// oneLine trims one trailing newline and refuses an empty or multi-line value.
func oneLine(b []byte, what string) ([]byte, error) {
	value := bytes.TrimSuffix(b, []byte("\n"))
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n") {
		Zero(b)
		return nil, fmt.Errorf("%s gave an empty or multi-line value", what)
	}
	return value, nil
}
