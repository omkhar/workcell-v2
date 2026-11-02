// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

// control is the plain container of SPEC T2: new mount, pid, uts and ipc
// namespaces, the host's network namespace kept so that the network is open,
// and the host's root shared. A user namespace maps the caller to root when
// the caller is not root already. Every escape test must fail here.
type control struct {
	dir     string
	payload string
}

func newControl() (Sandbox, error) { return &control{}, nil }

func (c *control) Start(_ context.Context, cfg Config) (string, error) {
	dir, err := os.MkdirTemp("", "escape-control-")
	if err != nil {
		return "", err
	}
	c.dir = dir
	c.payload = filepath.Join(dir, "payload")
	b, err := os.ReadFile(cfg.Payload)
	if err == nil {
		err = os.WriteFile(c.payload, b, 0o755)
	}
	if err != nil {
		return "", fmt.Errorf("control: place payload: %w", err)
	}
	return cfg.Workspace, nil // the host's root is the guest's: the export is where it lies
}

func (c *control) Exec(ctx context.Context, args ...string) (Output, error) {
	cmd := exec.CommandContext(ctx, c.payload, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	attr := &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
	}
	if uid := os.Getuid(); uid != 0 {
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	}
	cmd.SysProcAttr = attr
	cmd.WaitDelay = 2 * time.Second // the payload is pid 1 of its namespace: its death takes the rest
	var total atomic.Int64
	stdout := &bounded{limit: MaxStdout, total: &total}
	stderr := &bounded{limit: MaxStderr, total: &total}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	out := Output{Stdout: stdout.buf, Stderr: stderr.buf, Total: total.Load()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		out.Exit = exit.ExitCode()
	case ctx.Err() != nil:
		return out, fmt.Errorf("control: payload: %w", ctx.Err())
	default: // the namespaces could not be created, or the payload could not start
		return out, fmt.Errorf("control: start payload in new namespaces: %w (unprivileged user namespaces may be restricted here)", err)
	}
	return out, nil
}

func (c *control) Stop() error {
	if c.dir == "" {
		return nil
	}
	return os.RemoveAll(c.dir)
}
