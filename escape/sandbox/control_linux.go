// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

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
	"syscall"
	"time"
)

// control is the plain container of SPEC T2: new mount, pid, uts and ipc
// namespaces, the host's network namespace kept so that the network is open,
// and the host's root shared, and with no cap on what it logs. A user
// namespace maps the caller to root when the caller is not root already.
// Every escape test must fail here.
type control struct {
	dir       string
	payload   string
	workspace string
	env       []string // what a naive sandbox exports to the guest: the real secret
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
	c.env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	c.workspace = cfg.Workspace
	if sec := cfg.Secret; sec != nil {
		// The naive way: the real value in the environment, and in a dotenv
		// file in the workspace for tools that read one.
		c.env = append(c.env, sec.Env+"="+sec.Value)
		if cfg.Workspace != "" {
			if err := os.WriteFile(filepath.Join(cfg.Workspace, ".env"), []byte(sec.Env+"="+sec.Value+"\n"), 0o600); err != nil {
				return "", fmt.Errorf("control: stage secret: %w", err)
			}
		}
	}
	return cfg.Workspace, nil // the host's root is the guest's: the export is where it lies
}

func (c *control) Exec(ctx context.Context, args ...string) (Output, error) {
	cmd := exec.CommandContext(ctx, c.payload, args...)
	cmd.Dir = "/"
	cmd.Env = c.env
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
	// A plain container logs everything the guest says, without a cap: both
	// streams go whole into a log file in the session directory.
	log, err := os.OpenFile(filepath.Join(c.dir, "log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return Output{}, fmt.Errorf("control: open log: %w", err)
	}
	defer log.Close()
	stdout := &bounded{limit: MaxStdout}
	stderr := &bounded{limit: MaxStderr}
	cmd.Stdout, cmd.Stderr = io.MultiWriter(stdout, log), io.MultiWriter(stderr, log)
	err = cmd.Run()
	out := Output{Stdout: stdout.buf, Stderr: stderr.buf}
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

// Pull does what a naive sandbox does: it snapshots the guest's work with git,
// in the guest's own repository and under the guest's own configuration, so
// that every hook, filter and attribute runs on the host and every submodule
// URL is fetched; then it writes the snapshot's tree under dest path by path,
// as the tree names them, through whatever a name resolves to.
func (c *control) Pull(ctx context.Context, dest string) error {
	git, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("control: pull needs git on the host: %w", ErrNotImplemented)
	}
	if c.workspace == "" {
		return errors.New("control: the session has no workspace to pull")
	}
	run := func(args ...string) ([]byte, error) {
		// No proxy: the only addresses a pull may fetch are the test's own (SPEC S12).
		cmd := exec.CommandContext(ctx, git, append([]string{"-C", c.workspace, "-c", "http.proxy="}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
			"GIT_AUTHOR_NAME=workcell", "GIT_AUTHOR_EMAIL=workcell@localhost", "GIT_COMMITTER_NAME=workcell", "GIT_COMMITTER_EMAIL=workcell@localhost")
		return cmd.Output()
	}
	run("add", "-A")
	run("commit", "-q", "-m", "workcell pull") // nothing to commit is fine
	run("submodule", "update", "--init", "--recursive")
	tree, err := run("ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		return fmt.Errorf("control: list the guest's tree: %w", err)
	}
	for entry := range bytes.SplitSeq(bytes.TrimSuffix(tree, []byte{0}), []byte{0}) {
		meta, name, ok := bytes.Cut(entry, []byte{'\t'})
		f := strings.Fields(string(meta))
		if !ok || len(f) != 3 || f[1] == "commit" {
			continue // a submodule's content stays where submodule update put it
		}
		b, err := run("cat-file", "blob", f[2])
		if err != nil {
			return fmt.Errorf("control: read %s: %w", name, err)
		}
		p := filepath.Join(dest, string(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if f[0] == "120000" {
			err = os.Symlink(string(b), p)
		} else {
			err = os.WriteFile(p, b, 0o755)
		}
		if err != nil {
			return fmt.Errorf("control: write %s: %w", name, err)
		}
	}
	return nil
}

func (c *control) Stop() error {
	if c.dir == "" {
		return nil
	}
	return os.RemoveAll(c.dir)
}
