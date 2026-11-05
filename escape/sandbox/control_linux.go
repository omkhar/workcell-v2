// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// control is the plain container of SPEC T2: new mount, pid, uts and ipc
// namespaces, the host's network namespace kept so that the network is open,
// and the host's root shared, and with no cap on what it logs. A user
// namespace maps the caller to root when the caller is not root already.
// Its channel is a unix socket in the session directory, served by naiveHost
// for each run; the command, pid 1 of its namespace, holds the guest end as
// an inherited descriptor, since a plain container has no init.
// Every escape test must fail here.
type control struct {
	dir       string
	payload   string
	workspace string
	env       []string // what a naive sandbox exports to the guest: the real secret
	helpers   map[string]*exec.Cmd
	ln        *net.UnixListener // the host end of the channel
	relay     *naiveRelay       // the host end of the relay
	resolver  *naiveResolver    // the resolver the guest's resolv.conf names
}

// controlLoader runs as pid 1 of the run's namespaces: $0 is the session's
// resolv.conf, $1 the payload, the rest its arguments.
const controlLoader = `mount --make-rprivate / && mount --bind "$0" /etc/resolv.conf || { echo "control: cannot bind the session's resolv.conf over /etc/resolv.conf" >&2; exit 125; }; exec "$@"`

// helperNames are the session's helpers. Control starts them on first use,
// each a payload that sleeps, and they enforce nothing.
var helperNames = []string{"proxy", "resolver", "broker", "supervisor"}

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
	ln, err := net.Listen("unix", filepath.Join(dir, "channel"))
	if err != nil {
		return "", fmt.Errorf("control: open the channel: %w", err)
	}
	c.ln = ln.(*net.UnixListener)
	rl, err := net.Listen("unix", filepath.Join(dir, "relay"))
	if err != nil {
		return "", fmt.Errorf("control: open the relay: %w", err)
	}
	c.relay = &naiveRelay{ln: rl}
	go c.relay.serve()
	// The guest's resolv.conf names the naive resolver, whether or not it
	// could bind (port 53 needs root): a query then goes there or nowhere,
	// never to the host's own resolver (SPEC T8, S12).
	if c.resolver, err = listenNaiveResolver(naiveResolverAddr); err != nil {
		fmt.Fprintf(os.Stderr, "escape: control: no naive resolver at %s (%v): the guest's lookups will go unanswered\n", naiveResolverAddr, err)
	}
	host, _, _ := net.SplitHostPort(naiveResolverAddr)
	if cfg.Resolver != "" { // the judge's own resolver instead: the guest dials for itself here
		host = cfg.Resolver
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte("nameserver "+host+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("control: write resolv.conf: %w", err)
	}
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
	// The host's root is the guest's: the export is where it lies, live, in
	// either mode. cfg.Mount changes nothing here.
	return cfg.Workspace, c.record("start")
}

// record appends one lifecycle record to the session's log: a plain file, as
// a naive sandbox keeps it, in a directory the guest can reach.
func (c *control) record(line string) error {
	f, err := os.OpenFile(filepath.Join(c.dir, "log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("control: open log: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), line)
	return err
}

func (c *control) Exec(ctx context.Context, args ...string) (Output, error) {
	// The guest end of the channel: one connection, which the command
	// inherits as descriptor 3 and the host end serves.
	guest, err := net.Dial("unix", c.ln.Addr().String())
	if err != nil {
		return Output{}, fmt.Errorf("control: dial the channel: %w", err)
	}
	end, err := guest.(*net.UnixConn).File()
	guest.Close()
	if err != nil {
		return Output{}, fmt.Errorf("control: the channel's guest end: %w", err)
	}
	defer end.Close()
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &bounded{limit: MaxStdout}
	stderr := &bounded{limit: MaxStderr}
	host := &naiveHost{stdout: stdout, stderr: stderr, cancel: cancel}
	host.wg.Go(func() { host.accept(c.ln) })
	// The payload starts behind a loader, as the product's does: in the
	// run's own mount namespace it makes every mount private, so that
	// nothing it mounts shows on the host, and binds the session's
	// resolv.conf over /etc/resolv.conf, then becomes the payload.
	cmd := exec.CommandContext(cctx, "/bin/sh", append([]string{"-c", controlLoader, filepath.Join(c.dir, "resolv.conf"), c.payload}, args...)...)
	cmd.Dir = "/"
	cmd.Env = c.env
	cmd.ExtraFiles = []*os.File{end}
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
	// streams go whole into the log file in the session directory, after the
	// record of the run itself.
	if err := c.record("exec " + strings.Join(args, " ")); err != nil {
		return Output{}, err
	}
	log, err := os.OpenFile(filepath.Join(c.dir, "log"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Output{}, fmt.Errorf("control: open log: %w", err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = io.MultiWriter(stdout, log), io.MultiWriter(stderr, log)
	err = cmd.Run()
	end.Close()
	host.stop(ctx, c.ln) // the host end outlives the command only until its connections close
	out := Output{Stdout: stdout.bytes(), Stderr: stderr.bytes()}
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
	if ctx.Err() != nil {
		return out, fmt.Errorf("control: payload: %w", ctx.Err())
	}
	return host.result(out), nil
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

// Audit reads the log as it lies: every line is a record.
func (c *control) Audit(context.Context) (string, []string, error) {
	path := filepath.Join(c.dir, "log")
	b, err := os.ReadFile(path)
	if err != nil {
		return path, nil, err
	}
	var records []string
	for line := range strings.SplitSeq(strings.TrimSuffix(string(b), "\n"), "\n") {
		records = append(records, line)
	}
	return path, records, nil
}

// Verify is what a naive sandbox has: the log is there and holds something.
func (c *control) Verify(context.Context) error {
	fi, err := os.Stat(filepath.Join(c.dir, "log"))
	if err == nil && fi.Size() == 0 {
		err = errors.New("control: the log is empty")
	}
	return err
}

func (c *control) Helper(_ context.Context, name string) (int, error) {
	if err := c.startHelpers(); err != nil {
		return 0, err
	}
	h, ok := c.helpers[name]
	if !ok {
		return 0, fmt.Errorf("control: no helper %q; want one of %v", name, helperNames)
	}
	return h.Process.Pid, nil
}

func (c *control) Channel(context.Context) (Channel, error) {
	return Channel{Addr: "unix:" + c.ln.Addr().String()}, nil
}

func (c *control) Relay(context.Context) (Channel, error) {
	return Channel{Addr: "unix:" + c.relay.ln.Addr().String()}, nil
}

// startHelpers starts one payload process per helper name, once.
func (c *control) startHelpers() error {
	if c.helpers != nil {
		return nil
	}
	c.helpers = map[string]*exec.Cmd{}
	for _, name := range helperNames {
		h := exec.Command(c.payload, "helper", name)
		if err := h.Start(); err != nil {
			return fmt.Errorf("control: start %s: %w", name, err)
		}
		c.helpers[name] = h
	}
	return nil
}

// Update does what a naive updater does: it reads the manifest's payload
// without checking any signature, serial or expiry, fetches the artifact by
// the URL in it, wherever a redirect sends it, and keeps whatever bytes came,
// however many, with no digest check.
func (c *control) Update(ctx context.Context, u UpdateConfig) ([]byte, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(u.CA)
	// No proxy: the only addresses an update may fetch are the test's own (SPEC S12).
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	get := func(url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body) // a short body is still a body
		return b, nil
	}
	b, err := get(u.Channel)
	if err != nil {
		return nil, fmt.Errorf("control: fetch channel: %w", err)
	}
	var env struct {
		Payload []byte `json:"payload"`
	}
	var m struct {
		Pins map[string]map[string]struct {
			URL string `json:"url"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(b, &env); err == nil {
		err = json.Unmarshal(env.Payload, &m)
	}
	if err != nil {
		return nil, fmt.Errorf("control: decode manifest: %w", err)
	}
	p, ok := m.Pins[u.Name][runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("control: the manifest pins no %s for %s", u.Name, runtime.GOARCH)
	}
	art, err := get(p.URL)
	if err != nil {
		return nil, fmt.Errorf("control: fetch artifact: %w", err)
	}
	return art, os.WriteFile(filepath.Join(c.dir, "installed-"+u.Name), art, 0o755)
}

// Bench: a plain container boots no VM, so there is no start to time. It
// says so as the CLI reports a boot it could not do: one line on stderr and
// exit 1. It never prints a measurement.
func (c *control) Bench(context.Context) (Output, error) {
	return Output{Stderr: []byte("control: a plain container boots no VM\n"), Exit: 1}, nil
}

func (c *control) Stop() error {
	if c.dir == "" {
		return nil
	}
	for _, h := range c.helpers {
		h.Process.Kill()
		h.Wait()
	}
	if c.ln != nil {
		c.ln.Close()
	}
	if c.relay != nil {
		c.relay.stop()
	}
	if c.resolver != nil {
		c.resolver.stop()
	}
	return os.RemoveAll(c.dir)
}
