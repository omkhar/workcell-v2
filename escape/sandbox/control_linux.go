// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package sandbox

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// control is the plain container of SPEC T2: new mount, pid, uts and ipc namespaces, the host's network and root shared, no cap on what it logs. Its channel is
// a unix socket served by naiveHost for each run; the command, pid 1 of its namespace, holds the guest end as descriptor 3. Every escape test must fail here.
type control struct {
	dir       string
	payload   string
	workspace string
	env       []string // what a naive sandbox exports to the guest: the real secret
	command   string   // the provider a run starts by name, instead of the payload (Config.Command)
	head      bool     // the operator's stdout goes away after its first read (Config.Head)
	helpers   map[string]*exec.Cmd
	ln        *net.UnixListener // the host end of the channel
	relay     *naiveRelay       // the host end of the relay
	resolver  *naiveResolver    // the resolver the guest's resolv.conf names
	update    *UpdateConfig     // the channel a naive start installs from, every start
}

// controlLoader runs as pid 1 of the run's namespaces: $0 the session's resolv.conf, $1 the command, then its arguments.
const controlLoader = `mount --make-rprivate / && mount --bind "$0" /etc/resolv.conf || { echo "control: cannot bind the session's resolv.conf over /etc/resolv.conf" >&2; exit 125; }; exec "$@"`

// helperNames are the session's helpers: each a payload that sleeps, started on first use.
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
	c.env = []string{"PATH=" + filepath.Join(prefix, "bin") + ":/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	c.workspace, c.update, c.command, c.head = cfg.Workspace, cfg.Update, cfg.Command, cfg.Head
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
	// The guest's resolv.conf names the naive resolver whether or not it could bind: a query goes there or nowhere, never to the host's own (T8, S12).
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
	if sec := cfg.Secret; sec != nil && sec.Value != "" {
		// The naive way: the real value in the environment and in a dotenv file in the workspace.
		c.env = append(c.env, sec.Env+"="+sec.Value)
		if cfg.Workspace != "" {
			if err := os.WriteFile(filepath.Join(cfg.Workspace, ".env"), []byte(sec.Env+"="+sec.Value+"\n"), 0o600); err != nil {
				return "", fmt.Errorf("control: stage secret: %w", err)
			}
		}
	}
	// The host's root is the guest's: the export is where it lies, live, in either mode.
	return cfg.Workspace, c.record("start")
}

// record appends one lifecycle record to the session's log, a plain file the guest can reach.
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
	if c.update != nil { // a naive daily check: every start, from whatever the channel says
		c.Update(ctx, *c.update)
	}
	// The guest end of the channel: one connection the command inherits as descriptor 3.
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
	// The loader makes every mount private in the run's own mount namespace, binds the session's resolv.conf over /etc/resolv.conf, then becomes the payload,
	// or the command the session runs by name from the prefix's PATH.
	cmd := exec.CommandContext(cctx, "/bin/sh", append([]string{"-c", controlLoader, filepath.Join(c.dir, "resolv.conf"), cmp.Or(c.command, c.payload)}, args...)...)
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
	// A plain container logs everything the guest says, without a cap, after the record of the run itself.
	if err := c.record("exec " + strings.Join(args, " ")); err != nil {
		return Output{}, err
	}
	log, err := os.OpenFile(filepath.Join(c.dir, "log"), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Output{}, fmt.Errorf("control: open log: %w", err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = io.MultiWriter(stdout, log), io.MultiWriter(stderr, log)
	finish := func() {}
	if c.head { // the naive way: the command's own stdout is the operator's pipe
		w, fin, err := headPipe(stdout)
		if err != nil {
			return Output{}, err
		}
		cmd.Stdout, finish = w, fin
	}
	err = cmd.Run()
	finish()
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
	if c.command != "" && host.couldNotRun() { // a naive self-rollback (B9): the guest's word sets the layer aside
		os.Remove(filepath.Join(prefix, "bin", c.command))
	}
	return host.result(out), nil
}

// Pull does what a naive sandbox does: git in the guest's own repository and configuration, so every hook, filter, attribute and submodule URL is obeyed, then
// the tree written under dest through whatever a name resolves to.
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
	return path, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n"), nil
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

// Bind is in the host's one network: a plain container has no other.
func (c *control) Bind(_ context.Context, network, addr string) (net.Listener, net.PacketConn, error) {
	return bindHere(network, addr)
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
		h.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // in a group of its own, as the product's session is
		if err := h.Start(); err != nil {
			return fmt.Errorf("control: start %s: %w", name, err)
		}
		c.helpers[name] = h
	}
	return nil
}

// Update does what a naive updater does: no signature, serial, expiry or digest check, the artifact fetched by the manifest's URL wherever a redirect sends it.
func (c *control) Update(_ context.Context, u UpdateConfig) ([]byte, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(u.CA)
	// No proxy: the only addresses an update may fetch are the test's own (SPEC S12).
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	get := func(url string) ([]byte, error) {
		resp, err := client.Get(url)
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

func (c *control) Installed(_ context.Context, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, "installed-"+name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Install unpacks the artifact into the writable prefix every session's PATH starts with, and keeps no image; a bare executable, or a tar whose root holds one
// regular file and no bin/, is bin/<agent>.
func (c *control) Install(ctx context.Context, l Layer) (string, error) {
	if l.Artifact == nil { // a real pin: fetched as it is, digest checked
		var err error
		if l.Artifact, err = fetch(ctx, l.URL, l.Digest); err != nil {
			return "", err
		}
	}
	put := func(name string, mode os.FileMode, b []byte) error {
		p := filepath.Join(prefix, name)
		return errors.Join(os.MkdirAll(filepath.Dir(p), 0o755), os.WriteFile(p, b, mode))
	}
	var files []*tar.Header
	var bodies [][]byte
	err := untar(l.Artifact, func(h *tar.Header, r io.Reader) error {
		b, err := io.ReadAll(r)
		if h.Typeflag != tar.TypeDir {
			files, bodies = append(files, h), append(bodies, b)
		}
		return err
	})
	if err != nil { // no tar at all: a bare executable
		return "", put("bin/"+l.Agent, 0o755, l.Artifact)
	}
	for i, h := range files {
		name := h.Name
		if len(files) == 1 && !strings.HasPrefix(name, "bin/") {
			name = "bin/" + l.Agent
		}
		if err := put(name, os.FileMode(h.Mode), bodies[i]); err != nil {
			return "", err
		}
	}
	return "", nil
}

// Bench: a plain container boots no VM, so it reports as the CLI does a boot it could not do.
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
