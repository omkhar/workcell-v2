// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// bootArgs come first on the kernel command line; Config.Cmdline follows.
// reboot=k makes a guest reboot end the Firecracker process.
const bootArgs = "console=ttyS0 reboot=k panic=-1 pci=off quiet"

// Machine is one Firecracker microVM, a child process of the supervisor.
type Machine struct {
	cfg     vmm.Config
	mu      sync.Mutex
	lns     []net.Listener // what Listen made; closing one unlinks its socket
	cmd     *exec.Cmd      // nil until Start succeeded
	exited  chan struct{}  // closed once the child is reaped
	exitErr error          // valid after exited is closed
}

var _ vmm.Machine = (*Machine)(nil)

// New prepares a machine and boots nothing.
func New(cfg vmm.Config) *Machine {
	return &Machine{cfg: cfg, exited: make(chan struct{})}
}

func (m *Machine) configPath() string { return filepath.Join(m.cfg.Dir, "firecracker.json") }
func (m *Machine) vsockPath() string  { return filepath.Join(m.cfg.Dir, "vsock") }

// Check opens /dev/kvm for writing and looks at the pinned binary, if the Config names one.
func (m *Machine) Check(context.Context) error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot use KVM: %w (this user needs read and write access to /dev/kvm)", err)
	}
	_ = f.Close()
	if m.cfg.Binary == "" {
		return nil
	}
	if _, err := exec.LookPath(m.cfg.Binary); err != nil { // an absolute path: no search, just the file and its mode
		return fmt.Errorf("firecracker binary: %w", err)
	}
	return nil
}

// Listen binds the unix socket Firecracker dials when the guest connects to port. Closing the
// listener unlinks the socket, so Firecracker then refuses every guest connection to the port.
func (m *Machine) Listen(port uint32) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return nil, errors.New("firecracker: Listen after Start")
	}
	ln, err := net.Listen("unix", m.vsockPath()+"_"+strconv.FormatUint(uint64(port), 10))
	if err != nil {
		return nil, err
	}
	m.lns = append(m.lns, ln)
	return ln, nil
}

// Start writes the config file and execs Firecracker. It returns once the child
// runs; the guest boots on its own from there.
func (m *Machine) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return errors.New("firecracker: already started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.WriteFile(m.configPath(), encode(m.cfg), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(m.cfg.Binary, "--no-api", "--config-file", m.configPath()) // no API server, one config file
	if m.cfg.Console != nil {
		cmd.Stdout, cmd.Stderr = m.cfg.Console, m.cfg.Console
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true} // its own group: a hangup of the supervisor's terminal does not reach it
	started := make(chan error, 1)
	go func() {
		// Pdeathsig fires when the thread that forked the child exits, so that thread
		// stays locked to this goroutine for as long as the child lives (A9).
		runtime.LockOSThread()
		var set unix.CPUSet
		err := unix.SchedGetaffinity(0, &set) // this thread's CPUs: the child inherits the mask, and a start the host cannot bound is refused (I10)
		if err == nil {
			pin(&set, m.cfg.CPUs)
			err = unix.SchedSetaffinity(0, &set)
		}
		if err == nil {
			err = cmd.Start()
		}
		started <- err
		if err != nil {
			return
		}
		m.exitErr = cmd.Wait()
		close(m.exited)
	}()
	if err := <-started; err != nil {
		return fmt.Errorf("start firecracker: %w", err)
	}
	m.cmd = cmd
	return nil
}

// Wait blocks until Firecracker has exited, or ctx ends.
func (m *Machine) Wait(ctx context.Context) error {
	m.mu.Lock()
	started := m.cmd != nil
	m.mu.Unlock()
	if !started {
		return errors.New("firecracker: not started")
	}
	select {
	case <-m.exited:
	case <-ctx.Done():
		return ctx.Err()
	}
	return m.exitErr // an *exec.ExitError: "signal: killed" or "exit status N"
}

// Kill sends SIGKILL to Firecracker if it is still running.
func (m *Machine) Kill() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil {
		return nil
	}
	if err := m.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// Close kills the guest if it still runs, waits for the child to be reaped and
// removes the config file and the sockets under Dir. Nothing else is touched.
func (m *Machine) Close() error {
	err := m.Kill()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		<-m.exited
	}
	for _, ln := range m.lns {
		_ = ln.Close() // unlinks vsock_<port>; an error means it was closed already
	}
	for _, p := range []string{m.configPath(), m.vsockPath()} {
		if e := os.Remove(p); e != nil && !errors.Is(e, fs.ErrNotExist) {
			err = errors.Join(err, e)
		}
	}
	return err
}

// The subset of Firecracker's config file this backend writes. There is never a
// network interface: vsock is the only channel.
type fcConfig struct {
	BootSource bootSource    `json:"boot-source"`
	Drives     []drive       `json:"drives"`
	Machine    machineConfig `json:"machine-config"`
	Vsock      vsockConfig   `json:"vsock"`
}

type bootSource struct {
	Kernel   string `json:"kernel_image_path"`
	Initrd   string `json:"initrd_path,omitempty"`
	BootArgs string `json:"boot_args"`
}

type drive struct {
	ID       string `json:"drive_id"`
	Path     string `json:"path_on_host"`
	Root     bool   `json:"is_root_device"`
	ReadOnly bool   `json:"is_read_only"`
}

type machineConfig struct {
	CPUs   int  `json:"vcpu_count"`
	MemMiB int  `json:"mem_size_mib"`
	SMT    bool `json:"smt"`
}

type vsockConfig struct {
	CID     uint32 `json:"guest_cid"`
	UDSPath string `json:"uds_path"`
}

// pin keeps the first n CPUs of set: Firecracker's vCPU and device threads inherit the mask of the thread that forks it, so the guest costs the host n
// CPUs at most, devices included (I10). Sessions share cores as the scheduler sees fit: the count is the bound, not the placement.
func pin(set *unix.CPUSet, n int) {
	for c := 64*len(set) - 1; c >= 0 && set.Count() > n; c-- { // from the top (64 CPUs a word), until n remain
		set.Clear(c)
	}
}

// encode is the config file for cfg: json.Marshal of strings, integers and booleans, which cannot fail.
func encode(cfg vmm.Config) []byte {
	c := fcConfig{
		BootSource: bootSource{Kernel: cfg.Kernel, Initrd: cfg.Initrd, BootArgs: bootArgs},
		Drives:     []drive{},
		Machine:    machineConfig{CPUs: cfg.CPUs, MemMiB: cfg.MemoryMiB},
		Vsock:      vsockConfig{CID: cfg.CID, UDSPath: filepath.Join(cfg.Dir, "vsock")},
	}
	if cfg.Cmdline != "" {
		c.BootSource.BootArgs += " " + cfg.Cmdline
	}
	if cfg.Image != "" {
		c.Drives = append(c.Drives, drive{ID: "root", Path: cfg.Image, Root: true, ReadOnly: true})
	}
	if cfg.Workspace != "" {
		c.Drives = append(c.Drives, drive{ID: "workspace", Path: cfg.Workspace})
	}
	for _, l := range cfg.Layers {
		c.Drives = append(c.Drives, drive{ID: l.Name, Path: l.Image, ReadOnly: true})
	}
	for _, k := range cfg.Caches { // the drive_id of a layer is a bare agent name, so a cache's is prefixed
		c.Drives = append(c.Drives, drive{ID: "cache-" + k.Name, Path: k.Image, ReadOnly: !k.Writable})
	}
	b, _ := json.Marshal(c)
	return b
}
