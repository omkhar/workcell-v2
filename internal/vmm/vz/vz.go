// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build darwin && arm64 && cgo

package vz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Code-Hex/vz/v3"
	"github.com/omkhar/workcell/v2/internal/vmm"
	"golang.org/x/sys/unix"
)

// entitlement is what a process must carry to start a VM; an ad hoc signature
// with it is enough (ADR-001).
const entitlement = "com.apple.security.virtualization"

// Machine is one Virtualization.framework VM inside the supervisor process.
type Machine struct {
	cfg     vmm.Config
	mu      sync.Mutex
	vm      *vz.VirtualMachine // nil until Start succeeded
	lns     []*listener        // what Listen made; Start binds them to the VM
	console *console
	killed  bool
	exited  chan struct{}          // closed once the VM is stopped
	state   vz.VirtualMachineState // valid after exited is closed
}

var _ vmm.Machine = (*Machine)(nil)

// New prepares a machine and boots nothing.
func New(cfg vmm.Config) *Machine {
	return &Machine{cfg: cfg, exited: make(chan struct{})}
}

// Check proves the hypervisor is there (kern.hv_support) and that this process
// may use it: the framework refuses a configuration from a process without the
// entitlement, which is the error a user meets first. It boots nothing.
func (m *Machine) Check(context.Context) error {
	hv, err := unix.SysctlUint32("kern.hv_support")
	if err != nil || hv != 1 {
		return fmt.Errorf("cannot use Virtualization.framework: kern.hv_support is %d (%v): this Mac cannot start a VM", hv, err)
	}
	if m.cfg.Kernel == "" {
		return nil
	}
	c := &console{}
	defer c.close()
	cfg, err := configure(m.cfg, c)
	if err != nil {
		return err
	}
	_, err = cfg.Validate()
	return entitled(err)
}

// entitled turns the framework's refusal of an unentitled process into one
// clear line; any other error passes through.
func entitled(err error) error {
	if err != nil && strings.Contains(err.Error(), entitlement) {
		return fmt.Errorf("this workcell binary is not signed with the %s entitlement, so it cannot start a VM", entitlement)
	}
	return err
}

// Listen records a port the guest may dial. The framework's listener exists only
// once the VM does, so Start binds it; until then Accept waits.
func (m *Machine) Listen(port uint32) (net.Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vm != nil {
		return nil, errors.New("vz: Listen after Start")
	}
	l := newListener(port)
	m.lns = append(m.lns, l)
	return l, nil
}

// Start validates the configuration, binds the listeners and boots the guest. It
// returns once the VM runs.
func (m *Machine) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vm != nil {
		return errors.New("vz: already started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c := &console{}
	vm, err := m.create(c)
	if err != nil {
		c.close()
		return err
	}
	states := vm.StateChangedNotify()
	if err := vm.Start(); err != nil {
		c.close()
		return fmt.Errorf("start the VM: %w", err)
	}
	c.start(m.cfg.Console)
	go func() {
		for s := range states {
			if s == vz.VirtualMachineStateStopped || s == vz.VirtualMachineStateError {
				m.state = s
				close(m.exited)
				return
			}
		}
	}()
	m.vm, m.console = vm, c
	return nil
}

// create is the VM, validated, with the listeners bound to its socket device.
func (m *Machine) create(c *console) (*vz.VirtualMachine, error) {
	cfg, err := configure(m.cfg, c)
	if err != nil {
		return nil, err
	}
	if _, err := cfg.Validate(); err != nil {
		return nil, entitled(err)
	}
	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		return nil, err
	}
	devs := vm.SocketDevices()
	if len(devs) != 1 {
		return nil, fmt.Errorf("vz: %d socket devices, want 1", len(devs))
	}
	for _, l := range m.lns {
		if err := l.bind(devs[0]); err != nil {
			return nil, err
		}
	}
	return vm, nil
}

// Wait blocks until the VM has stopped, or ctx ends. The framework boots the kernel
// again when the guest restarts, so a stop comes from Kill or from a failure.
func (m *Machine) Wait(ctx context.Context) error {
	m.mu.Lock()
	started := m.vm != nil
	m.mu.Unlock()
	if !started {
		return errors.New("vz: not started")
	}
	select {
	case <-m.exited:
	case <-ctx.Done():
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.killed:
		return errors.New("vz: killed")
	case m.state == vz.VirtualMachineStateError:
		return errors.New("vz: the VM failed")
	}
	return nil
}

// Kill stops the VM now, without a word to the guest.
func (m *Machine) Kill() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vm == nil {
		return nil
	}
	select {
	case <-m.exited:
		return nil
	default:
	}
	err := m.vm.Stop()
	if err == nil {
		m.killed = true
		return nil
	}
	if s := m.vm.State(); s == vz.VirtualMachineStateStopped || s == vz.VirtualMachineStateError {
		return nil // it stopped on its own just now
	}
	return fmt.Errorf("stop the VM: %w", err)
}

// Close kills the guest if it still runs, waits until it is gone, drops what the
// listeners hold and releases the console. The framework's listeners go with the
// VM object. The backend made no file under Dir.
func (m *Machine) Close() error {
	err := m.Kill()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vm != nil {
		<-m.exited
	}
	for _, l := range m.lns {
		l.drop()
	}
	if m.console != nil {
		m.console.close()
	}
	return err
}

// configure is the framework's configuration for cfg, with the console's write
// end attached: a boot loader, one virtio console, one virtio socket device, one
// entropy device and the root image read-only before the workspace, so the guest
// sees them as vda and vdb. There is never a network device.
func configure(cfg vmm.Config, c *console) (*vz.VirtualMachineConfiguration, error) {
	opts := []vz.LinuxBootLoaderOption{vz.WithCommandLine(cmdline(cfg.Cmdline))}
	if cfg.Initrd != "" {
		opts = append(opts, vz.WithInitrd(cfg.Initrd))
	}
	boot, err := vz.NewLinuxBootLoader(cfg.Kernel, opts...)
	if err != nil {
		return nil, err
	}
	vmc, err := vz.NewVirtualMachineConfiguration(boot, uint(cfg.CPUs), uint64(cfg.MemoryMiB)<<20)
	if err != nil {
		return nil, err
	}
	if err := c.open(); err != nil {
		return nil, err
	}
	out, err := vz.NewFileHandleSerialPortAttachment(c.in, c.w)
	if err != nil {
		return nil, err
	}
	serial, err := vz.NewVirtioConsoleDeviceSerialPortConfiguration(out)
	if err != nil {
		return nil, err
	}
	vmc.SetSerialPortsVirtualMachineConfiguration([]*vz.VirtioConsoleDeviceSerialPortConfiguration{serial})
	sock, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	vmc.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{sock})
	rng, err := vz.NewVirtioEntropyDeviceConfiguration() // seeds the guest's CRNG at boot: without it, the first getrandom(2) of a TLS client waited about 6 s (U-701)
	if err != nil {
		return nil, err
	}
	vmc.SetEntropyDevicesVirtualMachineConfiguration([]*vz.VirtioEntropyDeviceConfiguration{rng})
	drives := []drive{{cfg.Image, true}, {cfg.Workspace, false}}
	for _, l := range cfg.Layers {
		drives = append(drives, drive{l.Image, true})
	}
	for _, c := range cfg.Caches {
		drives = append(drives, drive{c.Image, !c.Writable})
	}
	var disks []vz.StorageDeviceConfiguration
	for _, d := range drives {
		if d.path == "" {
			continue
		}
		att, err := vz.NewDiskImageStorageDeviceAttachment(d.path, d.readOnly)
		if err != nil {
			return nil, err
		}
		blk, err := vz.NewVirtioBlockDeviceConfiguration(att)
		if err != nil {
			return nil, err
		}
		disks = append(disks, blk)
	}
	vmc.SetStorageDevicesVirtualMachineConfiguration(disks)
	return vmc, nil
}

// drive is one block device: the file behind it and whether the guest may write it.
type drive struct {
	path     string
	readOnly bool
}

// console is the guest's serial console: the framework writes to w, and start's
// goroutine reads r and passes the bytes on. in is never written, so the guest
// gets no input.
type console struct {
	r, w, in *os.File
	done     chan struct{} // nil until start; closed when the copy has ended
}

func (c *console) open() (err error) {
	if c.r, c.w, err = os.Pipe(); err != nil {
		return err
	}
	c.in, err = os.Open(os.DevNull)
	return err
}

// start copies the console to w, or discards it, until close.
func (c *console) start(w io.Writer) {
	if w == nil {
		w = io.Discard
	}
	c.done = make(chan struct{})
	go func() {
		defer close(c.done)
		_, _ = io.Copy(w, c.r)
	}()
}

// close releases the descriptors. The framework keeps its own copies for as long
// as the VM object lives, so the read end is closed too, which ends the copy.
func (c *console) close() {
	for _, f := range []*os.File{c.w, c.in, c.r} {
		if f != nil {
			_ = f.Close()
		}
	}
	if c.done != nil {
		<-c.done
	}
}

// listener is one host port the guest may dial. Connections arrive from the
// framework on a goroutine of its own and queue here, up to a backlog; once the
// listener is closed, every connection the guest makes is closed at once (I12).
type listener struct {
	port   uint32
	inner  *vz.VirtioSocketListener
	conns  chan net.Conn
	done   chan struct{} // closed by Close, so that Accept wakes
	mu     sync.Mutex
	closed bool
}

const backlog = 16

func newListener(port uint32) *listener {
	return &listener{port: port, conns: make(chan net.Conn, backlog), done: make(chan struct{})}
}

// bind attaches the listener to the VM's socket device and starts taking calls.
func (l *listener) bind(dev *vz.VirtioSocketDevice) error {
	inner, err := dev.Listen(l.port)
	if err != nil {
		return fmt.Errorf("vsock port %d: %w", l.port, err)
	}
	l.inner = inner
	go l.pump()
	return nil
}

// pump takes every connection the framework hands over, so that the framework
// never waits on this process, and queues it or closes it.
func (l *listener) pump() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return // the framework's listener is closed
		}
		l.mu.Lock()
		queued := false
		if !l.closed {
			select {
			case l.conns <- c:
				queued = true
			default: // the backlog is full: refused, as a kernel would
			}
		}
		l.mu.Unlock()
		if !queued {
			_ = c.Close()
		}
	}
}

// Accept takes the next queued connection; once Close ran, the queue is empty for good.
func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close refuses every later connection, drops the queued ones and removes the
// framework's listener once it has one.
func (l *listener) Close() error {
	if l.drop() && l.inner != nil {
		_ = l.inner.Close()
	}
	return nil
}

// drop refuses every later connection and closes the queued ones. It reports
// whether this call was the first.
func (l *listener) drop() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.closed = true
	close(l.done)
	for len(l.conns) > 0 {
		_ = (<-l.conns).Close()
	}
	return true
}

func (l *listener) Addr() net.Addr { return addr(l.port) }

// addr is a host vsock port: the host is CID 2 to the guest.
type addr uint32

func (addr) Network() string  { return "vsock" }
func (a addr) String() string { return "2:" + strconv.FormatUint(uint64(a), 10) }
