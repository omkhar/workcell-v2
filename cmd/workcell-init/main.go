// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

// Command workcell-init is PID 1 of the guest (A6): one static binary and no shell (A8). It
// mounts the pseudo filesystems, dials the host over vsock and runs the commands the host
// asks for, one at a time, with a PTY or with pipes, relaying bytes and signals and
// reporting how each ended. It reaps every child, its own and the orphans the kernel hands
// to PID 1. When the host hangs up, for whatever reason, it kills everything, syncs and
// powers the guest off. It is a convenience for the host, never a control: nothing in the
// guest is trusted (A1), and the host ends the VM from outside when this does not (ADR-001).
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"github.com/omkhar/workcell/v2/internal/wire"
	"golang.org/x/sys/unix"
)

// frameLimit is how long one frame may take to arrive or to be taken by the host. The host
// is trusted; this only keeps the init from waiting forever on a host that is half gone.
const frameLimit = time.Minute

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "workcell-init: must run as PID 1 of a guest")
		os.Exit(1)
	}
	err := setup()
	if err == nil {
		err = serve()
	}
	fmt.Fprintln(os.Stderr, "workcell-init:", err)
	halt()
}

// setup mounts what commands expect. A mount that is there already is fine. When the host
// put root= on the kernel command line, the image it names becomes the root, and a failure
// to make it so is fatal: the console then says why. Without root= the initramfs stays the
// root.
func setup() error {
	for _, d := range []string{"/dev", "/proc", "/sys"} {
		_ = os.MkdirAll(d, 0o755)
	}
	mount("devtmpfs", "/dev", "devtmpfs", "")
	if fd, err := unix.Open("/dev/console", unix.O_RDWR|unix.O_NOCTTY, 0); err == nil {
		_ = unix.Dup3(fd, 1, 0)
		_ = unix.Dup3(fd, 2, 0)
		_ = unix.Close(fd)
	}
	_ = os.MkdirAll("/dev/pts", 0o755)
	mount("devpts", "/dev/pts", "devpts", "mode=0620,ptmxmode=0666")
	mount("proc", "/proc", "proc", "")
	mount("sysfs", "/sys", "sysfs", "")
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	disk := diskMiB(string(cmdline))
	if dev := rootDevice(string(cmdline)); dev != "" {
		if err := switchRoot(dev, disk); err != nil {
			return err
		}
	}
	_ = os.MkdirAll("/tmp", 0o755)
	mount("tmpfs", "/tmp", "tmpfs", tmpfsSize(disk))
	return nil
}

func mount(src, dir, fs, data string) {
	if err := unix.Mount(src, dir, fs, 0, data); err != nil && !errors.Is(err, unix.EBUSY) {
		fmt.Fprintln(os.Stderr, "workcell-init: mount", dir, err)
	}
}

// connect dials the host (CID 2). The device may still be probing when the guest starts,
// so it retries for 5 s. The socket is non-blocking so that wire's deadlines work on it.
func connect() (*os.File, error) {
	var err error
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		var fd int
		if fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
			continue
		}
		if err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: guest.Port}); err == nil {
			if err = unix.SetNonblock(fd, true); err == nil {
				return os.NewFile(uintptr(fd), "vsock"), nil
			}
		}
		_ = unix.Close(fd)
	}
	return nil, fmt.Errorf("vsock connect: %w", err)
}

// server is the one connection to the host. Output goroutines and the main loop share the
// writer; the reader is one goroutine that halts the guest when the host goes away.
type server struct {
	conn *wire.Conn
	wmu  sync.Mutex
	reap *reaper
}

func (s *server) send(typ uint8, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.conn.WriteFrame(wire.Frame{Type: typ, Payload: payload})
}

// serve runs the host's commands until the host does something a host never does.
func serve() error {
	r := newReaper()
	f, err := connect()
	if err != nil {
		return err
	}
	s := &server{conn: wire.New(f, frameLimit), reap: r}
	frames := make(chan wire.Frame)
	go func() {
		for {
			fr, err := s.conn.ReadFrame()
			if err != nil { // EOF or anything else: the session is over
				fmt.Fprintln(os.Stderr, "workcell-init: host:", err)
				halt()
			}
			frames <- fr
		}
	}()
	var cmd *command
	for {
		var exited <-chan unix.WaitStatus // nil, so never ready, between commands
		if cmd != nil {
			exited = cmd.exited
		}
		select {
		case st := <-exited:
			if err := s.send(guest.TypeExit, guest.EncodeExit(cmd.finish(st))); err != nil {
				return err
			}
			cmd = nil
		case fr := <-frames:
			switch fr.Type {
			case guest.TypeExec:
				if cmd != nil {
					return errors.New("the host asked for a command while one runs")
				}
				req, err := guest.DecodeExec(fr.Payload)
				if err != nil {
					return err
				}
				if cmd, err = start(req, s); err != nil {
					if err := s.send(guest.TypeExit, guest.EncodeExit(guest.Exit{Err: err.Error()})); err != nil {
						return err
					}
				}
			case guest.TypeStdin:
				if cmd != nil {
					cmd.input(fr.Payload)
				}
			case guest.TypeResize:
				if r, err := guest.DecodeResize(fr.Payload); err != nil {
					return err
				} else if cmd != nil {
					cmd.resize(r)
				}
			case guest.TypeSignal:
				if sig, err := guest.DecodeSignal(fr.Payload); err != nil {
					return err
				} else if cmd != nil {
					_ = unix.Kill(-cmd.pid, unix.Signal(sig))
				}
			default:
				return fmt.Errorf("frame type %d from the host", fr.Type)
			}
		}
	}
}

// reaper collects every child that ends. The kernel hands orphans to PID 1, so wait4(-1)
// must run for all of them, and the status of the one command the init started is passed
// on by pid. The lock is held from fork to registration, so no status is collected before
// it has an owner.
type reaper struct {
	mu     sync.Mutex
	pid    int                  // the command that runs, or 0
	status chan unix.WaitStatus // its status, once
}

func newReaper() *reaper {
	r := &reaper{}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGCHLD)
	go func() {
		for range sig {
			r.collect()
		}
	}()
	return r
}

func (r *reaper) collect() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err != nil || pid <= 0 {
			return
		}
		if pid == r.pid {
			r.pid = 0
			r.status <- ws
		}
	}
}

// halt ends the guest: every other process dies, the disks are synced and the machine
// restarts, which with reboot=k on the command line ends the VMM. POWER_OFF is not used:
// on a kernel without an ACPI power-off handler it halts the CPUs without exiting, so the
// VMM would live until the host's deadline. The host does not depend on any of this (A1):
// its deadline and Kill end the VM from outside.
func halt() {
	_ = unix.Kill(-1, unix.SIGKILL)
	for {
		if _, err := unix.Wait4(-1, nil, 0, nil); err != nil {
			break
		}
	}
	unix.Sync()
	for {
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
		time.Sleep(time.Second)
	}
}
