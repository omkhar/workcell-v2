// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/guest"
	"golang.org/x/sys/unix"
)

// command is the one process the host asked for, with the init's ends of its terminal or
// pipes. Its status arrives on exited, from the reaper.
type command struct {
	pid    int
	stdin  *os.File    // where host input goes: the PTY master or the stdin pipe
	pty    *os.File    // the PTY master, or nil with pipes
	outs   []*os.File  // what the relays read: the master, or the stdout and stderr pipes
	in     chan []byte // host bytes on their way to stdin
	relays sync.WaitGroup
	exited <-chan unix.WaitStatus
}

// start runs req. Its process group is its own, so a signal from the host reaches all
// of it. The error names what failed: the host reports it in place of an exit status.
func start(req guest.Exec, s *server) (*command, error) {
	c := &command{in: make(chan []byte, 64)}
	attr := &os.ProcAttr{Dir: req.Dir, Env: req.Env, Sys: &syscall.SysProcAttr{}}
	var child []*os.File // the command's fds 0, 1 and 2; closed here once it runs
	if req.PTY {
		master, slave, err := openPTY(req.Rows, req.Cols)
		if err != nil {
			return nil, err
		}
		c.stdin, c.pty, c.outs = master, master, []*os.File{master}
		child = []*os.File{slave, slave, slave}
		attr.Sys = &syscall.SysProcAttr{Setsid: true, Setctty: true} // the slave, fd 0, is its terminal
	} else {
		for i := range 3 {
			r, w, err := os.Pipe()
			if err != nil {
				closeAll(child...)
				c.close()
				return nil, err
			}
			if i == 0 {
				c.stdin, child = w, append(child, r)
			} else {
				c.outs, child = append(c.outs, r), append(child, w)
			}
		}
		attr.Sys.Setpgid = true
	}
	attr.Files = child
	path, err := lookPath(req.Argv[0], req.Env)
	if err == nil {
		s.reap.mu.Lock()
		var p *os.Process
		if p, err = os.StartProcess(path, req.Argv, attr); err == nil {
			c.pid = p.Pid
			_ = p.Release() // the reaper waits for it, not os; this makes p.Pid -1
			s.reap.pid, s.reap.status = c.pid, make(chan unix.WaitStatus, 1)
			c.exited = s.reap.status
		}
		s.reap.mu.Unlock()
	}
	closeAll(child...)
	if err != nil {
		c.close()
		return nil, err
	}
	for i, typ := range []uint8{guest.TypeStdout, guest.TypeStderr}[:len(c.outs)] {
		c.relay(c.outs[i], typ, s)
	}
	c.relays.Go(func() { // the stdin writer: a command that stops reading parks it, not serve
		for b := range c.in {
			if len(b) == 0 && c.pty == nil {
				_ = c.stdin.Close()
				_ = s.send(guest.TypeAck, guest.EncodeAck(0))
				return
			}
			_, _ = c.stdin.Write(b)                            // a command that closed its stdin or died gives EPIPE: not news
			_ = s.send(guest.TypeAck, guest.EncodeAck(len(b))) // the host's window: it may send one frame more
		}
	})
	return c, nil
}

// closeAll closes files; one named twice is closed once.
func closeAll(fs ...*os.File) {
	for _, f := range fs {
		if f != nil {
			_ = f.Close()
		}
	}
}

// lookPath resolves argv[0] the way a shell would, in the PATH the command will see.
func lookPath(name string, env []string) (string, error) {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	_ = os.Setenv("PATH", path) // the init's own environment is otherwise empty
	return exec.LookPath(name)
}

// openPTY returns an unlocked master, non-blocking so that deadlines work on it, and its
// slave, with the window size set so the command sees it from its first instruction.
func openPTY(rows, cols uint16) (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)
	}
	if err == nil {
		err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	}
	if err == nil {
		err = unix.SetNonblock(fd, true)
	}
	sfd := -1
	if err == nil {
		sfd, err = unix.Open("/dev/pts/"+strconv.Itoa(n), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, nil, fmt.Errorf("pty: %w", err)
	}
	return os.NewFile(uintptr(fd), "ptmx"), os.NewFile(uintptr(sfd), "pts"), nil
}

// relay copies what the command writes to the host, one frame per read, until the end
// of the stream or a deadline set by finish.
func (c *command) relay(f *os.File, typ uint8, s *server) {
	c.relays.Go(func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 && s.send(typ, buf[:n]) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	})
}

// input queues host bytes for the command's stdin. An empty payload is the end of its
// stdin, which only a pipe can convey; a terminal needs the host to send the EOF character.
// A host that keeps to guest.StdinWindow never fills the queue. One that ignores the window
// has what arrives past the queue dropped: serve must keep handling frames, so that a
// signal or the host's hang-up still ends things.
func (c *command) input(b []byte) {
	select {
	case c.in <- b:
	default:
	}
}

func (c *command) resize(r guest.Resize) {
	if c.pty == nil {
		return
	}
	rc, err := c.pty.SyscallConn() // not Fd(), which would make the master blocking again
	if err == nil {
		_ = rc.Control(func(fd uintptr) {
			_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: r.Rows, Col: r.Cols})
		})
	}
}

// finish turns the command's status into an Exit once its output has all been relayed.
// What it left behind in its process group is killed: the session ends with its command.
// A stray process that still holds the output open ends the drain after a second.
func (c *command) finish(st unix.WaitStatus) guest.Exit {
	_ = unix.Kill(-c.pid, unix.SIGKILL)
	deadline := time.Now().Add(time.Second)
	for _, f := range c.outs {
		_ = f.SetReadDeadline(deadline)
	}
	_ = c.stdin.SetWriteDeadline(deadline) // unparks the writer if the command stopped reading
	c.close()
	if st.Signaled() {
		return guest.Exit{Signal: int(st.Signal())}
	}
	return guest.Exit{Code: st.ExitStatus()}
}

// close ends the stdin queue, waits for the relays and the writer, and closes the init's ends.
func (c *command) close() {
	close(c.in)
	c.relays.Wait()
	closeAll(append(c.outs, c.stdin)...) // the stdin pipe may be closed already: the host ended it
}
