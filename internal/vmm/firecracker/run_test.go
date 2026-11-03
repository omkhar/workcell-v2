// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRun runs the built `workcell run` as a child, as a user would, against a data
// directory laid out the way `workcell update` will leave it: the pinned Firecracker and
// kernel, an initramfs whose /init is workcell-init, and the Debian image from mkimage.
func TestRun(t *testing.T) {
	needKVM(t)
	binary, kernel := pinned(t)
	tmp := shortDir(t)
	data := filepath.Join(tmp, "workcell")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	build(t, bin, "github.com/omkhar/workcell/v2/cmd/workcell")
	build(t, bin, "github.com/omkhar/workcell/v2/cmd/mkimage")
	initrd := initramfs(t, bin, file{"init", build(t, t.TempDir(), "github.com/omkhar/workcell/v2/cmd/workcell-init")})
	for dst, src := range map[string]string{"firecracker": binary, "vmlinux": kernel, "initrd.cpio": initrd} {
		if err := os.Symlink(src, filepath.Join(data, dst)); err != nil {
			t.Fatal(err)
		}
	}
	mk := exec.Command(filepath.Join(bin, "mkimage"), "-pin", "../../../pins/debian.json", "-arch", "amd64", "-o", filepath.Join(data, "root.ext4"))
	if out, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("mkimage: %v\n%s", err, out)
	}
	workcell := func(stdin *os.File, args ...string) *exec.Cmd {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "workcell"), append([]string{"run", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+tmp, "HOME="+tmp, "TERM=xterm")
		if stdin != nil {
			cmd.Stdin = stdin
		}
		return cmd
	}
	// pipes runs the child with stdin from the reader and returns what it printed and how it ended.
	pipes := func(t *testing.T, stdin *bytes.Reader, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		cmd := workcell(nil, args...)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		err := cmd.Run()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("stderr:\n%s", e.String())
			}
		})
		return o.String(), e.String(), cmd.ProcessState.ExitCode()
	}

	t.Run("exit-code", func(t *testing.T) {
		tests := []struct {
			name string
			args []string
			code int
			err  string // a word in stderr, or ""
		}{
			{"exit 7", []string{"sh", "-c", "exit 7"}, 7, ""},
			{"success", []string{"true"}, 0, ""},
			{"killed by SIGTERM", []string{"sh", "-c", "kill -TERM $$"}, 143, ""},
			{"no such command", []string{"/nope"}, 126, "could not run"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, stderr, code := pipes(t, nil, tc.args...)
				if code != tc.code || !strings.Contains(stderr, tc.err) {
					t.Errorf("exit %d with stderr %q, want exit %d and %q", code, stderr, tc.code, tc.err)
				}
			})
		}
	})

	t.Run("pipes", func(t *testing.T) {
		stdout, stderr, code := pipes(t, nil, "sh", "-c", "echo out; echo err >&2")
		if stdout != "out\n" || stderr != "err\n" || code != 0 {
			t.Errorf("stdout %q, stderr %q, exit %d; want %q, %q, 0", stdout, stderr, code, "out\n", "err\n")
		}
	})

	// 5 MiB is 80 frames of 64 KiB: more than the init queues, to a command that reads late.
	t.Run("stdin-flow-control", func(t *testing.T) {
		const size = 5 << 20
		stdout, _, code := pipes(t, bytes.NewReader(make([]byte, size)), "sh", "-c", "sleep 1; wc -c")
		if want := strconv.Itoa(size) + "\n"; stdout != want || code != 0 {
			t.Errorf("wc -c printed %q with exit %d, want %q", stdout, code, want)
		}
	})

	t.Run("terminal", func(t *testing.T) {
		master, slave := openPTY(t)
		setSize(t, master, 24, 80)
		before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		cmd := workcell(slave, "sh", "-c", "stty size; echo READY; read x; stty size; exit 3")
		cmd.Stdout, cmd.Stderr = slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true} // the slave is its terminal, as in a shell
		out := &screen{}
		go out.copyFrom(master)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("terminal output:\n%q", out.String())
			}
		})
		out.wait(t, "READY")
		if got := out.String(); !strings.Contains(got, "24 80\n") {
			t.Fatalf("stty size before the resize: %q, want 24 80", got)
		}
		setSize(t, master, 40, 100)        // the kernel sends SIGWINCH to workcell
		time.Sleep(500 * time.Millisecond) // the resize and the input travel apart; let the resize arrive first
		if _, err := master.WriteString("go\n"); err != nil {
			t.Fatal(err)
		}
		err = cmd.Wait()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatalf("workcell ended with %v, want exit 3", err)
		}
		if got := out.String(); !strings.Contains(got, "40 100\n") {
			t.Errorf("stty size after the resize: %q, want 40 100", got)
		}
		after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil || *after != *before {
			t.Errorf("the terminal was left changed: %+v, was %+v (%v)", after, before, err)
		}
	})
}

// openPTY is a host pseudo-terminal pair, closed when the test ends.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err == nil {
		err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	if slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	return master, slave
}

func setSize(t *testing.T, master *os.File, rows, cols uint16) {
	t.Helper()
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil {
		t.Fatal(err)
	}
}

// screen collects what a terminal's master end yields, carriage returns dropped.
type screen struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *screen) copyFrom(r *os.File) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		s.mu.Lock()
		s.b.WriteString(strings.ReplaceAll(string(buf[:n]), "\r", ""))
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// wait polls for want for up to 30 s.
func (s *screen) wait(t *testing.T, want string) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if strings.Contains(s.String(), want) {
			return
		}
	}
	t.Fatalf("no %q on the terminal in 30 s; it shows %q", want, s.String())
}
