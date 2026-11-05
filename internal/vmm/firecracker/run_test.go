// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
	initrd := initramfs(t, bin, file{"init", build(t, t.TempDir(), "github.com/omkhar/workcell/v2/cmd/workcell-init")})
	for dst, src := range map[string]string{"firecracker": binary, "vmlinux": kernel, "initrd.cpio": initrd, "root.ext4": debianImage(t, bin)} {
		if err := os.Symlink(src, filepath.Join(data, dst)); err != nil {
			t.Fatal(err)
		}
	}
	var flags []string  // flags of `workcell run`, before the --
	repo := t.TempDir() // the directory `workcell run` starts in, and copies into the guest
	sessions := filepath.Join(tmp, "s")
	if err := os.Mkdir(sessions, 0o755); err != nil {
		t.Fatal(err)
	}
	verb := func(dir string, stdin *os.File, args ...string) *exec.Cmd {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // a cold Go build is the longest run
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "workcell"), args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+tmp, "HOME="+tmp, "TERM=xterm", "TMPDIR="+sessions)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		return cmd
	}
	workcell := func(dir string, stdin *os.File, args ...string) *exec.Cmd {
		return verb(dir, stdin, append(append([]string{"run"}, append(flags, "--")...), args...)...)
	}
	// pipesIn runs the child in dir with stdin from the reader and returns what it printed and how it ended.
	pipesIn := func(t *testing.T, dir string, stdin *bytes.Reader, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		cmd := workcell(dir, nil, args...)
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
	pipes := func(t *testing.T, stdin *bytes.Reader, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		return pipesIn(t, repo, stdin, args...)
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

	// The caps of I10 as the guest sees them: one vCPU, at most 256 MiB of RAM, and ENOSPC
	// at 64 MiB of writes to the root while less than that succeeds.
	t.Run("resource-caps", func(t *testing.T) {
		flags = []string{"--cpus", "1", "--memory", "256MiB", "--disk", "64MiB"}
		t.Cleanup(func() { flags = nil })
		const script = `nproc
sed -n 's/^MemTotal: *\([0-9]*\) kB/\1/p' /proc/meminfo
dd if=/dev/zero of=/var/tmp/a bs=1M count=32 2>/dev/null && echo small-ok
rm -f /var/tmp/a
dd if=/dev/zero of=/var/tmp/b bs=1M count=80 2>&1 | grep -o 'No space left on device'`
		stdout, _, _ := pipes(t, nil, "sh", "-c", script)
		got := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(got) != 4 {
			t.Fatalf("the guest printed %q, want 4 lines", stdout)
		}
		if got[0] != "1" {
			t.Errorf("nproc is %q, want 1", got[0])
		}
		if kb, err := strconv.Atoi(got[1]); err != nil || kb > 256<<10 {
			t.Errorf("MemTotal is %q kB, want at most %d", got[1], 256<<10)
		}
		if got[2] != "small-ok" {
			t.Errorf("a 32 MiB write: %q, want small-ok", got[2])
		}
		if got[3] != "No space left on device" {
			t.Errorf("an 80 MiB write: %q, want ENOSPC", got[3])
		}
	})

	// Clone mode: the guest starts in a copy of the directory, what it writes there stays
	// there (I1), and once the session ends the VMM's files are gone while the copy stays
	// as a session, with the directory it came from on record, for diff and pull.
	t.Run("workspace", func(t *testing.T) {
		own := t.TempDir() // this case's own repository; repo, which other cases use, is never reassigned
		if err := os.WriteFile(filepath.Join(own, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(data, "sessions")
		before, _ := os.ReadDir(kept) // other cases leave their own sessions
		stdout, _, code := pipesIn(t, own, nil, "sh", "-c", "cat hello.txt; pwd; echo new > created.txt; cat created.txt")
		if want := "hi\n/workspace\nnew\n"; stdout != want || code != 0 {
			t.Errorf("the guest printed %q with exit %d, want %q and 0", stdout, code, want)
		}
		if _, err := os.Stat(filepath.Join(own, "created.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a file the guest wrote is on the host: %v", err)
		}
		if left, err := os.ReadDir(sessions); err != nil || len(left) != 0 {
			t.Errorf("left in %s after the session: %v (%v), want nothing", sessions, left, err)
		}
		after, err := os.ReadDir(kept)
		if err != nil || len(after) != len(before)+1 {
			t.Fatalf("%s holds %d entries after the session (%v), want %d: one more than before", kept, len(after), err, len(before)+1)
		}
		session := filepath.Join(kept, after[len(after)-1].Name()) // the names sort by time
		if _, err := os.Stat(filepath.Join(session, "workspace.ext4")); err != nil {
			t.Errorf("the session's image: %v", err)
		}
		if b, err := os.ReadFile(filepath.Join(session, "repo")); err != nil || strings.TrimSpace(string(b)) != own {
			t.Errorf("the session's repo file holds %q (%v), want %q", b, err, own)
		}
	})

	// The image bounds what the guest writes to /workspace: --disk of room, then ENOSPC (I10).
	t.Run("workspace-cap", func(t *testing.T) {
		flags = []string{"--disk", "64MiB"}
		t.Cleanup(func() { flags = nil })
		stdout, _, _ := pipes(t, nil, "sh", "-c", "dd if=/dev/zero of=/workspace/big bs=1M count=100 2>&1 | grep -o 'No space left on device'")
		if strings.TrimSpace(stdout) != "No space left on device" {
			t.Errorf("a 100 MiB write to /workspace with --disk 64MiB: %q, want ENOSPC", stdout)
		}
	})

	// A dependency cache (U-504). The runner's own Go toolchain goes into the guest in the export, the
	// guest image having none. The first session builds into go:rw, a cold build that compiles the
	// standard library; the next two read go and compile nothing, as `go build -x` shows, which
	// prints no compile command for a package it takes from the cache. What the second session
	// writes to its read-only cache is gone for the third, and the image is what it was (I7).
	t.Run("dependency-cache", func(t *testing.T) {
		goroot := runtime.GOROOT()
		if _, err := os.Stat(filepath.Join(goroot, "bin", "go")); err != nil {
			t.Skipf("no Go toolchain at %s to take into the guest", goroot)
		}
		own := t.TempDir()
		for _, name := range []string{"bin", "pkg/tool", "pkg/include", "src"} {
			if _, err := os.Stat(filepath.Join(goroot, name)); err == nil {
				if err := os.CopyFS(filepath.Join(own, "go", name), os.DirFS(filepath.Join(goroot, name))); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, name := range []string{"VERSION", "go.env"} {
			if b, err := os.ReadFile(filepath.Join(goroot, name)); err == nil {
				if err := os.WriteFile(filepath.Join(own, "go", name), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		hello := map[string]string{
			"go.mod":  "module hello\n\ngo " + strings.TrimPrefix(runtime.Version(), "go") + "\n",
			"main.go": "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hello\") }\n",
		}
		if err := os.Mkdir(filepath.Join(own, "hello"), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range hello {
			if err := os.WriteFile(filepath.Join(own, "hello", name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		const build = `cd hello && out=$(GOTOOLCHAIN=local GOPROXY=off CGO_ENABLED=0 ../go/bin/go build -x -o /tmp/h . 2>&1); rc=$?
echo exit=$rc; echo compiles=$(printf '%s\n' "$out" | grep -c '/compile '); [ $rc = 0 ] || printf '%s\n' "$out"; `
		image := filepath.Join(data, "caches", "go.ext4")
		sum := func() string {
			f, err := os.Open(image)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				t.Fatal(err)
			}
			return string(h.Sum(nil))
		}
		t.Cleanup(func() { flags = nil })

		flags = []string{"--memory", "2GiB", "--cache", "go:rw"}
		stdout, _, _ := pipesIn(t, own, nil, "sh", "-c", build)
		if strings.Contains(stdout, "compiles=0") || !strings.HasPrefix(stdout, "exit=0\ncompiles=") {
			t.Fatalf("the first build printed %q, want exit=0 and some compiles", stdout)
		}
		cold := sum() // the image exists, or sum has failed the test

		flags = []string{"--memory", "2GiB", "--cache", "go"}
		stdout, _, _ = pipesIn(t, own, nil, "sh", "-c", build+"echo x > /cache/go/mark && echo marked")
		if want := "exit=0\ncompiles=0\nmarked\n"; stdout != want {
			t.Errorf("the second build printed %q, want %q: warm, and the read-only cache writable to the guest", stdout, want)
		}
		stdout, _, _ = pipesIn(t, own, nil, "sh", "-c", build+"test -e /cache/go/mark && echo present || echo absent")
		if want := "exit=0\ncompiles=0\nabsent\n"; stdout != want {
			t.Errorf("the third build printed %q, want %q: warm, and no mark", stdout, want)
		}
		if sum() != cold {
			t.Error("the image of a read-only cache changed")
		}
	})

	t.Run("terminal", func(t *testing.T) {
		master, slave := openPTY(t)
		setSize(t, master, 24, 80)
		before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		cmd := workcell(repo, slave, "sh", "-c", "stty size; echo READY; read x; stty size; exit 3")
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

	// The command reads lines and answers each as got:<line>; quit ends it with status 5.
	const echo = `echo READY; while read l; do echo "got:$l"; [ "$l" = quit ] && exit 5; done`

	// Closing the terminal detaches (A9): the supervisor stays the one process that owns the VM,
	// `attach` brings a terminal back, and the end of the command is recorded (I9).
	t.Run("detach", func(t *testing.T) {
		run := onTerminal(t, workcell(repo, nil, "sh", "-c", echo))
		run.out.wait(t, "READY")
		run.master.Close() // the terminal goes away: SIGHUP, and EIO on its input
		select {
		case err := <-run.exited:
			t.Fatalf("the session ended with its terminal: %v", err)
		case <-time.After(time.Second):
		}
		if out, err := verb(repo, nil, "ls").Output(); err != nil || !regexp.MustCompile(`running +`+regexp.QuoteMeta(repo)).Match(out) {
			t.Fatalf("workcell ls after the terminal closed: %q, %v; want the session running", out, err)
		}
		at := onTerminal(t, verb(repo, nil, "attach"))
		at.typeUntil(t, "ping\n", "got:ping")
		at.master.WriteString("quit\n")
		if code := exitCode(t, at.exited, "attach"); code != 5 {
			t.Errorf("attach exited %d, want the command's 5", code)
		}
		if code := exitCode(t, run.exited, "run"); code != 5 {
			t.Errorf("run exited %d, want the command's 5", code)
		}
		if !at.restored() {
			t.Error("attach left its terminal changed")
		}
		if out, err := verb(repo, nil, "log").Output(); err != nil || !strings.Contains(string(out), "session_end") || !strings.Contains(string(out), "exit 5") {
			t.Errorf("workcell log has no session_end for exit 5: %q, %v", out, err)
		}
		if out, err := verb(repo, nil, "verify").CombinedOutput(); err != nil {
			t.Errorf("workcell verify: %v\n%s", err, out)
		}
	})

	// A second attach takes the terminal over: the client before it ends, restored, and says so.
	t.Run("takeover", func(t *testing.T) {
		run := onTerminal(t, workcell(repo, nil, "sh", "-c", echo))
		run.out.wait(t, "READY")
		first := onTerminal(t, verb(repo, nil, "attach"))
		first.typeUntil(t, "one\n", "got:one")
		run.out.wait(t, "detached") // the terminal that started the session was the client before
		second := onTerminal(t, verb(repo, nil, "attach"))
		second.typeUntil(t, "two\n", "got:two")
		if code := exitCode(t, first.exited, "the first attach"); code != 0 || !strings.Contains(first.out.String(), "detached") || !first.restored() {
			t.Errorf("first attach: exit %d, restored %v, shows %q; want 0, restored, and a detached line", code, first.restored(), first.out.String())
		}
		if strings.Contains(first.out.String(), "got:two") {
			t.Error("the output went to the client that was turned out")
		}
		second.master.WriteString("quit\n")
		if code := exitCode(t, second.exited, "the second attach"); code != 5 {
			t.Errorf("second attach exited %d, want 5", code)
		}
		if code := exitCode(t, run.exited, "run"); code != 5 {
			t.Errorf("run exited %d, want 5", code)
		}
	})
}

// terminal is a command started on a pseudo-terminal of its own, which is also its controlling terminal.
type terminal struct {
	master   *os.File
	out      *screen
	exited   <-chan error
	restored func() bool // whether the terminal's settings are what they were before the command ran
}

func onTerminal(t *testing.T, cmd *exec.Cmd) *terminal {
	t.Helper()
	master, slave := openPTY(t)
	setSize(t, master, 24, 80)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	out := &screen{}
	go out.copyFrom(master)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("%v shows:\n%q", cmd.Args[1:], out.String())
		}
	})
	return &terminal{master, out, exited, func() bool {
		after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		return err == nil && *after == *before
	}}
}

// typeUntil types line again and again until the terminal shows want, for up to 30 s: a client
// that has not connected yet reads nothing, and a line typed twice is answered twice.
func (x *terminal) typeUntil(t *testing.T, line, want string) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if strings.Contains(x.out.String(), want) {
			return
		}
		if _, err := x.master.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatalf("no %q on the terminal in 30 s; it shows %q", want, x.out.String())
}

// exitCode is the exit status of the command that ended, waiting up to 30 s for it.
func exitCode(t *testing.T, exited <-chan error, what string) int {
	t.Helper()
	select {
	case err := <-exited:
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return 0
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not end in 30 s", what)
	}
	return -1
}

// debianImage builds cmd/mkimage into dir and runs it on the pinned Debian: the root image
// `workcell update` will leave, as the escape adapter makes it.
func debianImage(t *testing.T, dir string) string {
	t.Helper()
	build(t, dir, "github.com/omkhar/workcell/v2/cmd/mkimage")
	image := filepath.Join(dir, "root.ext4")
	mk := exec.Command(filepath.Join(dir, "mkimage"), "-pin", "../../../pins/debian.json", "-arch", "amd64", "-o", image)
	if out, err := mk.CombinedOutput(); err != nil {
		t.Fatalf("mkimage: %v\n%s", err, out)
	}
	return image
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
