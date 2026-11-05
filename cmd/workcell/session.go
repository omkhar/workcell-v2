// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A session is a directory <data>/sessions/<id>/ that the supervisor of `workcell run` makes
// and holds. It contains repo (the directory the session was run in), workspace.ext4 (a clone
// session's image), vmm (the temporary directories of the VMM's sockets and config, one path
// per line) and lock. The supervisor holds an advisory lock on lock for as long as it lives;
// the kernel drops it when the process ends, however it ends, so the lock says whether a
// session is running where a pid file would lie after a crash. No daemon and no registry:
// everything the verbs below know is in the session directory (A9).

// sessionTime names a session directory by when it began, so that the names sort by time;
// a random suffix keeps two that began in the same instant apart.
const sessionTime = "20060102T150405.000000000Z"

var sessionID = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{8}$`)

// validID is true for what newSession makes and for nothing else, so that an id taken from
// the command line can name no path but a session directory.
func validID(id string) bool { return sessionID.MatchString(id) }

// holdSession creates the lock file of the session directory dir, locks it for the life of
// the process and records the process id in it. Closing the file releases the lock.
func holdSession(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX) // a probe by ls may hold the lock for an instant
	if err == nil {
		_, err = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// running says whether a supervisor holds the lock of the session directory dir. A directory
// with no lock file has no supervisor.
func running(dir string) (bool, error) {
	f, err := os.Open(filepath.Join(dir, "lock"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close() // and with it the probe's lock
	switch err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err {
	case nil:
		return false, nil
	case unix.EWOULDBLOCK:
		return true, nil
	default:
		return false, err
	}
}

// supervisor is the pid the running supervisor of the session recorded.
func supervisor(dir string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, "lock"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return 0, errors.New("the supervisor has not recorded its pid yet: try again")
	}
	return pid, nil
}

// recordBoot notes tmp, a directory the VMM of the session uses, in the session directory so
// that rm finds it even when the supervisor was killed before it could remove it.
func recordBoot(dir, tmp string) error {
	f, err := os.OpenFile(filepath.Join(dir, "vmm"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(tmp + "\n")
	return errors.Join(err, f.Close())
}

// listing is one session as ls shows it.
type listing struct{ id, state, repo string }

// list describes every session under sessions, oldest first: the ids sort by time.
func list(sessions string) ([]listing, error) {
	ents, err := os.ReadDir(sessions)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var out []listing
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		dir := filepath.Join(sessions, e.Name())
		l := listing{id: e.Name(), state: "exited", repo: "-"}
		if up, err := running(dir); err != nil {
			return nil, err
		} else if up {
			l.state = "running"
		}
		if b, err := os.ReadFile(filepath.Join(dir, "repo")); err == nil {
			l.repo = strings.TrimSuffix(string(b), "\n")
		}
		out = append(out, l)
	}
	return out, nil
}

// removeSession removes the session id and everything it left on the host: its directory,
// the image in it, and the VMM's directories that vmm names. It refuses while a supervisor
// holds the session, and keeps the lock until nothing is left, so none can start meanwhile.
// RemoveAll unlinks a symlink and never follows one.
func removeSession(sessions, id string) error {
	if !validID(id) {
		return fmt.Errorf("%q is not a session id: workcell ls lists them", id)
	}
	dir := filepath.Join(sessions, id)
	if st, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) || err == nil && !st.IsDir() {
		return fmt.Errorf("no session %s: workcell ls lists them", id)
	} else if err != nil {
		return err
	}
	lock, err := os.Open(filepath.Join(dir, "lock"))
	switch {
	case err == nil:
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == unix.EWOULDBLOCK {
			return fmt.Errorf("session %s is running: workcell stop %s first", id, id)
		} else if err != nil {
			return err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, "vmm"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, tmp := range strings.Split(string(b), "\n") { // a path may hold a space, never a newline
		if tmp == "" {
			continue
		}
		// Only what MkdirTemp(.., "wc") made: an absolute path to a directory, never a link.
		if st, err := os.Lstat(tmp); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil || !filepath.IsAbs(tmp) || !strings.HasPrefix(filepath.Base(tmp), "wc") || !st.IsDir() {
			return fmt.Errorf("session %s names %q, which is not a VMM directory: not removed", id, tmp)
		}
		if err := os.RemoveAll(tmp); err != nil {
			return err
		}
	}
	return os.RemoveAll(dir)
}

// stopLadder is how stop asks: SIGTERM, which the supervisor passes on to the command in the
// guest, then SIGTERM again, which makes it give up waiting and tear the VM down, then SIGKILL.
// The VMM dies with the supervisor.
var stopLadder = []struct {
	sig  syscall.Signal
	wait time.Duration
}{{syscall.SIGTERM, 5 * time.Second}, {syscall.SIGTERM, 5 * time.Second}, {syscall.SIGKILL, 2 * time.Second}}

// stopSession ends the supervisor of the session id. The lock is checked before every signal,
// so the pid is signalled only while the lock says the process that wrote it still lives.
func stopSession(sessions, id string) error {
	if !validID(id) {
		return fmt.Errorf("%q is not a session id: workcell ls lists them", id)
	}
	dir := filepath.Join(sessions, id)
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("no session %s: workcell ls lists them", id)
	}
	for _, step := range stopLadder {
		up, err := running(dir)
		if err != nil {
			return err
		}
		if !up {
			if step == stopLadder[0] {
				return fmt.Errorf("session %s is not running", id)
			}
			return nil
		}
		pid, err := supervisor(dir)
		if err != nil {
			return err
		}
		if err := unix.Kill(pid, step.sig); err != nil {
			return err
		}
		for end := time.Now().Add(step.wait); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if up, _ := running(dir); !up {
				return nil
			}
		}
	}
	return fmt.Errorf("session %s did not stop", id)
}

// ls is `workcell ls`: one line per session, oldest first: its id, running or exited, and the
// directory it was run in.
func ls(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: workcell ls")
		return 2
	}
	sessions, err := sessionsPath()
	var l []listing
	if err == nil {
		l, err = list(sessions)
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell ls:", err)
		return 1
	}
	for _, s := range l {
		fmt.Fprintf(stdout, "%s  %-7s  %s\n", s.id, s.state, s.repo)
	}
	return 0
}

// stop is `workcell stop <id>`; rm is `workcell rm <id>`.
func stop(args []string, stderr io.Writer) int { return byID("stop", stopSession, args, stderr) }
func rm(args []string, stderr io.Writer) int   { return byID("rm", removeSession, args, stderr) }

func byID(verb string, do func(sessions, id string) error, args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: workcell %s <id>\n", verb)
		return 2
	}
	sessions, err := sessionsPath()
	if err == nil {
		err = do(sessions, args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "workcell %s: %v\n", verb, err)
		return 1
	}
	return 0
}

// sessionsPath is the directory holding the session directories.
func sessionsPath() (string, error) {
	dir, err := dataDir()
	return filepath.Join(dir, "sessions"), err
}
