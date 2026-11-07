// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// exported is the sandbox the I1 and I7 tests want: a workspace export.
var exported = Want{Workspace: true}

// live is the sandbox the mount-mode I1 tests want: the export itself served
// live into the guest (`--mount`, SPEC A5), so that a write inside it is
// correct and only a byte beside or above it is a break.
var live = Want{Workspace: true, Mount: true}

// residueDirs are the places a guest writes that another guest must not see.
var residueDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/root", "/run"}

// target is what an I1 probe gets: where the guest sees its export, and the
// host path, inode and content of a secret the judge planted beside it. An
// attacker knows the host's layout; the invariant must hold anyway.
type target struct {
	guest, secret, token string
	ino                  uint64
}

func outsideArgs(args []string) (target, error) {
	if len(args) != 4 {
		return target{}, errors.New("want guest path, secret path, token and inode")
	}
	ino, err := strconv.ParseUint(args[3], 10, 64)
	if err != nil {
		return target{}, err
	}
	return target{guest: args[0], secret: args[1], token: args[2], ino: ino}, nil
}

// outside judges an I1 probe. It plants a secret beside the export on the host,
// lets plant (if any) add hostile content to the export itself, and fails if
// the probe reports the secret's token or a file appears beside the export.
func outside(plant func(workspace string) error) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		root := filepath.Dir(s.Workspace)
		token := newToken()
		secret := filepath.Join(root, "secret")
		if err := os.WriteFile(secret, []byte(token+"\n"), 0o644); err != nil {
			return false, "", err
		}
		if plant != nil {
			if err := plant(s.Workspace); err != nil {
				return false, "", err
			}
		}
		st, err := os.Stat(secret)
		if err != nil {
			return false, "", err
		}
		r, err := s.Run(s.Guest, secret, token, strconv.FormatUint(inode(st), 10))
		if err != nil {
			return false, "", err
		}
		if strings.Contains(r.Detail, token) {
			return false, "the guest read the secret beside its export (guest says " + r.Status + ": " + r.Detail + ")", nil
		}
		written, _ := filepath.Glob(filepath.Join(root, "written-*"))
		if len(written) > 0 {
			return false, fmt.Sprintf("the guest wrote beside its export: %s (guest says %s: %s)", filepath.Base(written[0]), r.Status, r.Detail), nil
		}
		return true, "guest says " + r.Status + ": " + r.Detail, nil
	}
}

// plantLinks puts a hostile repository's symlinks in the export: one to the
// secret beside it, one to the directory beside it.
func plantLinks(workspace string) error {
	if err := os.Symlink("../secret", filepath.Join(workspace, "link")); err != nil {
		return err
	}
	return os.Symlink("..", filepath.Join(workspace, "updir"))
}

// traversalProbe reads and writes past the top of the export with "..".
func traversalProbe(args []string) Result {
	t, err := outsideArgs(args)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	// Not filepath.Join: it would fold the ".." away before the kernel sees it.
	return Result{Status: "tried", Detail: "read=" + tryRead(t.guest+"/../secret") + " write=" + tryWrite(t.guest+"/../written-"+t.token)}
}

// symlinkProbe follows the planted links, and one of its own to the secret's
// host path, and writes through the link to the directory beside the export.
func symlinkProbe(args []string) Result {
	t, err := outsideArgs(args)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	own := filepath.Join(t.guest, "own")
	if err := os.Symlink(t.secret, own); err != nil {
		return Result{Status: "error", Detail: "symlink: " + err.Error()}
	}
	return Result{Status: "tried", Detail: "link=" + tryRead(filepath.Join(t.guest, "link")) + " own=" + tryRead(own) +
		" write=" + tryWrite(filepath.Join(t.guest, "updir", "written-"+t.token))}
}

// moveProbe takes entries across the top of the export without a write of
// its own: a hard link to the secret's host path made inside the export and
// read, a directory renamed out through "..", and a file hard-linked out,
// the last two to names beside the export.
func moveProbe(args []string) Result {
	t, err := outsideArgs(args)
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	hard := filepath.Join(t.guest, "hard")
	in := "ok"
	if err := os.Link(t.secret, hard); err != nil {
		in = short(err)
	} else {
		in = tryRead(hard)
	}
	dir, file := filepath.Join(t.guest, "dir"), filepath.Join(t.guest, "file")
	if err := errors.Join(os.Mkdir(dir, 0o755), os.WriteFile(file, []byte("escape\n"), 0o644)); err != nil {
		return Result{Status: "error", Detail: "make entries: " + err.Error()}
	}
	out := "ok"
	if err := os.Rename(dir, t.guest+"/../written-"+t.token); err != nil {
		out = short(err)
	}
	link := "ok"
	if err := os.Link(file, t.guest+"/../written-"+t.token+"-link"); err != nil {
		link = short(err)
	}
	return Result{Status: "tried", Detail: "hardlink=" + in + " rename=" + out + " linkout=" + link}
}

// tryRead returns the first line of the file (of its first 64 KiB), or the
// error, in a few words.
func tryRead(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return short(err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return short(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	if len(line) > 40 {
		line = line[:40]
	}
	return strconv.Quote(line)
}

// tryWrite creates the file and says whether it could.
func tryWrite(path string) string {
	if err := os.WriteFile(path, []byte("escape\n"), 0o644); err != nil {
		return short(err)
	}
	return "ok"
}

// short is an error as the underlying errno or a few words, so that several
// fit one result line.
func short(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	s := err.Error()
	if len(s) > 32 {
		s = s[:32]
	}
	return strings.ReplaceAll(s, " ", "_")
}

// residueJudge has the guest leave a token in every place a session writes,
// starts a second session, and fails if that one can read any of them. The
// second session also looks where the first saw its export: in a real guest
// that path is its own, empty export.
func residueJudge(ctx context.Context, s Session) (bool, string, error) {
	token := newToken()
	r, err := s.Run("plant", token, s.Guest)
	if err != nil {
		return false, "", err
	}
	defer func() {
		s.Run("clean", token, s.Guest)
		for _, d := range residueDirs { // what the guest left, if its /tmp is the host's
			os.Remove(filepath.Join(d, residueName(token)))
		}
	}()
	if !strings.HasPrefix(r.Detail, "planted=") || r.Detail == "planted=0" {
		return false, "", fmt.Errorf("the first session planted nothing: %s", r.Detail)
	}
	two, err := s.Another(nil)
	if err != nil {
		return false, "", err
	}
	r2, err := two.Run("seek", token, s.Guest, two.Guest)
	if err != nil {
		return false, "", err
	}
	if !strings.HasPrefix(r2.Detail, "found=0") {
		return false, "the second session read what the first wrote: " + r2.Detail + " (first session: " + r.Detail + ")", nil
	}
	return true, "second session says " + r2.Status + ": " + r2.Detail + " (first session: " + r.Detail + ")", nil
}

func residueName(token string) string { return "escape-residue-" + token }

// inode is the file's inode number on the host.
func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// residueProbe plants the token in every residue directory and the export,
// seeks it from another session, or cleans it up: args[0] says which.
func residueProbe(args []string) Result {
	if len(args) < 3 {
		return Result{Status: "error", Detail: "want plant|seek|clean, token and export paths"}
	}
	verb, token := args[0], args[1]
	places := append(append([]string{}, residueDirs...), args[2:]...)
	n := 0
	var where []string
	for _, d := range places {
		path := filepath.Join(d, residueName(token))
		switch verb {
		case "plant":
			if os.WriteFile(path, []byte(token+"\n"), 0o644) == nil {
				n++
			}
		case "seek":
			if b, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(b)) == token {
				n++
				where = append(where, d)
			}
		case "clean":
			if os.Remove(path) == nil {
				n++
			}
		default:
			return Result{Status: "error", Detail: "unknown verb " + verb}
		}
	}
	detail := fmt.Sprintf("%s=%d", map[string]string{"plant": "planted", "seek": "found", "clean": "cleaned"}[verb], n)
	if len(where) > 0 {
		detail += " at " + strings.Join(where, ",")
	}
	return Result{Status: "tried", Detail: detail}
}
