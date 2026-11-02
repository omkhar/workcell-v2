// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I8 probes are a hostile repository. Root in the guest shapes its
// workspace so that a pull which runs git in it, trusts its configuration, or
// writes its tree by name acts on the host: every shape aims an effect at a
// file beside the export (written-*) or at a listener the judge started. The
// judge pulls, then looks. Nothing the guest says counts.
//
// Each shape is given where the guest sees its export, the host directory
// beside the export (an attacker knows the host's layout), a token, and one
// extra argument: the submodule URL for the submodule shape.

// repoProbe makes the shape args[0] in the guest's workspace.
func repoProbe(args []string) Result {
	if len(args) != 5 {
		return Result{Status: "error", Detail: "want shape, export, beside, token and extra"}
	}
	shape, guest, beside, token, extra := args[0], args[1], args[2], args[3], args[4]
	canary := func(effect string) string { return filepath.Join(beside, "written-"+effect) }
	// script writes a shell script that makes an effect on the host, then runs tail.
	script := func(path, effect, tail string) error {
		return os.WriteFile(path, []byte("#!/bin/sh\ntouch '"+canary(effect)+"'\n"+tail+"\n"), 0o755)
	}
	var err error
	if shape != "fill" {
		err = gitDir(guest, map[string]string{"dotdot": "[core]\n\tbare = true\n", // so that a snapshot of the work tree cannot replace HEAD
			"config": "[core]\n\tfsmonitor = " + guest + "/.git/fsmonitor\n\thooksPath = " + guest + "/.hooks\n" +
				"[filter \"escape\"]\n\tclean = " + guest + "/.git/filter\n\trequired = true\n"}[shape])
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(guest, "work"), []byte(token+"\n"), 0o644)
	}
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	switch shape {
	case "hooks":
		for _, h := range []string{"pre-commit", "post-commit", "post-index-change"} {
			err = errors.Join(err, script(filepath.Join(guest, ".git", "hooks", h), "hook-"+h, ""))
		}
	case "config":
		err = errors.Join(os.Mkdir(filepath.Join(guest, ".hooks"), 0o755),
			script(filepath.Join(guest, ".hooks", "pre-commit"), "hookspath", ""),
			script(filepath.Join(guest, ".git", "fsmonitor"), "fsmonitor", "echo /"),
			script(filepath.Join(guest, ".git", "filter"), "filter", "cat"),
			os.WriteFile(filepath.Join(guest, ".gitattributes"), []byte("* filter=escape\n"), 0o644))
	case "submodule":
		err = errors.Join(os.WriteFile(filepath.Join(guest, ".gitmodules"), []byte("[submodule \"sub\"]\n\tpath = sub\n\turl = "+extra+"\n"), 0o644),
			os.Mkdir(filepath.Join(guest, "sub"), 0o755))
		_, e := git(guest, "", "update-index", "--add", "--cacheinfo", "160000,"+(token + token)[:40]+",sub")
		err = errors.Join(err, e)
	case "dotdot": // a commit whose tree holds a subtree named "..": git's own tools refuse to make one
		blob, e1 := git(guest, "escape\n", "hash-object", "-w", "--stdin")
		sub, e2 := git(guest, "100644 blob "+blob+"\twritten-"+token+"\n", "mktree")
		top, e3 := git(guest, "040000 tree "+sub+"\t..\n100644 blob "+blob+"\twork\n", "mktree")
		commit, e4 := git(guest, "", "commit-tree", top, "-m", "escape")
		_, e5 := git(guest, "", "update-ref", "HEAD", commit)
		err = errors.Join(e1, e2, e3, e4, e5)
	case "link":
		err = os.Symlink("..", filepath.Join(guest, "updir"))
	case "fill": // the link of the pull before is now a directory with a file in it
		dir := filepath.Join(guest, "updir")
		err = errors.Join(os.Remove(dir), os.Mkdir(dir, 0o755), os.WriteFile(filepath.Join(dir, "written-"+token), []byte("escape\n"), 0o644))
	case "case":
		err = errors.Join(os.WriteFile(filepath.Join(guest, "Readme"), []byte("upper\n"), 0o644),
			os.WriteFile(filepath.Join(guest, "readme"), []byte("lower\n"), 0o644))
	default:
		err = errors.New("unknown shape " + shape)
	}
	if err != nil {
		return Result{Status: "error", Detail: shape + ": " + err.Error()}
	}
	return Result{Status: "shaped", Detail: shape}
}

// gitDir lays out a repository by hand, with the configuration given, so
// that the shape depends on no git in the guest and brings no template.
func gitDir(guest, config string) error {
	dir := filepath.Join(guest, ".git")
	for _, d := range []string{"objects", "refs/heads", "hooks"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}
	return errors.Join(os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644),
		os.WriteFile(filepath.Join(dir, "config"), []byte("[core]\n\trepositoryformatversion = 0\n"+config), 0o644))
}

// git runs git in the guest's repository with stdin and returns its first
// line of output.
func git(guest, stdin string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", guest}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=escape", "GIT_AUTHOR_EMAIL=escape@localhost", "GIT_COMMITTER_NAME=escape", "GIT_COMMITTER_EMAIL=escape@localhost")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return line, nil
}

// bring has the guest make the shape and pulls the workspace into the
// directory pulled, beside the export. A refusal is reported, not returned;
// an adapter that cannot pull at all is an error.
func bring(s Session, shape, token, extra string) (refused string, err error) {
	beside := filepath.Dir(s.Workspace)
	r, err := s.Run(shape, s.Guest, beside, token, extra)
	if err != nil {
		return "", err
	}
	if r.Status != "shaped" {
		return "", fmt.Errorf("the guest did not shape its repository: %s: %s", r.Status, r.Detail)
	}
	err = s.Pull(filepath.Join(beside, "pulled"))
	if errors.Is(err, sandbox.ErrNotImplemented) {
		return "", err
	}
	if err != nil {
		return fmt.Sprintf("the pull of %s was refused: %.80s", shape, err.Error()), nil
	}
	return "", nil
}

// effects fails if any shape's effect landed beside the export.
func effects(s Session, note string) (bool, string, error) {
	written, _ := filepath.Glob(filepath.Join(filepath.Dir(s.Workspace), "written-*"))
	for i, w := range written {
		written[i] = filepath.Base(w)
	}
	if len(written) > 0 {
		return false, "the pull acted on the repository's content: " + strings.Join(written, ", ") + " appeared beside the export" + note, nil
	}
	return true, "nothing appeared beside the export" + note, nil
}

// obeyed makes the shapes one after another, pulling after each, and fails
// if an effect landed beside the export.
func obeyed(shapes ...string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		token, note := newToken(), ""
		for _, shape := range shapes {
			refused, err := bring(s, shape, token, "")
			if err != nil {
				return false, "", err
			}
			if refused != "" {
				note += "; " + refused
			}
		}
		return effects(s, note)
	}
}

// fetched names, in .gitmodules, a submodule at a listener on the host's own
// address, and fails if the pull connects to it.
func fetched(ctx context.Context, s Session) (bool, string, error) {
	addr, err := resolve(hostAddr + ":0")
	if err != nil {
		return false, "", err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return false, "", fmt.Errorf("canary listener: %w", err)
	}
	defer ln.Close()
	var got []string
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			got = append(got, c.RemoteAddr().String())
			c.Close()
		}
	})
	token := newToken()
	url := "http://" + ln.Addr().String() + "/escape-" + token + ".git"
	refused, err := bring(s, "submodule", token, url)
	ln.Close()
	wg.Wait()
	if err != nil {
		return false, "", err
	}
	if len(got) > 0 {
		return false, fmt.Sprintf("the pull fetched the submodule URL the repository named, %s: %d connections, the first from %s", url, len(got), got[0]), nil
	}
	return true, "nothing connected to " + url + "; " + refused, nil
}

// collided fails unless the pull refuses a tree with two names that differ
// only in case: a launch host (SPEC P6) folds case, and there the second
// name's content lands on the first.
func collided(ctx context.Context, s Session) (bool, string, error) {
	refused, err := bring(s, "case", newToken(), "")
	if err != nil {
		return false, "", err
	}
	var brought []string
	for _, name := range []string{"Readme", "readme"} {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(s.Workspace), "pulled", name)); err == nil {
			brought = append(brought, name)
		}
	}
	switch {
	case refused == "":
		return false, "the pull accepted names that differ only in case and brought " + strings.Join(brought, " and "), nil
	case len(brought) > 0:
		return false, refused + ", and it still brought " + strings.Join(brought, " and "), nil
	}
	return true, refused, nil
}

// The I13 tests bring a workcell.toml, in the export before the session
// starts, that tries to widen the session's policy. Each reuses the probe
// and the judge of the invariant the widening would break.
var (
	// widened allows one name at user level; the repository allows the other.
	widened = Want{Workspace: true, Allow: []string{"bound.escape.test"}, Deny: []string{"other.escape.test"}, Secret: true,
		Policy: "[network]\nallow = [\"other.escape.test\"]\n"}
	// rebound binds the user's secret, in the repository's policy, to the other allowed name as well.
	rebound = Want{Workspace: true, Allow: withSecret.Allow, Secret: true,
		Policy: "[[secret]]\nname = \"escape\"\nhost = \"other.escape.test\"\nheader = \"x-api-key\"\n"}
	// mounted asks for the user's tree live in the guest instead of a clone.
	mounted = Want{Workspace: true, Policy: "[workspace]\nmode = \"mount\"\n"}
	// uncapped asks for more than the user's caps.
	uncapped = Want{Workspace: true, CPUs: capped.CPUs, MemoryMiB: capped.MemoryMiB, DiskMiB: capped.DiskMiB,
		Policy: "[resources]\ncpus = 8\nmemory = \"4GiB\"\ndisk = \"20GiB\"\n"}
)

// reachJudge fails if the other name, which only the repository's policy
// allows, served the guest. The bound name serving the probe's check shows
// that the session worked at all.
func reachJudge(s Session, bound, other *canary) (bool, string, error) {
	r, err := run(s, bound, other)
	if err != nil {
		return false, "", err
	}
	if rs := other.requests(); len(rs) > 0 {
		return false, fmt.Sprintf("the guest reached %s, which only the repository's policy allows: %s (guest says %s: %s)", other.name, other.served(), r.Status, r.Detail), nil
	}
	if len(bound.requests()) == 0 {
		return false, "", fmt.Errorf("%s saw nothing, not even the check a correct product serves (guest says %s: %s)", bound.name, r.Status, r.Detail)
	}
	return true, fmt.Sprintf("%s; %s (guest says %s: %s)", bound.served(), other.served(), r.Status, r.Detail), nil
}

// liveProbe writes a file in the export, as an agent would.
func liveProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want the export path and a token"}
	}
	return Result{Status: "tried", Detail: "write=" + tryWrite(filepath.Join(args[0], "written-"+args[1]))}
}

// liveJudge fails if the guest's write is in the host's tree at once: the
// repository's policy made the workspace a mount, or the default is not a
// clone (SPEC A5).
func liveJudge(ctx context.Context, s Session) (bool, string, error) {
	token := newToken()
	r, err := s.Run(s.Guest, token)
	if err != nil {
		return false, "", err
	}
	if _, err := os.Lstat(filepath.Join(s.Workspace, "written-"+token)); err == nil {
		return false, "the guest's write is in the host's tree at once: the workspace is a mount, not a clone (guest says " + r.Status + ": " + r.Detail + ")", nil
	}
	return true, "the host's tree is untouched (guest says " + r.Status + ": " + r.Detail + ")", nil
}
