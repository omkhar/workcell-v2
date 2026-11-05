// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I8 probes are a hostile repository. Root in the guest shapes its
// workspace so that a pull which runs git in it, trusts its configuration, or
// writes its tree by name acts on the host: every shape aims an effect at a
// file beside the export (written-*) or at a listener the judge started. The
// judge pulls, then looks. Nothing the guest says counts.
//
// The guest has no git, so each shape writes .git itself (gitdir.go): the
// shapes git's own tools refuse, a tree named ".." or ".git", come the same
// way as the ones they allow. Each shape starts from a fresh .git, since
// each run of the product starts from a fresh copy of the export.
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
	// hook is a shell script that makes an effect on the host, then runs tail.
	hook := func(effect, tail string) []byte {
		return []byte("#!/bin/sh\ntouch '" + canary(effect) + "'\n" + tail + "\n")
	}
	script := func(path, effect, tail string) error { return os.WriteFile(path, hook(effect, tail), 0o755) }
	r := repo{guest}
	// The values are relative to the work tree, so that they hold wherever a pull brings it.
	err := r.create(map[string]string{
		"dotdot": "\tbare = true\n", // so that a snapshot of the work tree cannot replace HEAD
		"dotgit": "\tbare = true\n",
		"config": "\tfsmonitor = .git/fsmonitor\n\thooksPath = .hooks\n[filter \"escape\"]\n\tclean = ./.git/filter\n\trequired = true\n",
	}[shape])
	if err == nil {
		err = os.WriteFile(filepath.Join(guest, "work"), []byte(token+"\n"), 0o644)
	}
	if err != nil {
		return Result{Status: "error", Detail: err.Error()}
	}
	switch shape {
	case "plain": // the work file alone: what a pull must bring
	case "hooks":
		err = os.MkdirAll(filepath.Join(guest, ".git", "hooks"), 0o755)
		for _, h := range []string{"pre-commit", "post-commit", "post-index-change"} {
			err = errors.Join(err, script(filepath.Join(guest, ".git", "hooks", h), "hook-"+h, ""))
		}
	case "config":
		err = errors.Join(os.Mkdir(filepath.Join(guest, ".hooks"), 0o755),
			script(filepath.Join(guest, ".hooks", "pre-commit"), "hookspath", ""),
			script(filepath.Join(guest, ".git", "fsmonitor"), "fsmonitor", "echo /"),
			script(filepath.Join(guest, ".git", "filter"), "filter", "cat"),
			os.WriteFile(filepath.Join(guest, ".gitattributes"), []byte("* filter=escape\n"), 0o644))
	case "submodule": // the index holds a gitlink at sub, as `update-index --cacheinfo` would leave it
		err = errors.Join(os.WriteFile(filepath.Join(guest, ".gitmodules"), []byte("[submodule \"sub\"]\n\tpath = sub\n\turl = "+extra+"\n"), 0o644),
			os.Mkdir(filepath.Join(guest, "sub"), 0o755),
			r.index(entry{"160000", "sub", (token + token)[:40]}))
	case "dotdot": // a commit whose tree holds a subtree named "..": git's own tools refuse to make one
		err = committed(r, func(blob string) ([]entry, error) {
			sub, err := r.tree(entry{"100644", "written-" + token, blob})
			return []entry{{"40000", "..", sub}}, err
		})
	case "dotgit": // a commit whose tree holds a subtree named ".git", with a hook in it
		err = committed(r, func(string) ([]entry, error) {
			blob, err := r.object("blob", hook("dotgit-hook", ""))
			if err != nil {
				return nil, err
			}
			hooks, err := r.tree(entry{"100755", "pre-commit", blob})
			if err != nil {
				return nil, err
			}
			dotgit, err := r.tree(entry{"40000", "hooks", hooks})
			return []entry{{"40000", ".git", dotgit}}, err
		})
	case "link":
		err = os.Symlink("..", filepath.Join(guest, "updir"))
	case "fill": // the link of the pull before is now a directory with a file in it
		dir := filepath.Join(guest, "updir")
		err = errors.Join(os.RemoveAll(dir), os.Mkdir(dir, 0o755), os.WriteFile(filepath.Join(dir, "written-"+token), []byte("escape\n"), 0o644))
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

// committed writes a commit whose tree holds the work file and the entries
// more makes, given the id of a blob to use.
func committed(r repo, more func(blob string) ([]entry, error)) error {
	blob, err := r.object("blob", []byte("escape\n"))
	if err != nil {
		return err
	}
	entries, err := more(blob)
	if err != nil {
		return err
	}
	top, err := r.tree(append(entries, entry{"100644", "work", blob})...)
	if err != nil {
		return err
	}
	return r.commit(top)
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

// pulls has the guest make the plain shape, pulls it, and errors unless the
// pull brought its work file: a refusal proves nothing about a product that
// cannot pull at all.
func pulls(s Session) error {
	token := newToken()
	refused, err := bring(s, "plain", token, "")
	if err == nil && refused != "" {
		err = errors.New(refused)
	}
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(s.Workspace), "pulled", "work"))
	if err == nil && string(b) != token+"\n" {
		err = fmt.Errorf("pulled/work holds %q, not the token", b)
	}
	if err != nil {
		return fmt.Errorf("the pull brought nothing: %w", err)
	}
	return nil
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
		if err := pulls(s); err != nil {
			return false, "", err
		}
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
	if err := pulls(s); err != nil {
		return false, "", err
	}
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
	if err := pulls(s); err != nil {
		return false, "", err
	}
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

// planted fails if the pull wrote any path with a .git component into the
// host's tree: a hook there runs the moment the user runs git in it.
func planted(ctx context.Context, s Session) (bool, string, error) {
	if err := pulls(s); err != nil {
		return false, "", err
	}
	refused, err := bring(s, "dotgit", newToken(), "")
	if err != nil {
		return false, "", err
	}
	var found []string
	pulled := filepath.Join(filepath.Dir(s.Workspace), "pulled")
	filepath.WalkDir(pulled, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == ".git" {
			rel, _ := filepath.Rel(pulled, p)
			found = append(found, rel)
		}
		return nil
	})
	if len(found) > 0 {
		return false, "the pull wrote a .git component into the host's tree: " + strings.Join(found, ", ") + refused, nil
	}
	return true, "no .git component in the host's tree; " + refused, nil
}

// The I13 tests bring a workcell.toml, in the export before the session
// starts, that tries to widen the session's policy. Each reuses the probe
// and the judge of the invariant the widening would break. One narrows
// instead, so that a product which never reads the file is told apart from
// one that honours it.
var (
	// widened allows one name at user level; the repository allows the other.
	widened = repoPolicy(Want{Workspace: true, Allow: []string{"bound.escape.test"}, Deny: []string{"other.escape.test"}, Resolver: judgeResolver, Isolated: true, Secret: true}, "", "[network]\nallow = [\"bound.escape.test\", \"other.escape.test\"]\n")
	// respelled allows the other name as the user did not spell it: in capitals, with a trailing dot, by wildcard, as a forward port.
	respelled = repoPolicy(widened, "", "[network]\nallow = [\"bound.escape.test\", \"OTHER.escape.test\", \"other.escape.test.\", \"*.escape.test\", \"other.escape.test:443\"]\n")
	// linked is widened through a symbolic link to a file beside the export, outside the repository.
	linked = repoPolicy(widened, "link", widened.Policy)
	// narrowing allows both names at user level; the repository allows only the bound one.
	narrowing = repoPolicy(withSecret, "", "[network]\nallow = [\"bound.escape.test\"]\n")
	// rebound binds the user's secret, in the repository's policy, to the other allowed name as well.
	rebound = repoPolicy(withSecret, "", "[[secret]]\nname = \"escape\"\nsource = \"file:/etc/hostname\"\nhost = \"other.escape.test\"\nheader = \"x-api-key\"\n")
	// lifted repeats the user's narrowed secret without its method and path.
	lifted = repoPolicy(narrowed, "", "[[secret]]\nname = \"escape\"\nsource = \"file:/etc/hostname\"\nhost = \"bound.escape.test\"\nheader = \"x-api-key\"\n")
	// rewired repeats the user's secret with another header and a host file as its source.
	rewired = repoPolicy(withSecret, "", "[[secret]]\nname = \"escape\"\nsource = \"file:/etc/hostname\"\nhost = \"bound.escape.test\"\nheader = \"authorization\"\n")
	// mounted asks for the user's tree live in the guest instead of a clone.
	mounted = repoPolicy(exported, "", "[workspace]\nmode = \"mount\"\n")
	// piped is a workcell.toml no one will ever write to: a read of it never returns.
	piped = repoPolicy(exported, "fifo", "")
	// uncapped asks for more than the user's caps.
	uncapped = repoPolicy(Want{Workspace: true, CPUs: capped.CPUs, MemoryMiB: capped.MemoryMiB, DiskMiB: capped.DiskMiB}, "", "[resources]\ncpus = 8\nmemory = \"4GiB\"\ndisk = \"20GiB\"\n")
)

// repoPolicy is w with the repository's policy in the shape.
func repoPolicy(w Want, shape, policy string) Want { w.Shape, w.Policy = shape, policy; return w }

// PlantPolicy puts the repository's policy in the export ws before the
// session starts, in the shape w.Shape names: "" a plain file, "link" a
// symbolic link to a file beside the export (where the host, not the guest,
// can follow it), "fifo" a named pipe no one writes. The host must start, or
// refuse, within the test's time whatever the shape (SPEC I13, I10).
func PlantPolicy(ws string, w Want) error {
	path := filepath.Join(ws, "workcell.toml")
	switch w.Shape {
	case "link":
		return errors.Join(os.WriteFile(filepath.Join(ws, "..", "policy.toml"), []byte(w.Policy), 0o644), os.Symlink("../policy.toml", path))
	case "fifo":
		return syscall.Mkfifo(path, 0o644)
	case "":
		if w.Policy != "" {
			return os.WriteFile(path, []byte(w.Policy), 0o644)
		}
		return nil
	}
	return fmt.Errorf("unknown policy shape %q", w.Shape)
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
