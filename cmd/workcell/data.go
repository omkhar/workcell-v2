// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/vmm"
)

// dataDir is where the pinned artifacts live: $XDG_DATA_HOME/workcell, or ~/.local/share/workcell. update and doctor fill it; run only reads it.
func dataDir() (string, error) { return xdgDir("XDG_DATA_HOME", ".local", "share") }

// xdgDir is workcell's directory under the variable, else under the path beneath the home directory, on every OS alike. A relative variable is ignored, as the XDG spec says, and a relative home is an error: neither may name a tree under cwd (I13).
func xdgDir(env string, home ...string) (string, error) {
	if x := os.Getenv(env); filepath.IsAbs(x) {
		return filepath.Join(x, "workcell"), nil
	}
	h, err := os.UserHomeDir()
	if err == nil && !filepath.IsAbs(h) {
		err = fmt.Errorf("home directory %q is not an absolute path", h)
	}
	return filepath.Join(append(append([]string{h}, home...), "workcell")...), err
}

// judge is the error for a directory that holds, or lies inside, workcell's data or config directory, or holds the file config.toml resolves to (a link into a dotfiles repository, made yet or not, C85), named: a session there would carry the audit key, other sessions, their records, the images or the policy into the guest, and pull would write the guest's versions back (I7, I9, I13). A config.toml with more than one name (a hard link) is refused outright: its other names cannot be found without walking every directory.
// So is one that holds a mount point: a bind mount is neither a symlink nor an ancestor, so within relates it to nothing, and it can show those directories under another name, which no mount is told apart from (C65). So is one that holds the VMM directory of a running session (vmm, under its TMPDIR): the sockets there would lie in the guest's view, or under a pull, for the guest to swap for a link to any host socket of the operator's (I1, I4, I7). A stale record refuses nothing. And so is one that holds, or that a prefix leads into, a path the host later runs, opens or trusts from the user's config.toml or environment: the program of a cmd: source or the file of a file: source, the [update] ca, SSL_CERT_FILE, or an SSL_CERT_DIR entry or a member of one; a pull there would land the guest's version of it, for the broker, the installer or the proxy to run or trust next (C93; I8, I5, I6, I14). A missing config.toml names nothing; one that cannot be read or parsed cannot be judged and is refused. As the pull asks (holds, pull), each path is judged against the destination alone, which neither holds nor lies in the data directory by the first loop, and the [update] ca is one of them when absolute (a relative one is never a root: newInstaller refuses it). As session asks, each is judged against the working directory and the data directory, whose caches the guest writes (C84, C86), and the ca is left to the installer, which refuses it against the working directory while startup only warns and the session goes on, as before C93 (S1).
func judge(dir string, pull bool) error {
	data, err := dataDir()
	file, _ := configFile() // fails only as dataDir does; the file is judged resolved, as within resolves, so a link's target counts
	p, perr := policy.Read(file)
	if err = cmp.Or(err, perr); err != nil {
		return err
	}
	for _, held := range []string{data, filepath.Dir(file), file} {
		if within(dir, held) || within(held, dir) { // none need exist yet
			return fmt.Errorf("%q lies inside or holds workcell's own directory or config file %s, which no session may see: use another directory", dir, held)
		}
	}
	if fi, err := os.Stat(file); err == nil && fi.Mode().IsRegular() && fi.Sys().(*syscall.Stat_t).Nlink > 1 {
		return fmt.Errorf("workcell's config file %s has %d names, and another may lie in a directory a session sees, where the guest would rewrite it: make it a symbolic link or a copy instead", file, fi.Sys().(*syscall.Stat_t).Nlink)
	}
	// Linux lists the mount points in /proc/self/mountinfo by the kernel's own spelling, with a space, tab, newline and backslash escaped as octal. macOS has no such file, and no mount gives a directory a second name there (a firmlink is the system's own): nothing is listed, nothing refused.
	b, _ := os.ReadFile("/proc/self/mountinfo")
	under, octal := resolved(dir)+"/", strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 && strings.HasPrefix(octal.Replace(f[4]), under) {
			return fmt.Errorf("%q holds a mount at %s, which may be a second name of workcell's own directory %s or of another tree no session may see: unmount it or use another directory", dir, octal.Replace(f[4]), data)
		}
	}
	l, err := list(filepath.Join(data, "sessions"))
	for _, s := range l {
		b, _ := os.ReadFile(filepath.Join(data, "sessions", s.id, "vmm")) // none before boot
		for _, tmp := range strings.Split(string(b), "\n") {
			if s.state == "running" && tmp != "" && within(dir, tmp) {
				return fmt.Errorf("%q holds %s, the VMM directory of the running session %s, whose sockets no guest may see and no pull may write over: wait for it or workcell stop %s first", dir, tmp, s.id, s.id)
			}
		}
	}
	trusted, in := [][2]string{{"the [update] ca", map[bool]string{true: p.Update.CA}[pull && filepath.IsAbs(p.Update.CA)]}, {"SSL_CERT_FILE", os.Getenv("SSL_CERT_FILE")}}, map[bool]string{true: dir, false: data}[pull] // each path the host runs, opens or trusts, with what names it: none may lie in or lead into dir, nor into in: the data directory for a run (C84, C86), dir again for a pull, whose destination the first loop keeps out of it (C93). An empty value names nothing; a relative one is read against the working directory, as leadsInto reads it
	for _, s := range p.Secret {
		trusted = append(trusted, [2]string{fmt.Sprintf("secret %q", s.Name), sourcePath(s.Source)})
	}
	for _, d := range filepath.SplitList(os.Getenv("SSL_CERT_DIR")) { // and every member of each entry, since the system loader reads them all and follows a member that is a link out of the directory (C86). An entry that cannot be read (absent, or a file) names no member and is judged by its own path alone
		ents, _ := os.ReadDir(d)
		trusted = append(trusted, [2]string{"SSL_CERT_DIR", d})
		for _, e := range ents {
			trusted = append(trusted, [2]string{"SSL_CERT_DIR", filepath.Join(d, e.Name())})
		}
	}
	if i := slices.IndexFunc(trusted, func(t [2]string) bool { return t[1] != "" && leadsInto(t[1], dir, in) }); i >= 0 {
		return fmt.Errorf("%s names %s, which lies in or leads into %q, where the guest writes under --mount and a pull lands its tree%s: the host runs, reads or trusts that path, so no session may see it and no pull may write over it; move the file and set that path, or use another directory", trusted[i][0], trusted[i][1], dir, map[bool]string{false: ", or the data directory " + data + ", whose caches the guest writes"}[pull])
	}
	return err
}

func holds(dir string) error { return judge(dir, true) } // the pull's judge of its destination: judge, and the [update] ca too

// within says whether p is dir itself or lies under it, both resolved: the relation holds and session's temp-directory check share. The kernel judges by identity, not spelling: a bind mount (a firmlink on macOS) gives dir a second name that Rel never relates, so p's ancestors are also compared by inode.
func within(dir, p string) bool {
	if rel, err := filepath.Rel(resolved(dir), resolved(p)); err == nil && filepath.IsLocal(rel) { // "." or below
		return true
	}
	d, err := os.Stat(dir) // absent: dir holds nothing yet
	for q, up := resolved(p), ""; err == nil && q != up; q, up = filepath.Dir(q), q {
		if s, err := os.Stat(q); err == nil && os.SameFile(s, d) {
			return true
		}
	}
	return false
}

// leadsInto says whether a prefix of the path p, each followed as the kernel walks it (a link on the way too, and one not made yet by name, as resolved does), is the working directory cwd (or a pull's destination, in holds) or the data directory dir or lies in one: a file there is the repository's, or the guest's under --mount or by a pull, or a cache the guest writes by design, so none may be a root the host trusts (C59, C79, C84, C86, C93; I13, I14, I6, I8). A relative p is read against the working directory, so it leads there.
func leadsInto(p, cwd, dir string) (in bool) {
	for n, parts := 1, strings.SplitAfter(p, "/"); !in && n <= len(parts); n++ {
		in = within(cwd, strings.Join(parts[:n], "")) || within(dir, strings.Join(parts[:n], ""))
	}
	return in
}

// resolved is p absolute, with its symlinks followed: a link to a file not made yet is followed by name, as the kernel will once the file is made, and where p does not exist yet, the longest prefix that does is followed and the rest appended.
func resolved(p string) string {
	p, _ = filepath.Abs(p)
	for range 40 { // the kernel's own bound on a chain of links: a loop of them ends here, at the name it is at
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		} else if t, err := os.Readlink(p); err == nil { // a relative target is read from the link's directory as the kernel reads it, resolved, so that its .. climbs from where that directory really is
			p = filepath.Join(map[bool]string{false: resolved(filepath.Dir(p))}[filepath.IsAbs(t)], t)
		} else if d := filepath.Dir(p); d != p { // not the root
			return filepath.Join(resolved(d), filepath.Base(p))
		}
	}
	return p
}

// artifacts are the files a session boots from, and the directory they are in: the kernel, the initramfs, the root image and, where the backend is a program (vmmBinary), that too. run adds the provider layers (findLayers) and the caches (openCaches); pull and bench boot without them.
type artifacts struct {
	binary, kernel, initrd, image, dir string
	layers                             []vmm.Layer
	caches                             []vmm.Cache
}

// required names the files the backend here needs in the data directory, the VMM first.
func required() []string {
	names := []string{"vmlinux", "initrd.cpio", "root.ext4"}
	if vmmBinary != "" {
		names = append([]string{vmmBinary}, names...)
	}
	return names
}

// loadArtifacts is findArtifacts of the data directory.
func loadArtifacts() (artifacts, error) {
	dir, err := dataDir()
	if err != nil {
		return artifacts{}, err
	}
	return findArtifacts(dir)
}

// findArtifacts names the files in dir and says which one is missing, if any.
func findArtifacts(dir string) (artifacts, error) {
	a := artifacts{kernel: filepath.Join(dir, "vmlinux"), initrd: filepath.Join(dir, "initrd.cpio"), image: filepath.Join(dir, "root.ext4"), dir: dir}
	if vmmBinary != "" {
		a.binary = filepath.Join(dir, vmmBinary)
	}
	for _, n := range required() {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			return a, fmt.Errorf("%s is missing", filepath.Join(dir, n))
		}
	}
	return a, nil
}
