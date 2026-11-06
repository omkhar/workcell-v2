// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/omkhar/workcell/v2/internal/proxy"
	"github.com/omkhar/workcell/v2/internal/vmm"
)

// explain is `workcell explain [--mount] [--allow HOST]... [--cache NAME[:rw]]...`: it prints what a session started here by
// `workcell run`, with the same flags or without, can reach. The output is the whole assurance
// story (SPEC section 5): the workspace, the caches, the network, then the secrets.
func explain(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mount := fs.Bool("mount", false, "")
	var extra []string
	allowFlag(fs, &extra)
	var named []string
	cacheFlag(fs, &named)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: workcell explain [--mount] [--allow HOST]... [--cache NAME[:rw]]...\n  says what a session run here with the same flags can reach")
		return 2
	}
	caches, err := parseCaches(named)
	var cwd, file, held, note string
	var allow *proxy.Allowlist
	var secrets []binding
	if err == nil {
		cwd, err = os.Getwd()
	}
	if err == nil {
		held, err = cacheText(caches)
	}
	if err == nil {
		allow, secrets, note, file, err = loadPolicy(extra, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "workcell explain:", err)
		return 2
	}
	_, statErr := os.Stat(file)
	fmt.Print(explanation(*mount, cwd) + held + reach(file, statErr == nil, len(extra) > 0, allow) + note + bound(secrets))
	return 0
}

// cacheText is a line for each cache, from what the data directory holds now. It creates and locks nothing.
func cacheText(caches []vmm.Cache) (string, error) {
	if len(caches) == 0 {
		return "", nil
	}
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range caches {
		image := cachePath(dir, c.Name)
		_, err := os.Stat(image)
		b.WriteString(cacheLine(c, image, err == nil) + "\n")
	}
	return b.String(), nil
}

// bound is the secrets part: each by name, with the host and header it goes out in, the method
// and path prefix or the repositories it is narrowed to, the token endpoint that issues it when its source is a
// sign-in flow, and and the guest variable that holds its placeholder. Never its value (I5).
func bound(secrets []binding) string {
	if len(secrets) == 0 {
		return "secrets: none\n"
	}
	var b strings.Builder
	b.WriteString("secrets: swapped in by the session proxy; the guest holds a placeholder\n")
	for _, s := range secrets {
		fmt.Fprintf(&b, "  %s: in %s to https://%s", s.grant.Name, s.rule.Header, s.rule.Host)
		if s.rule.Method != "" {
			fmt.Fprintf(&b, ", %s only", s.rule.Method)
		}
		if s.rule.Path != "" {
			fmt.Fprintf(&b, ", under %s", s.rule.Path)
		}
		if len(s.rule.Repos) > 0 {
			fmt.Fprintf(&b, ", for %s", strings.Join(s.rule.Repos, ", "))
		}
		if s.rule.SignIn != nil {
			fmt.Fprintf(&b, ", signed in at https://%s%s", s.rule.SignIn.Host, s.rule.SignIn.Path)
		}
		if s.env != "" {
			fmt.Fprintf(&b, ", as $%s", s.env)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// explanation is the text for a session of dir: what its guest sees as /workspace, in plain words.
func explanation(mount bool, dir string) string {
	if mount {
		return "workspace: " + dir + ", live (--mount)\n" +
			"  The agent writes directly to the real tree: every change it makes lands there as it is\n" +
			"  made, and workcell pull and diff have nothing to bring back.\n"
	}
	return "workspace: a copy of " + dir + "\n" +
		"  The agent works in the copy; the real tree does not change until workcell pull brings\n" +
		"  the work back, and workcell diff lists it first.\n"
}

// reach is the network part: where the policy came from (file, which exists or not; flags, for
// --allow), then each name the guest can reach and how, in ascending order, or that it has no network.
func reach(file string, exists, flags bool, allow *proxy.Allowlist) string {
	from := "no config file at " + file
	if exists {
		from = "from " + file
	}
	if flags {
		from += " and --allow"
	}
	if allow == nil {
		return "network: " + from + "\n  The guest has no network.\n"
	}
	var b strings.Builder
	b.WriteString("network: " + from + "\n")
	for _, host := range allow.TLSHosts() {
		fmt.Fprintf(&b, "  https://%s  (443, terminated by the session proxy)\n", host)
	}
	for _, port := range allow.Ports() {
		if host, ok := allow.Forward(port); ok {
			fmt.Fprintf(&b, "  %s:%d  (tcp, forwarded as is)\n", host, port)
		}
	}
	b.WriteString("  Everything else is refused, and DNS answers only these names.\n")
	return b.String()
}
