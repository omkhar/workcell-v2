// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/omkhar/workcell/v2/internal/policy"
	"github.com/omkhar/workcell/v2/internal/proxy"
)

// configDir is where the policy lives: $XDG_CONFIG_HOME/workcell, or ~/.config/workcell (SPEC
// section 5), on every OS alike, as dataDir does for the data directory.
func configDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "workcell"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "workcell"), nil
}

// loadAllowlist reads the policy and builds the proxy's allowlist from it. A nil allowlist
// means the policy allows nothing: no TCP port is relayed. An error names the file and line.
func loadAllowlist() (*proxy.Allowlist, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "config.toml")
	p, err := policy.Read(file)
	if err != nil {
		return nil, err
	}
	return allowlist(p, file)
}

// allowlist turns the policy's allow entries into the proxy's allowlist, nil for none. A bare
// name is port 443 by SNI; "name:port" forwards that one port to the name. The proxy's parser
// judges each entry (A3), and an entry it refuses is reported with its line, a port two names
// claim with the line of the second.
func allowlist(p policy.Policy, file string) (*proxy.Allowlist, error) {
	if len(p.Allow) == 0 {
		return nil, nil
	}
	var all []string
	first := map[uint16]string{} // the entry that opened each forward port
	for _, e := range p.Allow {
		at := fmt.Sprintf("%s:%d", file, e.Line)
		if e.Text == "" || strings.ContainsAny(e.Text, " \t#") {
			return nil, fmt.Errorf("%s has an invalid endpoint: %q (want a host name, or host:port)", at, e.Text)
		}
		text := e.Text
		if !strings.Contains(text, ":") {
			text += ":443"
		}
		one, err := proxy.ParseAllowlist(text, at)
		if err != nil {
			return nil, err
		}
		for _, port := range one.Ports() {
			if port == 443 {
				continue
			}
			if prev, ok := first[port]; ok {
				if _, err := proxy.ParseAllowlist(prev+"\n"+text, at); err != nil {
					return nil, err
				}
			} else {
				first[port] = text
			}
		}
		all = append(all, text)
	}
	return proxy.ParseAllowlist(strings.Join(all, "\n"), file)
}
