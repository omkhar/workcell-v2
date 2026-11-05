// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Ported from v1: egressproxy/allowlist.go

// Package proxy is the per-session egress proxy. It admits a TLS
// connection only when its SNI and port are on an exact allowlist, and it
// forwards a non-TLS port only to the one host that owns that port. It
// resolves every host itself and refuses non-public addresses.
package proxy

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	tlsPort                 = 443
	maxAllowlistBytes int64 = 1 << 20
)

// Allowlist is the exact (host, port) set the proxy admits.
type Allowlist struct {
	sni     map[string]bool   // hosts allowed as SNI on port 443
	forward map[uint16]string // each non-443 port to its single host
}

// LoadAllowlist reads an allowlist file with one host:port entry per line.
// Blank lines and text after '#' are ignored.
func LoadAllowlist(path string) (*Allowlist, error) {
	data, err := readFileNoFollow(path, "egress allowlist", maxAllowlistBytes)
	if err != nil {
		return nil, err
	}
	return ParseAllowlist(string(data), path)
}

// canonicalHost lower-cases a host name and drops a trailing dot, so every
// lookup keyed by host agrees on one spelling.
func canonicalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// dnsName reports whether host, already canonical, is a DNS name: dot-separated
// labels of 1 to 63 letters, digits and inner hyphens, at most maxLogHost bytes.
func dnsName(host string) bool {
	if host == "" || len(host) > maxLogHost {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ParseAllowlist parses allowlist text; label names its source in errors.
func ParseAllowlist(text, label string) (*Allowlist, error) {
	a := &Allowlist{sni: map[string]bool{}, forward: map[uint16]string{}}
	for _, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		for _, entry := range strings.Fields(line) {
			host, portText, err := net.SplitHostPort(entry)
			if err != nil {
				return nil, fmt.Errorf("%s has an invalid endpoint: %q", label, entry)
			}
			// The proxy routes by name: an IP literal has no SNI and no host alias.
			if _, err := netip.ParseAddr(host); err == nil {
				return nil, fmt.Errorf("%s has an IP literal endpoint: %q", label, entry)
			}
			host = canonicalHost(host)
			if !dnsName(host) {
				return nil, fmt.Errorf("%s has an invalid endpoint: %q", label, entry)
			}
			port64, err := strconv.ParseUint(portText, 10, 16)
			if err != nil || port64 == 0 {
				return nil, fmt.Errorf("%s has an invalid endpoint port: %q", label, entry)
			}
			port := uint16(port64)
			if port == tlsPort {
				a.sni[host] = true
				continue
			}
			if prev, ok := a.forward[port]; ok && prev != host {
				return nil, fmt.Errorf("%s maps port %d to more than one host (%s, %s); only port 443 can share a port", label, port, prev, host)
			}
			a.forward[port] = host
		}
	}
	if len(a.sni) == 0 && len(a.forward) == 0 {
		return nil, fmt.Errorf("%s has no endpoints", label)
	}
	return a, nil
}

// Hosts lists every host the allowlist names, on any port, each once, in ascending order.
func (a *Allowlist) Hosts() []string {
	hosts := make(map[string]bool, len(a.sni)+len(a.forward))
	maps.Copy(hosts, a.sni)
	for _, host := range a.forward {
		hosts[host] = true
	}
	return slices.Sorted(maps.Keys(hosts))
}

// TLSHosts lists the hosts allowed on port 443, in ascending order: the names the proxy terminates.
func (a *Allowlist) TLSHosts() []string { return slices.Sorted(maps.Keys(a.sni)) }

// Ports lists the ports the proxy must listen on, in ascending order.
func (a *Allowlist) Ports() []uint16 {
	var ports []uint16
	if len(a.sni) > 0 {
		ports = append(ports, tlsPort)
	}
	for port := range a.forward {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports
}
