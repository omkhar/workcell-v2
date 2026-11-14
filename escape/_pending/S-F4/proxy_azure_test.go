// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// S-F4 (I4). This file waits here, where Go does not compile it, until S-F4 lands; the fix unit folds it into internal/proxy/ as one row of
// TestBlockedAddr: `"168.63.129.16": true`. 168.63.129.16 is Azure's platform virtual IP, the WireServer that serves goal state, extension settings
// and the certificate protecting them; GitHub-hosted runners and Codespaces are Azure VMs. It is global unicast, in no blocked prefix and never an
// interface address of the host, so when the host resolver answers an allowed name with it (the rebind model) the host dials it for the guest,
// while the other providers' metadata addresses (169.254.169.254, 100.100.100.200, 192.0.0.192, fd00:ec2::254) are refused.
package proxy

import (
	"net/netip"
	"testing"
)

func TestBlockedAddrAzure(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"168.63.129.16": true, "::ffff:168.63.129.16": true, // Azure platform virtual IP (WireServer), plain and IPv4-mapped
	}
	for s, want := range cases {
		if got := blockedAddr(netip.MustParseAddr(s), nil); got != want {
			t.Errorf("blockedAddr(%s) = %v, want %v", s, got, want)
		}
	}
}
