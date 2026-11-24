// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam
// Reproduces C70 of S-1006 sweep 3 (I4): fails until fix unit S-F53 lands. S-F53 folds these rows into TestBlockedAddr in internal/proxy/proxy_test.go, or moves this file to internal/proxy/c70_test.go, and removes the folder.
package proxy

import "net/netip"
import "testing"

func TestC70EquinixMetadata(t *testing.T) {
	for a, want := range map[string]bool{"192.80.8.124": true, "::ffff:192.80.8.124": true, "168.63.129.16": true, "192.0.3.1": false} {
		if got := blockedAddr(netip.MustParseAddr(a), nil); got != want {
			t.Errorf("I4: blockedAddr(%s) = %v, want %v", a, got, want)
		}
	}
}
