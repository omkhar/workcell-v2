// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build !linux

package proxy

import "net/netip"

// hostRoutes reads no route table where the product has no netlink (a Mac): the host's own networks are its interface prefixes alone.
func hostRoutes() ([]netip.Prefix, error) { return nil, nil }
