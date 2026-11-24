// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// The reproducing test of C66 (S-1004, I4), parked under S4: it fails on the product until S-F49 lands. Hosted CI on 033c9b7 judged it a fail: the guest reached the canary at 192.175.48.2:8443 twice, the on-link neighbour of a host whose own address is a /32 with the prefix around it on-link through a route alone. The fix unit puts the want back directly after rebindingOwnSNI in escape/suite/rebind.go, and the row, with its comment line, directly after rebind-host-network-sni in escape/suite/tests.go's All. The plumbing (sandbox.Config.OnLink, Want.OnLink, suite.Hold's on-link layout, the `netns <socket> <on-link>` verb) stays live meanwhile: nothing uses it without the row. On a Mac the adapter refuses OnLink with ErrNotImplemented, since the maintainer's static lo0 layout cannot hold this one too; a Mac shape or a Linux-only row is the fix unit's call.
package suite

var rebindingOnLink = Want{Allow: rebinding.Allow, Resolver: judgeResolver, Isolated: true, OnLink: true}

// The same neighbour, with the host's own address held as a /32 and the prefix around it on-link through a route alone, as a cloud NIC or a DHCP classless route lays it out (sandbox.Config.OnLink): no interface prefix holds the neighbour, and it is the host's LAN still.
var rebindOnLinkNeighbour = Test{ID: "I4", Name: "rebind-on-link-neighbour-forward", Probe: rebindProbe, Host: rebindJudge(rebind{canary: "neighbour"}), Want: rebindingOnLink}
