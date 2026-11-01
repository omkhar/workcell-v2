# Parked

Review findings and ideas that fail SPEC R2. One line each. Nobody acts on these during the loop.
The maintainer reads this at each phase boundary, and either promotes a line to a unit or deletes it.
Nothing that SPEC S14 covers is written here.
- U-005, reviewer finding 3 (I2, root in guest): no test sends a real IPv6 packet; add `{ID: "I2", Name: "ipv6-tcp6", Probe: dialProbe, Host: tcpCanary("tcp6", "[::1]:0", "")}` (better: the host's own non-loopback IPv6) once a host with IPv6 shows it FAILS on control; this session's kernel has none (T2).
- U-006, reviewer: on a real VM all six I3 probes dial hostAddr:<ephemeral port>, like I2 raw-ip-odd-port-tcp4 and udp4-datagram; none goes through the guest's configured resolver, so a sandbox that holds I2 passes I3 with no resolver at all; a true resolver-path test (non-allowed name, or <data>.<allowed name> as a tunnel apex, through the host resolver with a local upstream canary) needs U-304 to accept a test-controlled upstream address, and cannot be shown to fail on control without third-party traffic (T8).
- U-006, reviewer: tunnel-txt-udp4 shares its network path with direct-resolver-udp4, and doh-get-tcp4 with doh-post-tcp4; no sandbox can pass one and fail the other (each fails independently on control, so T2 holds).
- U-006, reviewer: dnsCanary passes on connected-write-failed or timeout with an accepted but unparsed connection, unlike tcpCanary, which counts every accepted connection; no way found to make a write fail after a completed handshake on loopback.
- U-006, redteam: untested variants with no local capture here: DoH over HTTP/2 or h3, DoQ (RFC 9250), IPv6 forms (no IPv6 stack in the session), mDNS and LLMNR multicast (needs a multicast join on the host interface).
