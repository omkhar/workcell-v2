# Parked

Review findings and ideas that fail SPEC R2. One line each. Nobody acts on these during the loop.
The maintainer reads this at each phase boundary, and either promotes a line to a unit or deletes it.
Nothing that SPEC S14 covers is written here.
- U-005, reviewer finding 3 (I2, root in guest): no test sends a real IPv6 packet; add `{ID: "I2", Name: "ipv6-tcp6", Probe: dialProbe, Host: tcpCanary("tcp6", "[::1]:0", "")}` (better: the host's own non-loopback IPv6) once a host with IPv6 shows it FAILS on control; this session's kernel has none (T2).
