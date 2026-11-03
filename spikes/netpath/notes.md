# U-300 spike: how guest packets reach the host proxy (input for ADR-003)

Prototype of option (a): the guest kernel terminates TCP itself and the guest init relays each stream over its own
vsock connection. Numbers marked CI come from the `netpath ...` lines that `go test -count=1 -v ./spikes/...` printed on
the hosted `ubuntu-24.04` runner (writable `/dev/kvm`), commit dd1c656 (PR #67), 2026-11-03 about 04:45Z: TestNetpath
PASS in 122.0 s, of which 107.5 s was the wait for the other spikes (`others_left=0`); whole gate 257 s.

## What the test does

1. Fetches the pinned Firecracker v1.17.0 and kernel A, builds `cmd/guest` as `/init`, waits (cap 200 s) for `fcch.test`
   and `libkrun.test` to end, then boots with `firecracker.New` (2 vCPU, 512 MiB, `workcell.ports=443,80`; hard limit 140 s).
   Control is `Listen(5000)`; the relay port 5001 is a plain unix listener on `<dir>/vsock_5001` (one stream each).
2. Host relay: bounded accept (1024 streams), reads the 20-byte header (version 1, proto 6/17, port BE, 16-byte address)
   under a 5 s deadline, splices TCP to a sink on 127.0.0.1 (sends one byte, reads the rest) and answers DNS itself
   (`canary.test.` A is 127.0.0.1, other names NXDOMAIN). Nothing leaves the host (T8).
3. Guest `setup`: `lo` up (ioctl), `local 0.0.0.0/0 dev lo table local` and `local ::/0` (netlink), `icmp_echo_ignore_all=1`,
   a dual-stack listener per port of `workcell.ports=`, UDP :53, `/etc/resolv.conf` at 127.0.0.1. Each accepted connection's
   `getsockname` is its original destination; it goes into the header.
4. Steps, each logged on its own (a failure logs `<key>=err:<text>` and the next runs): features, lo-only, setup, 20 connects
   to 198.51.100.7:443, one to [2001:db8::7]:443, a refused port, a 32 MiB send, a vsock half-close, DNS, the five I2 probes
   of `escape/suite` against canaries on the host's own address, ICMP with ignore 1 and 0, a vsock flood of 1100 streams
   (header plus 64 KiB each, held), release, one connect after the flood, quit.

## Keys and numbers

| Key | Meaning | CI |
|-----|---------|----|
| `cfg_<SYM>`, `tun_dev`, `kernel` | kernel A's config; open of `/dev/net/tun` | 6.1.155: NETFILTER, IP_NF_IPTABLES, XT_TARGET_REDIRECT, IP_MULTIPLE_TABLES, VETH, VSOCKETS y; NF_TABLES, XT_TARGET_TPROXY, TUN, DUMMY n; `tun_dev=ENOENT` |
| `lo_only_connect` | connect to 203.0.113.7:443 before any route | ENETUNREACH |
| `setup_ms`, `anyip4_route`, `anyip6_route`, `listen_*` | time of the whole setup; netlink answers | 0.766; ok, ok, all ok |
| `connect_p50_us` (min, max); `vsock_connect_p50_us` | dial to first sink byte, 20 samples; guest vsock connect plus header | 956 (763, 2657); 256 |
| `getsockname_dst`, `getsockname_match`, `hdr_dst` | destination in the guest and in the host's header | 198.51.100.7:443, true, same; 20 streams |
| `v6_*` | one IPv6 connect | 864 us, vsock 312 us, `[2001:db8::7]:443` in guest and header |
| `refused_errno`, `refused_us` | a port with no listener: the guest kernel's RST | ECONNREFUSED, 65 |
| `throughput_mib_s`, `sink_bytes`; `guest_send_mib_s` | 32 MiB at the host sink; the guest's write rate | 237.7, 33554432 (no loss at close); 281.0 |
| `vsock_shut_wr` | whether a guest SHUT_WR on vsock reaches the host | not-propagated (read timed out at 3002 ms) |
| `dns_answer`, `dns_rtt_ms`, `host_dns_queries` | Go resolver in the guest via the UDP 53 relay | 127.0.0.1, 1.171, AAAA then A |
| `i2_<test>=<status>\|host_saw=<n>` | probe status; canary on the host address; `relay_saw` | tcp4, mapped-v6: unreachable (refused); udp4, quic: sent; icmp: timeout; all `host_saw=0` (icmp na), `relay_saw=0`; `icmp_ignore1/0`: timeout, echo-reply |
| `flood_ok`, `flood_first_err`, `flood_ms`; `flood_*_delta_mib` | streams before the first failure; host RSS, fc RSS, MemAvailable | 1022, ECONNRESET@1022, 519; 45.3, 1.2, 55.6 |
| `relay_active`(`_after_release`), `after_flood_connect_p50_us` | relay state and recovery | 1022 (0), 1162 |
| `boot_ms`, `teardown_ms`, `vmm_exit`, `relay_bad_headers`, `relay_rejected` | timing and relay counters | 328, 27, nil, 1 (unexplained: a stream with no full header in 5 s), 0 |

## Findings that bear on the design

- A guest `shutdown(SHUT_WR)` on a vsock stream does not reach the host's unix stream under Firecracker. So a relay must
  carry end-of-stream in-band (a frame in the relay protocol) or close the whole stream; this prototype closes.
- 1022 streams opened and the next was reset (ECONNRESET): with the control connection, Firecracker's 1023-connection
  cap per vsock device. Held at the cap they cost 55.6 MiB of host MemAvailable (45.3 MiB in the test process, which counts
  the relay's copy buffers and the sink's side, as a proxy holds an upstream); release returned the relay to 0 active.

## Decision rules (from the brief), against CI

- (a) holds: `anyip4_route=ok`, `getsockname_match=true`, ECONNREFUSED in 65 us. No REDIRECT fallback is needed.
- I2: all five `host_saw=0`; `icmp_ignore1=timeout`, while `icmp_ignore0=echo-reply` shows the sysctl is required.
- `connect_p50_us` 956 (under 2000) and `throughput_mib_s` 237.7 (over 100) keep one vsock connection per stream.
- `setup_ms` 0.766 (under 20) settles P1. `flood_memavail_delta_mib` 55.6 (at most 256) at `flood_ok` 1022 keeps (a).
- macOS (not run): the design asks the VMM only for guest-initiated vsock to a host port and the guest kernel only for INET
  and `lo`, so the guest side is unchanged on any backend that offers that.
