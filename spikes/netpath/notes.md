# U-300 spike: how guest packets reach the host proxy (input for ADR-003)

Prototype of option (a): the guest kernel terminates TCP itself and the guest init relays each stream over its own
vsock connection. Numbers marked CI come from the `netpath ...` lines of `go test -count=1 -v ./spikes/...` on the
hosted runner; they are blank until a run prints them. The authoring session had no `/dev/kvm`.

## What the test does

1. Downloads the pinned Firecracker v1.17.0 and kernel A (6.1.155; URLs and digests of `internal/vmm/firecracker`'s tests)
   while it builds `cmd/guest` (static Go) as `/init` of a newc cpio. Then it waits (cap 200 s) until no `fcch.test` or
   `libkrun.test` runs, so their boots do not perturb timings or MemAvailable. The 140 s hard limit starts at boot.
2. Boots with the product backend (`firecracker.New`, 2 vCPU, 512 MiB, `workcell.ports=443,80` on the command line).
   Control is `Listen(5000)`; the relay port 5001 is a plain unix listener on `<dir>/vsock_5001` (one stream each).
3. Host relay: bounded accept (1024 streams), reads the 20-byte header (version 1, proto 6/17, port BE, 16-byte address)
   under a 5 s deadline, splices TCP to a sink on 127.0.0.1 (sends one byte, reads the rest) and answers DNS itself
   (`canary.test.` A is 127.0.0.1, other names NXDOMAIN). Nothing leaves the host (T8).
4. Guest `setup`: `lo` up (ioctl), `local 0.0.0.0/0 dev lo table local` and `local ::/0` (netlink), `icmp_echo_ignore_all=1`,
   a dual-stack listener per port of `workcell.ports=`, UDP :53, `/etc/resolv.conf` at 127.0.0.1. Each accepted connection's
   `getsockname` is its original destination; it goes into the header.
5. Steps, each logged on its own; a failure logs `<key>=err:<text>` and the next step runs: features, lo-only, setup,
   20 connects to 198.51.100.7:443, one to [2001:db8::7]:443, a refused port, a 32 MiB send, a vsock half-close, DNS, the five I2 probes of
   `escape/suite` against canaries on the host's own address, ICMP with ignore 1 and 0, a vsock flood of 1100 streams
   (header plus 64 KiB each, held), release, one connect after the flood, quit.

## Keys

| Key | Meaning | CI |
|-----|---------|----|
| `cfg_<SYM>`, `tun_dev`, `netlink_route`, `kernel` | kernel A's `/proc/config.gz` (y, m, n, absent); open of `/dev/net/tun` | CI |
| `lo_only_connect` | errno of a connect to 203.0.113.7:443 before any route (local run: ENETUNREACH) | CI |
| `setup_ms`, `anyip4_route`, `anyip6_route`, `listen_*` | time of the whole setup; netlink answers | CI |
| `connect_p50_us` (min, max) | dial to first byte from the sink, through guest relay, vsock, host relay; 20 samples | CI |
| `vsock_connect_p50_us` | the guest relay's vsock connect plus header write, per stream | CI |
| `getsockname_dst`, `getsockname_match`, `hdr_dst`; `v6_*` | destination seen by the guest and in the host's header; IPv6 | CI |
| `refused_errno`, `refused_us` | a port with no listener: the guest kernel's RST | CI |
| `throughput_mib_s`, `sink_bytes` | 32 MiB at the host sink, first to last byte; under 32 MiB means bytes lost at close | CI |
| `guest_send_mib_s`; `vsock_shut_wr` | guest write rate; whether a guest SHUT_WR on vsock reaches the host (else close only) | CI |
| `dns_answer`, `dns_rtt_ms`, `host_dns_queries` | Go resolver in the guest via UDP 53 relay | CI |
| `i2_<test>=<status>\|host_saw=<n>` | probe status and what the canary on the host address saw; `relay_saw` streams | CI |
| `icmp_ignore1`, `icmp_ignore0` | ICMP probe status with `icmp_echo_ignore_all` 1 and 0 | CI |
| `flood_ok`, `flood_first_err`; `flood_*_delta_mib` (host, fc RSS; MemAvailable) | streams opened before the first failure (`<errno>@<index>`); their cost | CI |
| `relay_active`(`_after_release`), `after_flood_connect_p50_us`; `boot_ms`, `teardown_ms`, `waited_s`, `test_s` | relay state and recovery; timing (`others_left` > 0: a perturbed run) | CI |

## Decision rules (from the brief)

- Keep (a) if `anyip4_route=ok`, `getsockname_match=true` and `refused_errno=ECONNREFUSED` with `refused_us` under 1000.
  If the route is refused or the destination is lost, fall back to legacy iptables REDIRECT (kernel A has it; see `cfg_*`).
- All five `i2_*` must show `host_saw=0`, and `icmp_ignore1` must not be `echo-reply`.
- `connect_p50_us` under 2000 and `throughput_mib_s` over 100 keep one vsock connection per stream.
- `setup_ms` under 20 settles P1.
- `flood_memavail_delta_mib` at or under 256 with `flood_ok` near 1023 keeps (a); otherwise (a'): multiplex over one vsock.
  The host deltas count the relay's copy buffers and the sink's side of each held stream, as a proxy holds an upstream.

Local facts (no VM): in a user and network namespace on this session's host kernel (6.18, IPv6 absent there) the guest's setup code gave
`lo_only_connect=ENETUNREACH`, `anyip4_route=ok`, getsockname equal to the dialled 198.51.100.7:443, 10.1.2.3:443 and
8.8.8.8:443, `refused_errno=ECONNREFUSED`, ICMP `echo-reply` with ignore 0 and `timeout` with 1; `anyip6_route=ENOTSUP`.

macOS (not run here): the design asks the VMM only for guest-initiated vsock to a host port and the guest kernel only
for INET and `lo`, so the guest side is unchanged on any backend that offers that.
