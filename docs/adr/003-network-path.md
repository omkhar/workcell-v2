# ADR-003: the network path from guest to proxy

status: proposed

## Context

A3 makes a host-side userspace proxy the only way out, default deny, allow by hostname; A1 trusts nothing in the guest; I2 covers raw
IPs, any port, IPv6, UDP, QUIC and ICMP; I3 and I4 resolve on the host and dial the vetted address; I11 makes a dead helper mean no
network; I12 keeps hostile channel bytes harmless. ADR-001 gives no backend a network device: vsock is the only channel, the init is
shared (A7). Today the guest has `lo` only: the gate's five I2 probes end in "network is unreachable", P1 p50 is 243 ms. U-300 built (a) as
`spikes/netpath` and ran it once in hosted CI (ubuntu-24.04, 4 vCPU, /dev/kvm; 2026-11-03 04:45Z, commit dd1c656, pull request #67):
Firecracker v1.17.0, kernel A 6.1.155, 2 vCPU, 512 MiB, a static Go PID 1 in an initramfs, no network device. Numbers are from that run
unless marked; the test took 122 s, 107.5 s of them waiting for the other spike packages, and the gate 257 s of its 900 s.

## Options

| | (a) AnyIP route, the guest kernel terminates TCP, one vsock stream per connection | (a') as (a), multiplexed over one vsock connection | iptables REDIRECT to the init, same relay | (b) tun in the guest, gVisor netstack on the host | (c) passt, pasta, slirp | (d) virtio-net: tap on Linux, NAT on vz | (e) HTTP_PROXY variables only |
|---|---|---|---|---|---|---|---|
| Guest needs | INET, IPV6, VSOCKETS, netlink, `lo`: kernel A has them (measured), kernel C has them; no netfilter, TUN or modules | as (a) | NETFILTER, IP_NF_IPTABLES, REDIRECT (A: y) and an iptables front end: about 250 lines of raw `ipt_replace` or one pinned static binary | TUN: n in A (`/dev/net/tun` ENOENT), y in C | a network device of a kind no backend of ours has | a network device | a listener on `lo`, and programs that honour the variables |
| Host side; macOS; lines | one accept loop in the supervisor, fed by a unix socket or by vz `VirtioSocketDevice.Listen(port)` (v3.8.0, MIT, newest tag); 0 modules; about 400 | as (a) plus stream ids and per-stream flow control; about 600 | as (a); about 650 | gvisor.dev/gvisor: 1 direct module at a pseudo-version (no tagged release, so B3 cannot select it), about 50 indirect (gvisor-tap-vsock has 27 direct requires); a kernel C pin; about 400 plus the module; gains ICMP and true half-close | attaches to qemu over a unix socket, Linux only; Firecracker's only net backend is tap; GPL-2.0-or-later and BSD-3-Clause per distribution metadata, dated snapshots about monthly (passt.top unreachable from here); no macOS | tap needs CAP_NET_ADMIN (P3); vz NAT gives the guest a path no proxy ends (A3) | 0; about 60 on top of (a) |
| I2 before the proxy | unlisted TCP port: the guest kernel's RST in 65 us; UDP and QUIC die in the guest; ICMP echo ignored by sysctl; IPv6 the same route | as (a) | TCP as (a); UDP needs more rules | every packet reaches a host-side stack that must drop it (I12 surface) | the helper's own policy | none: enforcement would be a host firewall | a program that ignores the variables gets ENETUNREACH, as today |
| Measured | setup 0.77 ms; connect to first byte p50 956 us (763 to 2657), the vsock part 256 us; 237.7 MiB/s through the relay against 281 MiB/s of raw guest writes, all 32 MiB arrived; 1022 held streams cost 55.6 MiB | not built | not built: the route worked | not built: no pinned kernel has TUN | not built | not built | served by (a)'s relay |

## Decision

- Option (a). The init brings `lo` up, adds `local 0.0.0.0/0 dev lo table local` and `local ::/0` over route netlink (x/sys/unix, as
  `escape/suite` already does), sets `icmp_echo_ignore_all` for IPv4 and `net.ipv6.icmp.echo_ignore_all` (kernel 4.19 or later), listens
  dual-stack on each port of `workcell.ports=` and on UDP 53, and writes `nameserver 127.0.0.1`. Every address is then local: the guest
  kernel completes any TCP handshake to a listed port, and `getsockname` on the accepted socket is the destination the program dialled
  (equal on every stream, IPv4 and IPv6). It needs INET, IPV6, VSOCKETS, netlink and `lo`, nothing kernel C lacks; no netfilter, TUN or module.
- The host writes the list: the supervisor derives it from the allowlist (443 when any SNI host is allowed, plus each forward port) and
  appends `workcell.ports=443,80` to `Config.Cmdline`, which it builds with no secret in it (I5). Trusting it is trusting the host's own
  writing (A1), and the host admits only those ports regardless, so a guest that edits its copy gains nothing.
- Relay: one vsock connection per stream to host port 5001, opened by the init behind a 20-byte header: version 1, proto 6 or 17, port
  big-endian, 16-byte address (IPv4 mapped). The host reads exactly 20 bytes under a deadline before it allocates anything else; a wrong
  version or proto, or a port it does not serve, closes the stream (I12; the decoder and the frame reader get T5 fuzz targets).
- Joining `internal/proxy`: the relay hands each TCP stream to a per-port `net.Listener` adapter and the proxy's `Serve(ln, port)` runs
  unchanged: 443 routes by SNI, a forward port by its one host, and `connect` resolves the name on the host and dials the vetted address
  (I4, I6). The header's address is a hint for the deny line and is never dialled.
- UDP 53 (I3): the init forwards each datagram as one stream, header then a two-byte length frame, and writes back the one framed reply;
  the host resolver (U-304) answers allowed names and refuses the rest, so no query leaves the host (measured: `canary.test.` AAAA then
  A, 1.2 ms). Any address on UDP 53 lands there; TCP 53, 853 and every other port are unlisted; DoH is a 443 stream and meets the SNI check.
- Everything else (I2): TCP to an unlisted port gets the guest kernel's RST (ECONNREFUSED in 65 us, the host saw nothing); UDP and QUIC
  have no listener and die in the guest (both probes `sent`, host saw 0); ICMP echo is ignored (`timeout` with the sysctl at 1, `echo-reply`
  at 0); IPv6 and IPv4-mapped IPv6 take the same route and listeners. After U-301 the two TCP probes read "refused", not "unreachable".
- Half-close is carried by closing, not in band: a guest SHUT_WR on vsock never reached the host, since Firecracker's connection state
  machine acts only on a shutdown with both flags. So the init ends a stream when the program's read side returns EOF, the host when the
  upstream closes, each flushing what it holds; a host close reaches the guest as a full shutdown. TLS and HTTP never half-close, so
  keep-alive is untouched; a plaintext client that half-closes to end its request loses the reply. FIN in band would frame every chunk: 60 lines a side.
- Guest root (A1) can drop the route (then ENETUNREACH everywhere, as today), kill or replace the init, bind the listed ports, or speak the
  header protocol itself with any address or port: each stream still meets the host's port list, SNI or Host check and resolver, so the
  guest side shapes traffic and enforces nothing. I11: with the relay listener gone, Firecracker resets every guest connect to 5001
  (measured as ECONNRESET), the init resets the program's connection, and no byte leaves.
- Flood bound (I10): 1022 held streams of 64 KiB cost 55.6 MiB of host memory (relay process 45.3, Firecracker 1.2); the 1023rd was reset,
  since Firecracker's MAX_CONNECTIONS is 1023 and the control connection is one. A stalled host side adds the 64 KiB TX buffer per connection:
  about 135 MiB at the cap. The relay keeps its own cap of 1024, as the proxy does, the bound on vz; (a') buys nothing here. `relay_bad_headers=1`
  is that 1023rd connection: Firecracker connects the unix socket before it counts, so the host accepted a stream dropped before its header, at no cost.
- Second port and macOS: `Machine.Listen` stays as ADR-001 words it, connections to one port, and U-208's one-shot moves to the channel's
  caller, which wraps the plain listener itself, so the relay (and a later attach port) accept many and vz needs no second listener kind. The
  init is the same on vz; the host accepts from `VirtioSocketDevice.Listen(5001)` instead of a unix socket, nothing else is host-specific
  (U-701). P1: setup took 0.77 ms in the guest; the spike VM's 328 ms to first vsock byte, against the product's 243 ms p50, is its harness.
- (e) is a complement, not the path: the session environment may name a listed port as the proxy so tools that honour it get a reasoned
  refusal with no SNI peek; a tool that ignores it meets the same listeners (A1). It lands only if U-308 shows a denial it makes clearer.
- Inherited. U-301: the init setup, the relay and the second listener, I2 green on "refused". U-303: the per-port adapters; a stream the
  header does not place is closed. U-304: framed queries from a stream, allowed names only. U-306: close the relay listener when a helper
  dies and prove ECONNRESET. U-308: the header's destination beside the SNI or Host in deny lines; `explain` lists the ports.

## Consequences

- Budget: 0 new modules (still 2 of 15); about 400 lines (init 200, host 150, shared header and frame 50) and two T5 fuzz targets. A guest
  program cannot bind a listed port (EADDRINUSE); loopback services and every other port behave as before, and nothing leaves. Upstreams see
  a guest close as a close, never a bare FIN. `Machine.Listen` reads "connections" again and the channel's caller takes the one-shot (I12 holds).

## Reversal cost

Low. The guest side is one setup function and one relay loop in the init, the host side one accept loop behind `Serve(ln, port)`; proxy,
resolver, broker and audit never see vsock or the header, whose version byte lets an old host refuse a new format. (a') adds stream ids and
flow control, about 200 lines on both sides. iptables REDIRECT swaps the two netlink routes for about 250 lines of raw iptables or one pinned
static binary, plus SO_ORIGINAL_DST for getsockname. (b) waits for a kernel pin with TUN, costs the gvisor module and about 400 lines.
