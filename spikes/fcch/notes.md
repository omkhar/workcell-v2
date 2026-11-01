# U-101 spike: Firecracker and Cloud Hypervisor on Linux

Input for ADR-001 (U-103a, "choose the VM layer"). Numbers marked CI come from the `fcch ...` lines
that `go test -count=1 -v ./spikes/...` printed on the hosted `ubuntu-24.04` runner (4 vCPU, `/dev/kvm`
0666), run 2026-11-01 about 18:50Z on commit 26554d0 (PR #21): TestFCCH PASS in 89.09 s, whole gate PASS
in 128 s of 900 s. The authoring session had no `/dev/kvm`, so it could not boot anything. Facts marked
"local" were measured there on linux/amd64 with go 1.27.0 (downloads hashed, ELF headers read, nothing
downloaded was executed). Same measurements as U-100 (libkrun, notes in `spikes/libkrun/notes.md`).

## What the test does

1. Downloads four pinned inputs in parallel over HTTPS and checks their SHA-256 (logged before the
   compare): the Firecracker release tarball, the Cloud Hypervisor static binary, kernel A and kernel B.
   It also hashes the extracted `firecracker` and compares it with the line in the release's own
   `SHA256SUMS` (`fc_sha256sums=match`). In parallel it installs virtiofsd with
   `sudo -n apt-get install -y --no-install-recommends virtiofsd` (one `apt-get update` retry);
   if that fails, `ch-fs` is skipped and `virtiofsd=unavailable` is logged.
2. Builds the guest (static Go, `CGO_ENABLED=0`) and writes it as `/init` of an uncompressed newc
   cpio, in Go (about 30 lines). Both kernels accept a plain cpio.
3. Waits (poll `/proc/*/comm` each second, cap 240 s) until no `libkrun.test` runs, because
   `go test ./spikes/...` starts it beside this test and its cargo build would perturb the samples.
4. Rows, each one warm-up plus 20 timed boots, then one SIGKILL boot:
   `fc` (Firecracker, kernel A, blk-raw), `ch-blk` (Cloud Hypervisor, kernel A, blk-raw),
   `ch-fs` (Cloud Hypervisor, kernel B, virtio-fs). Cross rows, one boot each, separate the kernel
   effect from the VMM effect: `fc-kB`, `ch-blk-kB`. A failed cross row is logged, never fatal.

The guest reads a token and a host loopback address from the share, dials the address, lists
`/sys/class/net`, connects AF_VSOCK CID 2 port 5000 (retrying 5 s while the device probes), sends
`hello <token> loopback=<ok|err> ifaces=<csv> env_leak=<yes|no> exit=7 cmdline=<escaped>`, reads the
echo, writes it to the share, syncs and shuts the VM down. Neither VMM carries a guest exit code, so
`exit=7` over vsock is the only channel; `vmm_exit` is the VMM process's own status.

Share kinds: `blk-raw` on both VMMs (a 4 MiB file; the host writes `<token> <probe>` at offset 0, the
guest reads 512 B of `/dev/vda` and writes the echo at offset 4096, 2048 B, then fsync; no mkfs, no root);
`virtiofs` on Cloud Hypervisor only (tag `work`, files `from-host.txt`, `probe.txt`, `from-guest.txt`
exactly as libkrun).

Definitions: t0 is the instant before the boot's first host process starts (virtiofsd for `ch-fs`);
`total_ms` is first vsock byte minus t0 (the P1 number, libkrun's definition); `boot_ms` is first byte minus
the instant before `PUT /actions InstanceStart` (Firecracker) or before `cmd.Start` of cloud-hypervisor
(it has no separate start step, so for it `boot_ms` and `total_ms` differ only by virtiofsd's start);
`teardown_ms` is VMM exit minus vsock EOF; `api_ms` is first API 204 minus t0 (Firecracker only).

## Versions and inputs

| Input | Version | Asset | Bytes | SHA-256 |
|-------|---------|-------|-------|---------|
| Firecracker | v1.17.0 | `https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz` | 7464385 | `06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558` |
| firecracker binary inside it | v1.17.0 | member `release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64` (upstream `SHA256SUMS` agrees) | 3676680 | `99ad0f5cd0514a88aad0e9ae8cfdb3cc3b4ab9d190e1194602406c786b5de7a5` |
| Cloud Hypervisor | v54.0 | `https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static` | 7365360 | `4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b` |
| Kernel A (both VMMs) | 6.1.155 | `https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155` | 44278288 | `e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53` |
| Kernel B (virtio-fs, cross rows) | 7.2.8, tag `ch-release-v7.2.8-20261009` | `https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/vmlinux-x86_64` | 48205848 | `edfeb8a8a6c04ff2979e9f1c700feaa29b8f564f952261834ef0b7d2e673a853` |
| virtiofsd | 1.10.0, distribution package (noble universe) | `apt-get install virtiofsd` | 3152384 | `e256a63975f3ba343d651ce001fdc1f1128a5967612f0f102ab1387727ead140` (CI; not pinned, the package moves) |
| golang.org/x/sys | v0.49.0 | Go module, guest only | | go.sum |

- Fallbacks if an input disappears (one constant each): Firecracker v1.16.2 with the same URL pattern, then
  v1.13.1 (tgz sha256 `59450b9171ff2ebdf2f9a25be3a248a7ba79fb6371aec51a9d6d8eefca7b4faf`, 7546949 B);
  Cloud Hypervisor v48.0 (sha256 `e967dd736d434052f15883c5ef044b0d0ff36360d3df7082797fa7553be75092`, 4674208 B);
  kernel B `ch-release-v6.12.8-20250613` (50030992 B, sha256 `782a61a99df82b74100a687adcac23e6299aa6532f536a15d6c6aff04c5a9f74`).
- Kernel A is Firecracker's own CI guest kernel. Its config has VIRTIO_MMIO, VIRTIO_PCI, ACPI, PVH,
  VSOCK, VIRTIO_BLK, the 8250 console, INITRD and DEVTMPFS_MOUNT, but no FUSE or VIRTIO_FS. Firecracker
  appends its own `pci=off` and two `virtio_mmio.device=4K@0x...` parameters to the command line, and kernel A
  finds the MMIO devices from them (CI: `fc` row's `cmdline`). The bucket's
  `v1.17` folder is empty and new folders there are date-stamped CI artifacts, not releases: a pin
  on that bucket is a pin on a file, with no upstream promise it stays.
- Kernel B is Cloud Hypervisor's own kernel fork build (ch_defconfig: VIRTIO_MMIO, VIRTIO_PCI, VIRTIO_FS,
  FUSE_FS, VSOCK, VIRTIO_BLK, 8250 console, PVH, ACPI, INITRD, no modules). It is the only input with
  virtio-fs. Cloud Hypervisor v54 needs a host kernel of at least 6.8 (the runner has 7.0).
- virtiofsd: no prebuilt release exists (`virtiofsd_prebuilt=none`). The package is glibc-dynamic. A
  product that wants virtio-fs on Cloud Hypervisor must build or ship virtiofsd itself.
- Sources of truth in the log: `fcch sha256 <name>=`, `fcch versions fc= ch= virtiofsd=` (from `--version`).

## Driving the VMMs from Go

- No cgo, no purego, no shared library: the host side is `os/exec` plus `net/http` (Firecracker's API on a
  unix socket via a custom `DialContext`; about 25 lines). Cloud Hypervisor needs only command-line flags;
  its optional `--api-socket` is not used (`chExtraArgs` is the one place to add it).
- Firecracker: `firecracker --api-sock <dir>/fc.api` (no jailer, default seccomp, no `--enable-pci` so devices
  are MMIO). Config by `PUT /machine-config`, `/boot-source` (kernel, initrd, boot args), `/drives/share`,
  `/vsock` and `/actions` (`InstanceStart`); every call must answer 204. There is no root drive: the initramfs is the root.
  Serial output (ttyS0) is the process's stdout, kept in `console.txt`. Last-resort switch: `fcExtraArgs`
  (`--no-seccomp`, to be recorded if used).
- Cloud Hypervisor: `cloud-hypervisor --kernel K --initramfs I --cmdline ... --cpus boot=2
  --memory size=1024M --disk path=<img>,image_type=raw --vsock cid=3,socket=<dir>/ch.vsock
  --serial file=<dir>/console.txt --console off`. `image_type` is mandatory since v54.
- Both VMMs reach a host listener for guest-initiated vsock at `<vsock socket path>_<port>`; the test
  listens on `<dir>/v.sock_5000` (Firecracker) or `<dir>/ch.vsock_5000` before the VMM starts.
- virtio-fs on Cloud Hypervisor is a second host process: `virtiofsd --socket-path <dir>/fs.sock --shared-dir
  <dir>/work --cache never --sandbox none --seccomp none` first, then `--memory size=1024M,shared=on --fs
  tag=work,socket=<dir>/fs.sock`. virtiofsd exits by itself when Cloud Hypervisor does; the test records when
  (`virtiofsd_exit_ms`) and kills it after 5 s otherwise.
- Every child gets `Pdeathsig=SIGKILL`; each boot has a fresh short directory (unix socket paths stay under 108 bytes).
- Every child's environment holds `FCCH_CANARY=<random>`. The guest reports `env_leak` if it sees the canary
  in its environment or `/proc/cmdline` (I5).
- A failed boot logs `fcch diag ...`: each process's exit status and stderr tail, and the console tail.

## Guest side

- PID 1 is the Go guest, from an initramfs; unknown `key=value` kernel parameters become its environment
  (`wcexit`, `wcshare`; no dots in names). So the transport of parameters is the kernel command line, size-bounded
  and visible to the guest in `/proc/cmdline` (I5 fact, as for libkrun).
- It mounts devtmpfs, proc and sysfs itself and points fds 1 and 2 at `/dev/console`.
- Exit: `wcexit=reboot` is `reboot(RESTART)` for Firecracker (with `reboot=k` on the command line it exits 0);
  `wcexit=poweroff` is `reboot(POWER_OFF)` for Cloud Hypervisor (a guest reset makes it reboot in place by default; its
  ACPI power-off ends the process). The guest never returns from main: on any error it prints and still shuts down.
- `guest_exit=7` reaches the host over vsock only; `vmm_exit` (expected 0 for both) is the VMM's own status.
  exit_path (CI): fc `reboot`, ch-blk and ch-fs `poweroff`; `vmm_exit=0` and `guest_exit=7` on all three rows.

## Network

Neither VMM was given a network device, so the guest sees `lo` only. Facts per row (CI): `loopback=err`
(guest dial to a host 127.0.0.1 listener failed), `ifaces=lo`, `env_leak=no` on all three rows. No TSI-like
mechanism exists in either VMM: vsock is a port map to a host unix socket and nothing else (I2, I3, I4).

## Numbers (hosted CI, 2 vCPU, 1024 MiB)

| Row | boot_ms p50 / min / max | total_ms p50 / min / max | teardown_ms p50 / min / max |
|-----|-------------------------|--------------------------|-----------------------------|
| fc (Firecracker v1.17.0, kernel A, blk-raw) | 194 / 186 / 214 | 197 / 188 / 216 | 501 / 492 / 534 |
| ch-blk (Cloud Hypervisor v54.0, kernel A, blk-raw) | 121 / 109 / 179 | 121 / 109 / 179 | 8 / 5 / 20 |
| ch-fs (Cloud Hypervisor v54.0, kernel B, virtio-fs) | 278 / 256 / 315 | 280 / 257 / 318 | 36 / 31 / 54 |
| libkrun, same gate run | 543 / 533 / 570 | 545 / 536 / 573 | not logged here |
| libkrun, U-100 reference run (commit 6d73de7) | 699 / 676 / 711 | 701 / 679 / 714 | 20 / 18 / 24 |

| Fact | Value |
|------|-------|
| cross rows, one boot, boot_ms / total_ms | `fc-kB` 288 / 291; `ch-blk-kB` 115 / 115 (both ok) |
| `api_ms` (Firecracker, first 204 minus t0), `virtiofsd_ready_ms` (ch-fs) | 1, 1 |
| `vmm_exit`, `guest_exit`, `exit_path` | 0, 7, `reboot` (fc); 0, 7, `poweroff` (ch-blk, ch-fs) |
| `leftover` in the boot directory after exit (I7) | fc: `console.txt, fc.api, share.img, v.sock, v.sock_5000`; ch-blk: `ch.vsock_5000, console.txt, share.img`; ch-fs: `ch.vsock_5000, console.txt, fs.sock.pid, work` |
| after SIGKILL on the VMM: `kill_ms`, `orphans`, `virtiofsd_exit_after_kill_ms` (A9) | fc 19, 0, n/a; ch-blk 11, 0, n/a; ch-fs 16, 0, 18 |
| `virtiofsd_exit_ms` on a normal exit | -32: virtiofsd exited 32 ms before Cloud Hypervisor did (negative means before) |
| `loopback`, `ifaces`, `env_leak` (I4, I5) | `err`, `lo`, `no` on every row |
| `--version` | Firecracker v1.17.0, cloud-hypervisor v54.0, virtiofsd 1.10.0 |
| download_s / gobuild_s / waited_for_libkrun_s / test_s | 1.3 / 8.2 / 51.2 / 89.1 |
| subtest seconds | fc 15.12, ch-blk 3.64, ch-fs 7.14, fc-kB 0.33, ch-blk-kB 0.15 |

Notes for reading the numbers:

- libkrun's numbers in later gates are perturbed: `go test ./spikes/...` runs `libkrun.test` and `fcch.test`
  at once on 4 vCPUs, and fcch downloads about 107 MB and builds Go at that time. U-100's clean
  reference is commit 6d73de7. This test avoids the reverse problem by waiting for `libkrun.test` to end
  before its first timed sample (CI: it waited 51.2 s). In this gate run libkrun printed p50 543 / 545
  (boot / total) against 699 / 701 in its U-100 run, so the runner was faster that day: the spikes' numbers
  compare fairly only within one gate run.
- Firecracker's teardown_ms is about 500 ms (the guest reboot path), against 8 ms for Cloud Hypervisor's
  power-off and 20 ms for libkrun. It adds to every session's end, not to its start.
- `virtiofsd_exit_ms` is virtiofsd's exit minus the VMM's exit: negative means virtiofsd was already gone.
- Both VMMs leave their unix sockets and the share image in the boot directory (`leftover`) but no process
  (`orphans=0` after SIGKILL); the test's cleanup removes the directory.
- Kernel B costs Firecracker about 90 ms more boot (`fc-kB` 288 against `fc` 194) while Cloud Hypervisor is
  unchanged (`ch-blk-kB` 115 against `ch-blk` 121). So the `ch-fs` p50 of 278 comes mostly from virtio-fs
  and virtiofsd, not from the kernel.
- The two kernels differ, so a VMM comparison is only like for like on kernel A (`fc` against `ch-blk`). The
  cross rows show what changing the kernel does on each VMM.
- P1's hosted target (p50 under 2.5 s) is met by every row with a wide margin: total_ms p50 197 (fc), 121 (ch-blk), 280 (ch-fs).

## Sizes and ELF (the A6 answer)

| Binary | Bytes (local) | Bytes (CI) | PT_INTERP | NEEDED |
|--------|---------------|------------|-----------|--------|
| firecracker v1.17.0 | 3676680 | 3676680 | none | none |
| cloud-hypervisor v54.0 | 7365360 | 7365360 | none | none |
| virtiofsd 1.10.0 (package) | n/a | 3152384 | `/lib64/ld-linux-x86-64.so.2` | `libseccomp.so.2, libcap-ng.so.0, libgcc_s.so.1, libm.so.6, libc.so.6` |
| guest | 3548272 | 3548272 | none | none |
| initramfs (guest as `/init`) | 3548512 | 3548512 | | |
| kernel A / kernel B | 44278288 / 48205848 | 44278288 / 48205848 | | |

Both VMMs are static-pie ELF files (`file`: "static-pie linked"), so with them A6's "one static Go binary" holds
for the Go side and the VMM can be fetched by pinned digest and exec'd: no loader, no library search path, nothing like
libkrun's `libkrun.so` plus `libkrunfw.so.5`. Only virtiofsd (needed for virtio-fs) is dynamic.

## Licences

- Firecracker: Apache-2.0 (`LICENSE` and `NOTICE` ship in the tarball). Cloud Hypervisor: Apache-2.0 AND BSD-3-Clause.
  virtiofsd: Apache-2.0 AND BSD-3-Clause. golang.org/x/sys: BSD-3-Clause.
- Both kernels are GPL-2.0-only. Shipping one means the same source duty U-100 noted for libkrunfw. Fetching it
  from upstream by pinned URL and digest (B8 style) redistributes nothing; install then depends on a
  third-party download. Kernel A comes from a CI bucket with no release promise, kernel B from a tagged release.

## Privileges

Only a writable `/dev/kvm`. No root, no capability check, no setuid; Firecracker ran without its jailer here, which
would add root or a user namespace and a chroot. The only `sudo` is the test's `apt-get` for virtiofsd.

## macOS (for U-102 and P6)

Neither Firecracker nor Cloud Hypervisor has a macOS backend (both need KVM, or MSHV on Cloud Hypervisor). If one is
chosen for Linux, macOS needs a different VM layer behind the same backend interface (P6).

## Exit codes and guest shutdown

Firecracker and Cloud Hypervisor both exit 0 on a guest shutdown and carry no guest exit code. The workload's
exit code must travel over vsock or the share, so the host side needs a channel that libkrun gave for free
(libkrun: ioctl 0x7602, then the VMM exits with the code).

## Reversal cost

Firecracker or Cloud Hypervisor, behind one backend package: low to medium. It is exec plus HTTP and flags, with no
cgo and no library to embed, and two pin rows (VMM, kernel). It rises with a dependency on virtio-fs (Cloud Hypervisor
only: a second host process and a binary nobody prebuilds) or on kernel A (an unversioned CI bucket). Replacing
Firecracker with libkrun is the reverse of the cost U-100 noted; Firecracker has no virtio-fs, so a workspace export
through a block device (raw image, no mkfs) would have to be replaced by another route.
