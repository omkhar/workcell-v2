# U-100 spike: libkrun on Linux

Input for ADR-001 (U-103a, "choose the VM layer"). Numbers marked `TBD (CI)` come from the
`libkrun ...` lines that `go test -count=1 -v ./spikes/libkrun/` prints on the hosted
`ubuntu-24.04` runner (4 vCPU, `/dev/kvm` 0666). The authoring session had no `/dev/kvm`.
Facts marked "local" were measured there on linux/amd64 with go 1.27.0 and rustc 1.97.0.

## What the test does

1. Downloads two pinned inputs over HTTPS and checks their SHA-256 (logged before the compare).
2. Builds libkrun from source with the runner's cargo: `cargo build --release --locked`,
   `CARGO_PROFILE_RELEASE_LTO=false CARGO_INCREMENTAL=0`.
3. Builds the guest (static Go, `CGO_ENABLED=0`) and the host child `krunchild` twice
   (`CGO_ENABLED=0` and `=1`), and reads each with `debug/elf`.
4. Boots: A (libkrun defaults, implicit vsock with TSI), B (vsock without TSI, the warm-up),
   one B with the cgo child, 20 timed B boots, and C (no built-in init, Go guest is PID 1).

The guest mounts virtio-fs tag `work`, reads a token, dials a host loopback listener, connects
AF_VSOCK CID 2 port 5000 (mapped by `krun_add_vsock_port` to a host unix socket), sends
`hello <token> loopback=<ok|err>`, writes the host's echo back to `work`, and exits 7.

## Versions and inputs

| Input | Version | Asset | Bytes | SHA-256 |
|-------|---------|-------|-------|---------|
| libkrun source | 1.19.7 (branch `stable-1.19.x`, git `43b2f5aa`) | `https://static.crates.io/crates/libkrun/libkrun-1.19.7.crate` | 31760 | `1610d0669ba96a8de6aee2b3ca1e7436933c77836aca6a2920930907046f4aaa` |
| libkrunfw | 5.6.2, kernel 6.12.109, ABI 5 | `https://github.com/containers/libkrunfw/releases/download/v5.6.2/libkrunfw-x86_64.tgz` | 8655425 | `016c32ddb2a28aa300382cab33352d63a41a901eb36ee8d1ca24b389791c8b91` |
| purego | v0.11.2 | Go module | | go.sum |
| golang.org/x/sys | v0.49.0 | Go module, guest only | | go.sum |

- libkrun `main` is the 2.0 API and incompatible with 1.x; the spike uses 1.19.7.
- Source comes from crates.io, not the GitHub tag archive. The tag archive was refused by the
  authoring session's proxy, so it could not be pinned there. The crate is the better input anyway:
  crates.io publishes its checksum in the index (`cksum` equals the pinned digest), it ships
  `Cargo.lock`, and every `krun-*` sub-crate is pinned `=0.1.0-1.19.7` with a lock checksum.
  GitHub tag archives carry no checksum and are not promised byte-stable.
- libkrunfw: no checksum file, no signature. The tarball holds `lib/x86_64-linux-gnu/libkrunfw.so.5.6.2`
  plus two symlinks; the test extracts that one regular file as `libkrunfw.so.5` and nothing else.
- Ubuntu noble has no libkrun package.

## Loading libkrun from Go

- libkrun 1.19.7 has no `DT_NEEDED` on libkrunfw. `krun_create_ctx` dlopens `libkrunfw.so.5` by soname
  (the name is hard-coded: version coupling, libkrun 1.19 needs libkrunfw ABI 5).
- Pre-loading `<lib>/libkrunfw.so.5` by full path (`RTLD_NOW|RTLD_GLOBAL`) before `<lib>/libkrun.so`
  satisfies the soname lookup. Local: with all config calls made and no `/dev/kvm`,
  `krun_start_enter` got past the libkrunfw check and failed only at KVM creation.
  needs_ld_library_path: TBD (CI; expected `false`).
- Built `libkrun.so`: SONAME `libkrun.so.1`, NEEDED `libgcc_s.so.1, libc.so.6, ld-linux-x86-64.so.2`.
- purego `RegisterLibFunc` binds all twelve functions; `-probe` (create ctx, set 2 vCPU / 1024 MiB)
  printed `ctx=0` locally with both child builds.
- Without `/dev/kvm`, `krun_start_enter` does not return an error: it panics in Rust and the process
  aborts (SIGABRT). A backend must check `/dev/kvm` itself before entering.
- `krun_set_exec` with a NULL `envp` copies the caller's whole environment onto the guest kernel
  command line. Always pass an explicit array (the child passes an empty one). Relevant to I5.

## Guest side

- The init is C (`init/init.c` in crate `krun-init-blob`), built by its build.rs with `cc -O2 -static`
  and embedded in libkrun.so; `krun_set_root` injects it as a virtual `/init.krun` over the root
  virtio-fs, and the kernel gets `init=/init.krun`. Build-time override: `KRUN_INIT_BINARY_PATH`
  replaces the embedded init with any binary, a route to the A6 static Go init.
- init.c mounts devtmpfs, proc, sysfs, cgroup2, devpts, tmpfs itself, brings `lo` up, adds `dummy0`
  only with `tsi_hijack` on the cmdline, reads optional `/.krun_config.json`, forks, and
  `execvp(KRUN_INIT)`. The root needs nothing but the exec target: a static Go binary
  (`guest_bytes` local 3457133, no interpreter, no NEEDED). Works as exec target: TBD (CI).
- Transport: exec path, env and argv travel on the kernel command line:
  `reboot=k panic=-1 panic_print=0 nomodule console=hvc0 rootfstype=virtiofs rw quiet no-kvmapf
  init=/init.krun KRUN_INIT=<path> ... <env> -- <args>`. So they are size-bounded and visible to
  the guest in `/proc/cmdline`.
- Exit code: init records the workload's status with `ioctl(open("/"), 0x7602, code)` on the root
  virtio-fs, then `reboot(RESTART)`; the VMM exits with it. guest_exit_7_host_exit: TBD (CI).
- PID 1 without the built-in init (`krun_disable_implicit_init` before `krun_set_root`; the kernel
  still runs `/init.krun`, so the guest is copied there): pid1_direct TBD (CI), pid1_boot_ms TBD (CI).
  The guest then does the 0x7602 ioctl, `sync` and `reboot` itself.

## Network: TSI

- Default (implicit vsock) enables TSI, which hijacks guest AF_INET sockets and opens them from the
  host process. tsi_default_loopback (guest dial to a host 127.0.0.1 listener): TBD (CI).
- `krun_disable_implicit_vsock` + `krun_add_vsock(ctx, 0)` keeps vsock and the port map with no
  hijack. tsi_off_loopback: TBD (CI; expected `err`).
- So the default must never be used: I2, I3, I4 need TSI off and the A3 host proxy as the only path.

## Numbers (hosted CI, 2 vCPU, 1024 MiB, LTO off)

| Fact | Value |
|------|-------|
| boot_ms p50 / min / max (n=20; first vsock byte minus the child's instant before `krun_start_enter`) | TBD (CI) |
| total_ms p50 / min / max (n=20; first vsock byte minus the instant before `cmd.Start`) | TBD (CI) |
| teardown_ms (child exit minus vsock EOF) | TBD (CI) |
| cargo build seconds | TBD (CI); local 62 s cold registry, 47 s warm |
| download / go build / whole test seconds | TBD (CI) |
| rustc | TBD (CI); local 1.97.0 |

Boot numbers are for a non-LTO libkrun; a release build with upstream's `lto = true` may differ
slightly. P1 asks for p50 under 2.5 s on a hosted runner.

## Sizes and ELF (the A6 answer)

| Binary | Bytes (local) | Bytes (CI) | PT_INTERP | NEEDED |
|--------|---------------|------------|-----------|--------|
| krunchild, `CGO_ENABLED=0` (purego) | 2740174 | TBD | `/lib64/ld-linux-x86-64.so.2` | `libdl.so.2, libpthread.so.0, libc.so.6` |
| krunchild, `CGO_ENABLED=1` | 2653952 | TBD | `/lib64/ld-linux-x86-64.so.2` | `libc.so.6` |
| guest | 3457133 | TBD | none | none |
| libkrun.so | 5390920 | TBD | | `libgcc_s.so.1, libc.so.6, ld-linux-x86-64.so.2` |
| libkrunfw.so.5 | 21825208 | | | |

With purego (`//go:cgo_import_dynamic` from libc under `!cgo`) or with cgo, the host binary is a
glibc-dynamic ELF with an interpreter, never fully static. It needs `libkrun.so` (soname
`libkrun.so.1`) and `libkrunfw.so.5` beside it or on the loader path. A6's "one static Go binary"
does not hold with libkrun on Linux: the honest form is one Go binary plus two shared libraries,
or the libraries embedded and written out at run time.

## Licences

- libkrun: Apache-2.0. purego: Apache-2.0. golang.org/x/sys: BSD-3-Clause.
- libkrunfw: the wrapper is LGPL-2.1-only; the bundled Linux kernel and patches are GPL-2.0-only.
  Shipping the binary means accompanying it with the corresponding kernel source or a written offer.
- A6/B8: if workcell ships libkrunfw, the project redistributes a GPL kernel and takes on the
  source duty. If the client fetches it from upstream by pinned URL and digest (B8 style), the
  project redistributes nothing, but install then depends on a second upstream artifact.

## Privileges

Only a writable `/dev/kvm`. No root, no capability check, no setuid.

## macOS (for U-102)

libkrun on macOS uses Hypervisor.framework on arm64, in the EFI flavour, and the host binary needs the
`com.apple.security.hypervisor` entitlement. The 1.19.7 source names `libkrunfw.5.dylib` for the
non-EFI macOS build; an `efi` build loads no libkrunfw. Not measured here.

## Reversal cost

Medium: one backend package, the purego dependency, and two pin rows. High only if the workspace
export leans on virtio-fs and the replacement is Firecracker, which has no virtio-fs.
