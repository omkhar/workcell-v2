# U-102 spike: macOS (Virtualization.framework, Apple container, libkrun, vfkit)

Input for ADR-001 (U-103a, "choose the VM layer"), beside `spikes/libkrun/notes.md` (U-100) and
`spikes/fcch/notes.md` (U-101). Every number below comes from the `macos ...` lines that
`go test -count=1 -v ./spikes/macos/` printed on the maintainer's second macOS account, 2026-11-02 about
16:55Z: Apple M2 Max, 12 CPUs, 64 GiB, macOS 27.2 (26B123), `kern.hv_support=1`. TestMacOS PASS in 73.7 s
with a warm cache. Cold downloads: the kernels took `download_s=1.0`, and krunkit (6.4 MB) and vfkit
(66 MB) took a few seconds more on their rows.

These numbers compare with U-101's only within a machine class. U-101 ran on a hosted `ubuntu-24.04`
runner, this on a developer laptop. The P1 target that applies here is the developer-machine target:
p50 under 1.0 s.

## What the test does

1. Skips, with the reason, before any download unless `kern.hv_support` is 1 and `codesign` exists. The
   VM files carry `//go:build darwin && arm64`. So on Linux, and on GitHub's `macos-15` runner (no nested
   virtualisation), only the pure table tests in `pure_test.go` run.
2. Fetches every input into `os.UserCacheDir()/workcell-spike/` and re-hashes it on every use. It logs
   each SHA-256 before it compares it with the pinned constant, and checks the arm64 Image magic
   `ARM\x64` at offset 56 (`kernel_a_magic`, `kernel_b_magic`).
3. Builds the guest (`GOOS=linux GOARCH=arm64 CGO_ENABLED=0`) as `/init` of fcch's newc cpio. It also builds:
   - a `CGO_ENABLED=0` darwin hello (the guest's empty non-Linux main);
   - `vzchild` (cgo, vz v3.8.0);
   - `krunchild` (`CGO_ENABLED=0`, purego).

   Each child is signed on a fresh copy, because re-signing a file that has already run can get it killed.
4. Runs each unsigned child once (`unsigned_err`), then the signed one. If the signed vzchild cannot
   `Validate` or `Start`, the test skips.
5. Rows: each has 1 warm-up, 20 timed boots and 1 SIGKILL boot, with 2 vCPU and 1024 MiB. Only `vz-blk` is
   fatal. Every other row logs `macos fail ...` and the test carries on. The test skips the remaining rows
   once it has run 8 minutes.
   - `vz-blk`: VZ, kernel A, virtio-blk raw image (4 MiB; `<token> <probe>` at 0, echo at 4096, as fcch).
   - `vz-fs`: VZ, kernel B, virtio-fs tag `work` (fcch's three files). It fails, see below.
   - `vz-blk-kB`: cross row, one boot. It fails, see below.
   - `container`: Apple `container` 1.6.1 running busybox by digest. The guest binary sits in a
     bind-mounted directory and runs in `probe` mode.
   - `vz-fs-kC`: VZ, kernel C (the kernel that `container` installs), virtio-fs. This row was added
     because kernel B cannot boot on VZ.
   - `krun-blk`: libkrun 1.19 from krunkit's podman tarball, loaded by purego. It uses kernel A, raw, the
     initramfs and blk-raw.
   - `vfkit-blk`: the signed vfkit v0.6.4 release binary, exec'd. It uses kernel A, the initramfs and blk-raw.

All VMs have a virtio console on `hvc0` written to a file, one virtio-vsock device, the share, and nothing
else: no network device and no entropy device (the guest did not stall, `entropy=none`). The kernel command
line is `console=hvc0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=blk|fs`. libkrun pads it, and the guest
sees it end in `        --`.

vzchild:

- It calls `Validate()` and prints `start_unix_ns` just before `vm.Start()`.
- It listens on vsock port 5000 before `Start`, which works (`listen=before_start`).
- It prints `first_unix_ns` on the first byte, echoes the line and prints `eof_unix_ns` at EOF.
- Then it waits up to 10 s for `VirtualMachineStateStopped` (otherwise `vm.Stop()` and `exit_path=hang`) and
  exits 0. VZ ends the connection and stops the VM almost together, so vzchild waits up to 2 s for EOF after
  `Stopped`.
- Its `-noecho` flag never answers the guest, so the VM stays up for the SIGKILL boot.

krunchild:

- It follows libkrun's `examples/external_kernel.c`. It calls `purego.Dlopen` on `<lib>/libkrun.dylib` by
  full path, then `krun_set_log_level(1)`, `krun_create_ctx` and `krun_set_vm_config(ctx,2,1024)`.
- Then `krun_add_disk(ctx,"share",img,false)`, and `krun_disable_implicit_vsock` plus `krun_add_vsock(ctx,0)`.
  Both symbols resolve (`vsock=explicit`), so there is no TSI.
- Then `krun_add_vsock_port(ctx,5000,<dir>/k.sock)`, `krun_set_console_output` and
  `krun_set_kernel(ctx,kernelA,0 /*RAW*/,initrd,cmdline)`.
- It prints `enter_unix_ns`, then calls `krun_start_enter` on the main thread (`LockOSThread` in `init`).
  There is no `krun_set_root` and no `krun_set_exec`. It booted on the first push.

vfkit, the exact command line (logged as `macos vfkit command=`):

```
vfkit --cpus 2 --memory 1024 --bootloader linux,kernel=<A>,initrd=<I>,cmdline="console=hvc0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=blk"
  --device virtio-blk,path=<dir>/share.img --device virtio-vsock,port=5000,socketURL=<dir>/v.sock
  --device virtio-serial,logFilePath=<dir>/console.txt --restful-uri none://
```

Without `,listen`, vfkit connects to the test's unix socket when the guest connects. That is the direction
this guest needs; `,listen` would make vfkit own the socket for host-initiated connections.

For krun-blk and vfkit-blk the test listens on the unix socket before the exec, as fcch does, and times the
exchange itself.

Definitions, U-101's words:

- t0 is the instant before the first host process starts.
- `total_ms` is the first vsock byte minus t0. It is the P1 number.
- `boot_ms` is the first byte minus the child's instant before `vm.Start` (vzchild) or before
  `krun_start_enter` (krunchild).
- `teardown_ms` is the child's exit minus vsock EOF.
- vfkit and `container` have no separate start step, as with Cloud Hypervisor. For them, `boot_ms` =
  `total_ms`, measured from the instant before `cmd.Start`.
- For `container`, `teardown_ms` is the CLI's exit minus the first byte. It is an upper bound: it includes
  the guest's own run time after its line.

## Inputs

| Input | Source | Bytes | SHA-256 | Licence | Fallback |
|-------|--------|-------|---------|---------|----------|
| Kernel A, 6.1.155 | `https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/aarch64/vmlinux-6.1.155` | 17111552 | `61baeae1ac6197be4fc5c71fa78df266acdc33c54570290d2f611c2b42c105be` | GPL-2.0-only | `vmlinux-5.10.245`, same folder |
| Kernel B, 7.2.8 | `https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v7.2.8-20261009/Image-arm64` | 24177152 | `8f8f3d5a983809f87a4e1e9a13053a3361fda47ef04e09c771a41c5e037cb6c2` | GPL-2.0-only | tags `ch-release-v7.2.8-20261002` (24177152 B, `00343744a98c83267b2b8d159327d441e3f3351076be8355f6f13e08f277fdae`), `ch-release-v6.16.9-20261001` (23595520 B, `613a947e04ea73d9c5a888c2beccff70a2953cf1d3274a2b4ea33ff62761a973`) |
| Kernel C, 6.18.35-197-debug | placed by `container system start --enable-kernel-install`, from `https://github.com/kata-containers/kata-containers/releases/download/3.32.0/kata-static-3.32.0-arm64.tar.zst` (member `opt/kata/share/kata-containers/vmlinux-6.18.35-197-debug`; URL read from the `container` binary) | 30423552 | `fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d` | GPL-2.0-only | none: not downloaded by the test |
| busybox 1.37 image index | `docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` | 9535 (index) | the digest | GPL-2.0 (BusyBox) | `docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f` (3.22) |
| krunkit 1.3.2 podman tarball (libkrun 1.19.0) | `https://github.com/libkrun/krunkit/releases/download/v1.3.2/krunkit-podman-unsigned-1.3.2.tgz` | 6434546 | `de9ab62dd90461cd1df1e37b78e780690d75490f4bab1674cbb4a1f75b90c227` | Apache-2.0 (krunkit, libkrun); libepoxy MIT, virglrenderer MIT, MoltenVK Apache-2.0, EFI firmware (edk2) BSD-2-Clause-Patent | the earlier krunkit tarballs, same URL pattern |
| vfkit v0.6.4 | `https://github.com/crc-org/vfkit/releases/download/v0.6.4/vfkit` (universal Mach-O) | 66431936 | `0ed83fc8ca7aa708598835480dba1362406aa7cd1dab3b27464eb76327d9652d` | Apache-2.0 | v0.6.x, same URL pattern |
| `github.com/Code-Hex/vz/v3` | Go module v3.8.0, cgo and Objective-C | | go.sum | MIT | none named |
| `github.com/Code-Hex/go-infinity-channel` v1.0.0, `golang.org/x/mod` v0.22.0 | indirect, through vz | | go.sum | MIT, BSD-3-Clause | |
| `github.com/ebitengine/purego` v0.11.2 | Go module, already a direct dependency (U-100) | | go.sum | Apache-2.0 | |

- Kernel A: VIRTIO_PCI, VIRTIO_MMIO, VIRTIO_BLK, VIRTIO_CONSOLE (HVC), VIRTIO_VSOCKETS, DEVTMPFS, INITRD. No
  FUSE_FS or VIRTIO_FS. The config sits beside it as `vmlinux-6.1.155.config`.
- The krunkit tarball holds, all unsigned: `bin/krunkit`; `lib/libkrun.dylib` (EFI, GPU, BLK and NET
  build); `lib/libepoxy.0.dylib`, `lib/libvirglrenderer.1.dylib` and `lib/libMoltenVK.dylib`; and
  `share/krunkit/KRUN_EFI.silent.fd`.
  - Every install name is `@rpath/...`, and libkrun.dylib has no LC_RPATH of its own (`libkrun_lc_rpath=none`).
  - `bin/krunkit` carries LC_RPATHs for `/opt/homebrew/lib` and `/opt/podman/lib`.
  - The test extracts regular files only into `krunkit-1.3.2/` beside the tarball, afresh on each run, then:
    - `codesign -s - -f` each dylib;
    - `install_name_tool -add_rpath <lib>` on krunchild and on krunkit (krunkit only for `--version`).
- Direct Go dependencies go from 2 to 3 of 15. `go.mod` holds no `replace`, `exclude` or `ignore`.
- vz requires Go >= 1.25 and macOS >= 12 (most calls >= 11). Its package has no build tag of its own, so
  every file that imports it needs `darwin && cgo`.

## Versions

macOS 27.2 (26B123), Apple M2 Max, go1.27.3 darwin/arm64, Apple clang 21.0.0 (clang-2100.4.1.1), SDK 27.2.

- vz v3.8.0.
- krunkit 1.3.2; libkrun current version 1.19.0 (from `otool -L`). krunkit boots EFI only (its
  `--bootloader` is EFI, per its docs). So on macOS no exec-a-binary model exists for libkrun: it is a
  library, or krunkit with firmware and a disk image.
- vfkit v0.6.4.
- `container` CLI 1.6.1: Homebrew bottle, first on PATH, at `/opt/homebrew/Cellar/container/1.6.1`. Apple's
  own pkg `com.apple.container-installer` 1.1.0 is also installed, in `/usr/local`, and was not run. Only
  its signatures were read.

## Numbers (developer Mac, 2 vCPU, 1024 MiB)

| Row | boot_ms p50 / min / max | total_ms p50 / min / max | teardown_ms p50 / min / max |
|-----|-------------------------|--------------------------|-----------------------------|
| vz-blk (VZ, kernel A, blk-raw) | 224 / 215 / 331 | 248 / 231 / 363 | 1 / 0 / 96 |
| vz-fs (VZ, kernel B, virtio-fs) | fails: kernel B does not boot on VZ | | |
| vz-blk-kB (VZ, kernel B, blk-raw, one boot) | fails: same | | |
| vz-fs-kC (VZ, kernel C, virtio-fs) | 229 / 212 / 319 | 240 / 222 / 332 | 27 / 22 / 40 |
| container (Apple container 1.6.1, busybox, bind mount) | 559 / 527 / 795 | 559 / 527 / 795 | 117 / 80 / 145 (upper bound) |
| krun-blk (libkrun 1.19.0 via purego, kernel A, blk-raw) | 55 / 37 / 70 | 71 / 50 / 87 | 0 / 0 / 2 |
| vfkit-blk (vfkit v0.6.4, kernel A, blk-raw) | 269 / 224 / 566 | 269 / 224 / 566 | 0 / 0 / 188 |

- P1, developer-machine target (p50 under 1.0 s): every row that boots meets it.
- libkrun is the fastest by far. Its VM runs inside krunchild on Hypervisor.framework: no XPC helper and no
  framework VM setup. The run before the final one gave krun-blk boot p50 34 and total p50 46.
- Every VZ row pays for the creation of an XPC helper process: vz-blk, vz-fs-kC, vfkit and container's VM.
  vfkit (exec of a 66 MB binary, then vz) costs about 10 to 20 ms more than vzchild.
- teardown_ms is bimodal on the VZ rows: about 1 ms or about 100 ms.
- Run to run on this Mac, p50 total_ms moved by about 10%:
  - vz-blk: 232 to 248;
  - vz-fs-kC: 206 to 240;
  - container: 559 to 594;
  - krun-blk: 46 and 71;
  - vfkit-blk: 245 and 269.

## Facts

| Fact | Value |
|------|-------|
| `loopback`, `ifaces`, `env_leak` (I4, I5) | VZ, krun and vfkit rows: `err`, `lo`, `no`. container: `err`, `eth0,lo`, `no` |
| default gateway seen by the guest (read from `/proc/net/route`, never dialled) | VZ, krun, vfkit: `none`. container: `192.168.64.1` (vmnet NAT) |
| `guest_exit`, `vmm_exit`, `exit_path` | VZ, krun, vfkit: 7 over vsock, 0, `poweroff`. container: 7 in the hello line, CLI exit 7 |
| does `wcexit=poweroff` stop the VM? | yes, on VZ, libkrun and vfkit: `reboot(POWER_OFF)` (PSCI off) ends it. No reboot path is needed. libkrun then exits the process with 0 |
| libkrun vsock | `vsock=explicit`: the implicit vsock (with TSI) is disabled, so port 5000 is only a map to `<dir>/k.sock` |
| `leftover` in the boot directory (I7) | vz-blk `console.txt,share.img`. vz-fs-kC `console.txt,work`. krun-blk `console.txt,k.sock,share.img`. vfkit-blk `console.txt,share.img,v.sock`. Only the test's own listener sockets remain |
| helper processes after a normal exit (I7) | `helper_procs=0->0` on every VZ row: the VZ helper is gone by the time the child has exited |
| container residue after `--rm` | `container ls -a` is `[]` |
| SIGKILL on vzchild or vfkit (A9) | `kill_ms` 0 to 1. `orphans=0` 2 s later, `method=lsof`. The share was held by `com.apple.Virtualization.VirtualMachine`, whose parent is launchd (`ppid=1`), not the child |
| SIGKILL on krunchild (A9) | `kill_ms=1`, `orphans=0`, `method=lsof`. The share was held by `krunchild` itself (in-process VM) |
| SIGKILL on the `container` CLI (A9) | `after_kill=running`, `orphans=2` (one `container-runtime-linux` and one VZ helper, `method=count`). `container rm -f` took 161 ms |
| processes during a container run | `container-apiserver`, `container-core-images`, `container-network-vmnet`, `machine-apiserver`, `container-runtime-linux`, `com.apple.Virtualization.VirtualMachine`, each with `ppid=1` |
| launchd | `launchctl print gui/502/com.apple.container.apiserver`: exit 113 "Bad request". `user/502/...`: present, its plist in `~/Library/Application Support/com.apple.container/apiserver/` |
| `container system start` | `apiserver_was_running=false`, `started_by_test=true`, `system_start_s` 0.4 to 1.6 with the kernel already installed (13 s by hand the first time, kernel download included). The test runs `container system stop` at the end |
| container guest kernel command line | `console=hvc0 tsc=reliable panic=0 oops=panic lsm=lockdown,capability,landlock,yama,apparmor init=/sbin/vminitd ro rootfstype=ext4 root=/dev/vda` |

### Kernel B on Virtualization.framework

Three Cloud Hypervisor arm64 builds were tried: v7.2.8-20261009, v7.2.8-20261002 and v6.16.9-20261001.

- Usually `vm.Start()` fails with `VZErrorDomain Code=1 "Internal Virtualization error. The virtual machine
  failed to start."`, before any console output, even with an empty initrd (tried by hand).
- Once, in the final run's `vz-blk-kB`, the VM reached `Running` and then went to `Error` about 2 s later,
  still with no console output.
- Their Image headers match kernel A's: same flags (LE, 4K pages), same PE/COFF stub.
- Kernel A and kernel C both boot. Kernel A also boots unchanged under libkrun and vfkit.
- The unified log is not readable from this account, so the cause is not known.

For ADR-001 this means that on VZ, Cloud Hypervisor's kernel cannot be shared with Linux. A virtio-fs
kernel for macOS has to come from elsewhere: Kata's, as here, or a build of our own.

## Sizes and links (the A6 answer)

| Binary | Bytes | `otool -L` (arm64 slice; ELF NEEDED for the guest) | Outside `/usr/lib` and `/System/Library` |
|--------|-------|----------------------------|------------------------------------------|
| hello, `CGO_ENABLED=0` darwin | 1815282 | `/usr/lib/libSystem.B.dylib` | none |
| vzchild (cgo, vz) | 5958288 | Foundation, Virtualization, Cocoa, CoreFoundation, Security, AppKit frameworks; `libobjc.A`, `libresolv.9`, `libSystem.B` | none |
| krunchild (`CGO_ENABLED=0`, purego) | 2857696 | `libSystem.B`, `libresolv.9` | none at link time; it dlopens libkrun.dylib |
| libkrun.dylib 1.19.0 (signed ad hoc) | 5488512 | Hypervisor framework, `libiconv.2`, `libSystem.B` | `@rpath/libepoxy.0.dylib`, `@rpath/libvirglrenderer.1.dylib` |
| libepoxy.0.dylib | 2089424 | `libSystem.B` | none |
| libvirglrenderer.1.dylib | 1638832 | `libSystem.B` | `@rpath/libMoltenVK.dylib`, `@rpath/libepoxy.0.dylib` |
| libMoltenVK.dylib | 5091344 | IOSurface, CoreGraphics, AppKit, IOKit, Metal, Foundation, QuartzCore, CoreFoundation; `libc++`, `libobjc`, `libSystem` | none |
| KRUN_EFI.silent.fd (firmware) | 2097152 | | |
| vfkit v0.6.4 (universal: x86_64 and arm64) | 66431936 | Foundation, Virtualization, Cocoa, CoreFoundation, IOKit, Security, AppKit; `libobjc.A`, `libresolv.9`, `libSystem.B` | none |
| guest (linux/arm64 ELF) | 3500141 | none (static) | none |
| `container` (Mach-O behind the bash wrapper on PATH) | 66472096 | 42 entries: libc++, libarchive, Swift runtime, Virtualization, vmnet, ... | `@rpath/libswiftCompatibilitySpan.dylib` |
| `container-runtime-linux` | 62533440 | same set | `@rpath/libswiftCompatibilitySpan.dylib` |
| initramfs / kernel A / kernel B / kernel C | 3500384 / 17111552 / 24177152 / 30423552 | | |

Apple ships no static libSystem, so even the `CGO_ENABLED=0` hello carries `LC_LOAD_DYLIB
/usr/lib/libSystem.B.dylib`. On macOS A6 therefore reads: one Mach-O, nothing third-party beside it, and
`otool -L` lists only `/usr/lib` and `/System/Library`.

- The vz binary meets it: it adds only system frameworks.
- vfkit meets it as a binary, but it is a second Mach-O beside ours.
- libkrun does not: four third-party dylibs (libkrun, libepoxy, virglrenderer, MoltenVK) plus EFI
  firmware, which are 16.4 MB beside krunchild. The GPU stack is there only because krunkit's build
  enables it.
- `container` does not: it is a bash wrapper plus a Mach-O that loads one library through `@rpath`, plus a
  tree of plugin executables and a launchd agent.

## Entitlements and signing

| Binary | Entitlements | Signature |
|--------|--------------|-----------|
| vzchild or krunchild as `go build` leaves it | none | `flags=0x20002(adhoc,linker-signed)`: the Go linker signs ad hoc (`install_name_tool` keeps that) |
| vzchild after `codesign -s - -f --entitlements vz.entitlements` | `com.apple.security.virtualization:true` | `flags=0x2(adhoc)`, no team |
| krunchild after `codesign -s - -f --entitlements hv.entitlements` | `com.apple.security.hypervisor:true` | `flags=0x2(adhoc)`, no team |
| libkrun.dylib and its three dependencies (shipped unsigned) | none | `codesign -s - -f`: `flags=0x2(adhoc)` |
| vfkit v0.6.4 | `com.apple.security.network.client`, `com.apple.security.network.server`, `com.apple.security.virtualization`, all true | `Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)`, `flags=0x10000(runtime)` |
| `container` (Homebrew 1.6.1) | none | ad hoc, no team, not Apple-signed |
| `container-runtime-linux` (Homebrew 1.6.1) | `com.apple.security.virtualization:true` | ad hoc, no team |
| `container` (Apple pkg 1.1.0, `/usr/local/bin`) | none | `Developer ID Application: Apple Inc. - Containerization (UPBK2H6LZM)`, `flags=0x10000(runtime)` |
| `container-runtime-linux` (Apple pkg 1.1.0) | `com.apple.security.virtualization:true` | same Developer ID, hardened runtime |

- vzchild unsigned fails at `Validate()`, before any VM exists: `validate: Error Domain=VZErrorDomain
  Code=2 "Invalid virtual machine configuration. The process doesn't have the
  "com.apple.security.virtualization" entitlement."`.
- krunchild unsigned fails inside `krun_start_enter`: `Building the microVM failed:
  Internal(Vm(VmSetup(VmCreate)))`, `start_enter=-22`. Every earlier call succeeds.
- Signed, both boot. `com.apple.security.virtualization` and `com.apple.security.hypervisor` are Boolean
  entitlements and need no approval from Apple. An ad hoc signature with the plist is enough for a
  developer build and for this suite. No certificate and no root are needed.
- `com.apple.vm.networking` is restricted, and it is not needed: there is no network device (A3 puts the
  network on the host proxy anyway). Apple signs its own runtime with only the virtualization
  entitlement, plus hardened runtime. vfkit adds the two network entitlements for its own networking.
- A notarised release needs a Developer ID Application certificate, hardened runtime, a secure timestamp
  and the entitlements as an ASCII plist. H-703 does that work. This spike only records it.

## Apple container: architecture and the A9 result

- There is one VM per container, run through Apple's Swift `Containerization` package. The guest's PID 1
  is `vminitd` (`init=/sbin/vminitd` on the kernel command line), and it is driven over vsock. The kernel
  comes from Kata (above). Bind mounts are virtio-fs (`"type":{"virtiofs":{}}` in `container ls --format
  json`), and the network is vmnet NAT (`eth0`, gateway 192.168.64.1).
- The CLI talks XPC to `container-apiserver`, a launchd agent in `user/<uid>`. The wire protocol is not
  documented. So a Go program has no supported path except exec of the CLI. The Homebrew CLI on PATH is
  itself a bash script that execs the Mach-O.
- The agent and its plugins outlive the session: launchd is the parent of every one of them, and of the
  per-container runtime and VM helper. When the CLI dies, the container keeps running (`after_kill=running`).
  It takes a second command (`container rm -f`) to clean up. This is the measured A9 answer: A9 fails by
  construction.
- P3 also fails by construction: it needs a separate install (Apple pkg or Homebrew) and a kernel download
  on first `system start`.
- Pulling the image needed the network and Docker Hub. The first `run` also fetched an init image (about
  66 MB).

By contrast, the VMs of vzchild, vfkit and krunchild all died with their process: `orphans=0` 2 s after
SIGKILL. That holds even though the VZ helper's parent is launchd.

## Licences

- Kernels A, B and C: GPL-2.0-only, with the source duty U-100 and U-101 noted.
- vz and go-infinity-channel: MIT. golang.org/x/mod: BSD-3-Clause. purego: Apache-2.0.
- libkrun and krunkit: Apache-2.0. libepoxy: MIT. virglrenderer: MIT. MoltenVK: Apache-2.0. The EFI firmware
  is edk2-based, BSD-2-Clause-Patent. These licences are upstream's; the tarball carries no licence files.
- vfkit: Apache-2.0.
- Apple container: Apache-2.0 (`LICENSE` in the Cellar). BusyBox: GPL-2.0.

## Privileges

- No root anywhere. VZ and vfkit need only `com.apple.security.virtualization`. libkrun needs only
  `com.apple.security.hypervisor`, plus signatures on its dylibs. Ad hoc is enough for both, without
  hardened runtime.
- A notarised libkrun build needs hardened runtime, and with it library validation. That means either
  `com.apple.security.cs.disable-library-validation` on the host binary, or all four dylibs re-signed with
  the same Team ID as the binary.
- `container system start --enable-kernel-install` asked for nothing: no password and no prompt. Without
  the flag it would prompt for the kernel install. It registers launchd agents in `user/<uid>`.

## Reversal cost

- vz binding: low to medium.
  - One backend package and one direct dependency (cgo plus Objective-C, darwin only, behind a build tag).
  - One signing step: an ad hoc plist for developers, Developer ID for release.
  - Everything else is shared with Linux: the guest, the initramfs, vsock and blk-raw. Kernel A boots
    unchanged on VZ.
  - The virtio-fs kernel needs a different source than Cloud Hypervisor's.
- vfkit: low.
  - One pinned 66 MB binary, signed by Red Hat (Developer ID, hardened runtime), behind an exec model with
    flags and a unix socket. This is the macOS twin of Firecracker or Cloud Hypervisor for ADR-001's A7
    comparison.
  - No cgo and no signing of our own for the VM part.
  - It is a second Mach-O to fetch by digest (P3 still holds: it is a download, not an install). It
    measures the same as vz underneath, plus about 10 to 20 ms.
- libkrun on macOS: medium to high.
  - purego (no cgo) plus four third-party dylibs, the EFI firmware and two kinds of signing (the
    hypervisor entitlement, and the dylibs signed by us).
  - Only krunkit's podman tarball ships it prebuilt, with a GPU stack the spike does not use.
  - A6 and P3 fail as shipped. It is by far the fastest (total p50 46 to 71 ms), and it shares the
    libkrun API with Linux (U-100).
- Apple container: exec of a CLI that sits behind an Apple pkg or a Homebrew bottle and a launchd daemon.
  - It has no API, and it brings its own guest init, image store and network. A9 and P3 fail by
    construction.
  - Leaving it costs nothing, because nothing would depend on it. Adopting it would mean giving up A2's
    "our guest init", A6 and A9.
