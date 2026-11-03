# ADR-005: the mount-mode transport

status: proposed

## Context

A5 makes a live mount an explicit `--mount`; A1 trusts nothing in the guest; A6 wants one static init and one host binary; A7 shares
the init across backends and caps the backend at six methods; I1, I10 and I12 bound what the host does for the guest; R6 asks for
descriptor-relative, no-follow handling where the host touches guest-controlled data; P6 adds macOS arm64 on Virtualization.framework.
ADR-001 gave no backend a shared directory and left this transport here. Facts: the pinned kernel A (firecracker-ci v1.14, vmlinux-6.1.155)
has `# CONFIG_FUSE_FS is not set` in the config beside it, no VIRTIO_FS, no NET_9P and NFS_V4 only; Firecracker has no virtio-fs. The spike
(`spikes/mount`, PR #73, commit fe23e90, hosted ubuntu-24.04, the product's firecracker backend, 2 vCPU, 1024 MiB) measured kernel A at
`/dev/fuse` ENODEV and mount ENODEV, then did everything below on kernel B (`ch-release-v7.2.8-20261009`, the URL and SHA-256 that
`spikes/fcch` pinned, FUSE_FS and VIRTIO_FS), which booted in 241 ms against A's 254 ms in the same run. Budgets: 3 of 15 modules, about
8,400 of 15,000 product lines.

## Options

| | (C) pass-through: the init copies raw `/dev/fuse` requests to vsock, the host speaks FUSE | (A) FUSE parsed in the init, an own (handle, name) protocol to the host | (B) go-fuse v2.12.1 in the init, the same own protocol | (D) Cloud Hypervisor virtio-fs with a vhost-user-fs daemon in Go | (E) vz virtio-fs on macOS, (C) on Linux | (F) NFS over the relay | (G) 9P over vsock |
|---|---|---|---|---|---|---|---|
| Guest kernel needs | FUSE_FS: kernel B or C, not A | as (C) | as (C) | VIRTIO_FS: B or C; Linux only, host kernel 6.8, `--memory shared=on` | VIRTIO_FS on arm64: C (B does not boot on VZ, `spikes/macos`) | NFS_V3 absent in A, V4 only | NET_9P absent in A, B unknown |
| Host side; modules; lines | one Go FUSE server, 0 modules; spike 846 (server) + 516 (codec, 49 of them the guest copier) + 40 (mount) lines | server about 450, init about 600; 0 modules | server about 450, init about 300; 1 module (BSD-3-Clause, tagged 2026-10-21, pure Go, mount(2) direct): 7,731 lines in `fuse`, 5,564 in `fs`, plus mountinfo, godebug and x/sync in go.sum | the same FUSE core behind vhost-user and virtqueues in shared memory, about 1,500 lines estimated; a Cloud Hypervisor pin | (C) plus a `virtiofs` branch in the init and a share field in vz's Config; macOS 12+ | no tagged Go NFSv4 server; go-nfs v0.0.4 (2026-04-13) is v3 only | hugelgupf/p9 v0.4.1 (2026-05-15), 1 module; no readdirplus |
| A6, A7, P6 | hold: one init, same bytes on vz; the host is Go on all three hosts and FUSE structs are little-endian on all three | hold | hold; the init carries about 13,000 library lines | A7 fails: no macOS, a second Linux VMM | A7 strained: a backend-specific mount path | hold on paper; the guest meets the host as a network peer on port 2049 | hold |
| Host parser (I12, T5) | the FUSE request decoder: fixed-size arguments, names in nine opcodes only | an own decoder; FUSE parsing sits in the untrusted guest | as (A) | FUSE decoder plus vhost-user and rings | as (C), plus Apple's virtiofs host for the Mac | NFS RPC | 9P |
| Measured | all numbers below | not built: same transport, one parse more | not built: same transport | fcch: boot 280 ms, virtiofsd dynamic, no throughput | macos spike: `vz-fs-kC` boots in 240 ms, no throughput | not built | not built |

## Decision

- Option (C). The init opens `/dev/fuse`, dials host port 5002 (one connection per session, `Machine.Listen` as ADR-003's 5001), mounts
  `fuse` on `/workspace` with `fd=N,rootmode=40000,user_id=0,group_id=0,max_read=61440`, then copies: each read of `/dev/fuse` is one
  request and goes out as one `internal/wire` frame (type 1, the port's only type); each frame back is written to `/dev/fuse` in one
  write (ENOENT means the kernel dropped the request; ENODEV means unmounted). About 90 lines of init, no parsing. A mount session
  passes no workspace disk and the host says so on the command line, as it does for ports.
- The host service, `internal/fileserve` (U-502b), speaks FUSE 7 against the export opened `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`. The FUSE
  grammar is the (handle, name) model: `nodeid` and `fh` are indices into tables the host holds, and a name appears only in LOOKUP,
  CREATE, MKDIR, MKNOD, UNLINK, RMDIR, RENAME, SYMLINK and LINK; empty, `.`, `..`, `/`, NUL or over 255 bytes is EINVAL before any
  syscall. A node is (parent node, name, kind, a directory's own descriptor); every call is `*at` on the parent's descriptor with
  `O_NOFOLLOW` or `AT_SYMLINK_NOFOLLOW`; OPEN of a symlink node is ELOOP; READLINK returns the target as bytes. No `O_PATH`,
  `/proc/self/fd` or `AT_EMPTY_PATH`, so the same calls exist on macOS (which translates errno and `Stat_t`). uid and gid read 0, chown is
  EPERM; xattrs, locks, LINK, MKNOD, fallocate, lseek, copy_file_range, poll and RENAME2 flags are ENOSYS, after which the kernel
  stops asking (one GETXATTR in 1,800 writes). Guest root may speak the protocol itself (A1); every request still meets these tables.
- INIT reply, as measured: minor min(kernel, 37), flags ASYNC_READ, BIG_WRITES, ATOMIC_O_TRUNC, AUTO_INVAL_DATA, DO_READDIRPLUS,
  PARALLEL_DIROPS, CACHE_SYMLINKS (kernel B offered 0x73fffffb, the host answered 0x843029), max_write 61440 so one WRITE or READ is
  one 64 KiB frame, max_readahead 131072. Entry and attribute timeouts are 1 s: a walk of 10,100 entries with `lstat` took 182 ms cold
  (404 requests: 101 OPENDIR, 202 READDIRPLUS, 101 RELEASEDIR) and 139 ms warm, against 7,125 ms over 30,710 requests with timeouts
  0 and 14 ms on the guest's tmpfs. So no batching: the kernel pipelines itself (16 in flight on reads) and the caches remove the one
  case batching would help. A host edit becomes visible within the second, as with NFS; AUTO_INVAL_DATA drops cached pages when
  size or mtime changed. Invalidation pushed from the host waits for a defect.
- Throughput: 100 MiB written at 99.4 MiB/s in 1,800 frames, fsync 486 ms, sha256 equal on the host; read back after `drop_caches` at
  235.8 MiB/s over 2,400 READs; the netpath relay carried 237.7 MiB/s, so the frame size is not the limit. Floor: one GETATTR 208 us p50
  (149 to 627), one `lstat` by name 672 us (three requests). Small files: open, read, close of 2,000 files took 924 us each, five
  requests per file; ENOSYS to FLUSH and FUSE_NO_OPEN_SUPPORT would make it two, to be measured in U-502c, not decided here.
- Bounds (I10, I12): wire frames of 64 KiB under deadlines; lengths and names checked before any syscall; 16 requests in flight;
  descriptors capped at 4096 (ENFILE beyond); U-502b adds a node cap (the walk held 10,102 nodes, 102 descriptors, 2 open files) and
  the T5 fuzz target on the decoder. Mount took 0.8 ms, unmount 33 ms, teardown 41 ms; I7 holds because the export is the session's own.
- The guest init never touches its own mount through the `os` package: an `*os.File` on a FUSE file makes the runtime's poller send
  FUSE_POLL from a thread that holds its P, and the init deadlocked against its own copier (spike, first run). Raw `unix` calls or
  nothing at all; commands run in child processes and are unaffected.
- Kernel pin. Mount mode needs FUSE_FS, which A lacks, and ADR-001 already ruled A out as a B3 pin (no release, no timestamps). amd64
  moves to B, measured here on the product backend at 241 ms boot; arm64, shared by macOS and Linux arm64, needs C (Kata 3.32.0's
  6.18.35, which boots on VZ with virtio-fs, so with FUSE_FS). U-502c moves `escape/sandbox` and the firecracker tests from A to B and
  boots C on Firecracker once, so that one kernel source may serve all three hosts; the `pins/` rows follow ADR-001.
- macOS (P6): the init is the same bytes; the host accepts 5002 from `VirtioSocketDevice.Listen`; nothing else is host-specific. (E) is a
  later `virtiofs` branch in the init's mount function if a Mac number shows vsock's floor hurting, since kernel C has VIRTIO_FS.

## Consequences

- Budget: 0 new modules (still 3 of 15). About 1,200 product lines: host service 700, codec 400 (in two files, under the 800-line cap),
  init 90, one T5 fuzz target; product about 9,600 of 15,000. The kernel pin grows from 44 MB to 48 MB and the gate's VM suite boots B.
- What the guest sees: owner 0:0, no xattrs, local POSIX locks only, host-side edits within a second, fsync at host speed (486 ms for
  100 MiB). `pull` and `diff` refuse a mount session (U-502); `explain` names the export.

## Reversal cost

Low. The init part is 90 lines behind one port. The host service's grammar is the kernel's own, so (A) or (B) change the guest side only:
(B) is go-fuse's RawFileSystem forwarding to the same (handle, name) tables, about 300 lines and 1 module. (D) puts a vhost-user front
(about 1,500 lines, Linux only) on the same FUSE core. (E) is a `virtiofs` branch in the init's mount function and one Config field on
vz. FUSE minors are negotiated down and upstream changes are additive, so a kernel pin move costs a number, not a format.
