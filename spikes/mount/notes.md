# U-502a spike: the mount-mode transport (input for ADR-005)

Prototype of option C, FUSE pass-through: the guest init forwards each raw FUSE request from `/dev/fuse` over vsock
and writes each reply back. It parses nothing. The host speaks the FUSE protocol itself against one exported
directory. The authoring session had no `/dev/kvm` and no `/dev/fuse`, so every number comes from the `mount ...` lines
that `go test -count=1 -v ./spikes/...` prints on the hosted runner. See the hosted log of the PR that carries this
spike. The tables below say which key to read. Nothing here was measured in a VM.

## What the test does

1. Downloads the pinned Firecracker v1.17.0, kernel A (6.1.155) and kernel B (`ch-release-v7.2.8-20261009`, FUSE_FS=y)
   in parallel, using the URLs and SHA-256 constants of spikes/netpath and spikes/fcch. It also builds `cmd/guest` as `/init`
   and writes the host tree, 100 dirs x 100 files of 16 bytes, in a TempDir. Then it waits (cap 240 s) for `fcch.test`,
   `libkrun.test` and `netpath.test`. The hard limit is 100 s from the first boot. Reaching it kills the VM and logs
   `hard_limit=reached`, which is not a test failure. Only a changed host tree (`host_tree_intact=false`) fails the test.
   Each guest has 2 vCPU and 1024 MiB on `firecracker.New` with the product's boot args.
2. Kernel A: `features` and one `mount`, for the fact only. Kernel B: `features`, `mount`, then walk_t1, walk_t1_warm,
   write, read, cat, tmpfs, walk_t0 (stopped at 15 s with `walk_t0_ms=partial:<entries>`), rtt, umount. This order puts
   the steps most likely to hang last.
3. Ports: control 5000 (netpath's line protocol), FUSE 5002 (`Machine.Listen`; one connection; the listener is closed
   after accept). Frames are `internal/wire` type 1, one FUSE request or reply each, at most 64 KiB.
4. The mount is `fd=N,rootmode=40000,user_id=0,group_id=0,max_read=61440` on `/workspace`. The INIT reply gives minor
   min(kernel, 37), ASYNC_READ, BIG_WRITES, ATOMIC_O_TRUNC, AUTO_INVAL_DATA, DO_READDIRPLUS (not AUTO), PARALLEL_DIROPS and
   CACHE_SYMLINKS, with max_write 61440 (15 pages: one WRITE or READ is one frame) and max_readahead 131072.
5. Every step is non-fatal. The guest bounds each one at 20 s and then reports `<key>=partial:<progress>`; a failure is
   `<key>=err:<text>`. After a broken or late control reply the host asks nothing more (`<key>=skipped`). On kernel B the
   console tail is always printed. It holds every `/dev/fuse` errno, progress lines (`guest: rtt lstat=1000 open=ok
   fstat=1000`), and a ring of the last 40 forwarded requests, dumped on a partial step, at quit and when the copier ends.

## Keys to read in the log

| Line | Keys | Meaning |
|------|------|---------|
| `mount kernel=A ...` | `cfg_FUSE_FS`, `fuse_dev`, `fuse_mknod`, `fuse_open`, `mount` | Expected `n`, `ENOENT`, `ok`, an errno, `ENODEV` |
| `mount kernel=B ...` | `boot_ms`, `config_gz`, `proc_fs_fuse`, `mount`, `mount_ms`, `mount_stat`; then a line of its own with `fuse_init_minor`, `fuse_init_flags`, `fuse_reply_flags` | kernel B has no `/proc/config.gz` (cfg_* absent); `mount_stat=ok` gates the rest |
| guest step lines | `walk_t1_ms`, `walk_entries` (10100), `walk_t1_warm_ms`, `walk_t0_ms` | WalkDir plus Lstat; timeouts 1 s cold, 1 s warm, 0 after a drop_caches |
| | `rtt_stat_p50_us` (min, max), `rtt_fstat_p50_us` | 1000 Lstat of `d00/f00` and 1000 fstat of it, timeouts 0 |
| | `cat_files` (2000), `cat_ms`, `cat_per_file_us` | open, read, close of d00..d19, timeouts 1 s after a drop |
| | `write_mib` (100), `write_ms`, `write_mib_s`, `write_fsync_ms`, `write_sha256` | 1 MiB writes, then fsync |
| | `read_mib_s`, `read_sha256_match` | after `drop_caches` |
| | `tree_tmpfs_ms`, `walk_tmpfs_ms`, `write_tmpfs_mib_s`, `umount_ms`, `copier_exit` | the guest's own tmpfs baseline; unmount |
| `mount step=<name> ...` | `fs_requests`, `fs_ops=op:N,...`, `fs_errors`, `fs_first_error`, `fs_inflight_peak` | what the host served during that step |
| last line | `fs_nodes_peak`, `fs_open_files_peak`, `host_fds_peak`, `host_bigfile_bytes`, `host_sha256_match`, `host_tree_intact`, `vmm_exit`, `teardown_ms`, `serve_exit`, `prep_s`, `waited_s`, `test_s` | the host's view at the end |

Requests per guest operation come from the step lines. With timeouts 0, one Lstat of `d00/f00` costs a LOOKUP of `d00`, a
LOOKUP of `f00` and probably a GETATTR. One fstat costs one GETATTR. So `rtt_fstat_p50_us` is the per-request floor.

## Sizes (wc -l, this spike)

| File | Lines | What |
|------|-------|------|
| `serve/serve.go` | 846 (769 without blanks and comments) | the host server: about 100 of those lines are spike counters |
| `fuse/fuse.go` | 516 | opcodes, decoder (the T5 fuzz target), encoders, the request ring; `Copy`, the guest copier, is 49 lines |
| `cmd/guest/main.go` | 534 | PID 1. The product part is `mountFUSE` (40 lines) plus `Copy`; the rest is measurement |

go-fuse v2.12.1 (BSD-3-Clause; fetched into a scratch module, never into go.mod), non-test lines: `fuse` 7731 (6929
without the darwin and BSD files), `fs` 5564 (5362). Their imports add about 950 more lines from its `internal/...` and
`splice` packages. go-fuse's own go.mod requires `golang.org/x/sys`, `golang.org/x/sync`, `github.com/moby/sys/mountinfo`
and `github.com/kylelemons/godebug`. So option B is one direct dependency, but more than one module in go.sum. Option C
adds none.

## Shape of the host server (what U-502b inherits)

- Node = (parent node, name, kind, a directory's own descriptor), and node 1 = the export opened
  `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`. Every syscall is `*at` on a parent's descriptor with `AT_SYMLINK_NOFOLLOW` or
  `O_NOFOLLOW`. There is no `O_PATH`, `/proc/self/fd` or `AT_EMPTY_PATH`, so the same calls exist on macOS. OPEN of a
  symlink node is ELOOP. Mode changes go through `fchmod` on an fd opened `O_NOFOLLOW`, so a chmod of a symlink is EPERM.
- Names are refused before any syscall: empty, `.`, `..`, `/`, NUL, or over 255 bytes is EINVAL. A request whose
  length or fixed-size arguments are wrong is EINVAL. Under 40 bytes, or a frame of another type, is counted and
  dropped.
- Lookups are counted, and FORGET and BATCH_FORGET drop nodes. A node keeps its parent while it has children. RENAME
  moves the node. UNLINK, RMDIR and replacement detach it (a stale node is ENOENT unless it is used by its open handle).
- Concurrency: 16 requests at once, replies out of order under one write mutex. One RWMutex is held for writing only
  where a descriptor may close (FORGET, RELEASE), so no request can use a reused fd number. The guest can make the
  host hold at most 4096 descriptors (ENFILE beyond that, I10). The node count has no cap yet.
- Not implemented (ENOSYS): LINK, MKNOD, xattrs, locks, FALLOCATE, LSEEK, RENAME2 with flags, COPY_FILE_RANGE.
  uid and gid are reported as 0, and chown is EPERM. chmod or truncate of a file the host user cannot open fails.
- Errors are Linux errno values. A macOS host must translate its errno numbers and its `Stat_t` and `Statfs_t` layouts.

## Checked without a VM (pure tests, every platform)

Struct sizes and field offsets against fuse.h v6.1, the INIT reply, name refusal and a decoder table. FuzzRequest ran
for 20 s locally with no failure. On Linux, TestRoundTrip plays the kernel over `net.Pipe`: INIT, LOOKUP, GETATTR, OPEN,
READ, CREATE, WRITE, a symlink out of the export (ELOOP on open, EPERM on chmod, target unchanged), MKDIR, RENAME,
SETATTR, READDIRPLUS paging, UNLINK, RMDIR, STATFS, ENOSYS, malformed requests and the no-reply opcodes. All reply
lengths are checked. A throwaway run of `Copy` over a SEQPACKET socketpair, deleted afterwards, carried 61520-byte WRITE
frames and answered an oversized request E2BIG.

## Surprises

- The first hosted run (commit 97e255d) hung in `rtt` at its first `os.Open` of a regular file on the mount. The host
  saw OPEN, one FUSE_POLL (opcode 40, answered ENOSYS), four INTERRUPTs and then nothing. Cause: an `*os.File` adds its
  descriptor to the Go runtime's epoll set. On a FUSE file, `epoll_ctl` sends FUSE_POLL. The runtime makes that call
  itself, not as a syscall, so the thread blocks in the kernel holding its P. A stop-the-world GC then waits for that P,
  while the goroutine that would deliver the reply is parked. The process that serves a FUSE mount deadlocked by
  touching it. (Directories have no poll method, so `filepath.WalkDir` was safe.) Rule for U-502b: the guest init never
  opens a file on its own mount through `os`, or the copier lives in a process that never touches the mount. This
  spike's guest now does every operation on the mount through raw `unix.*` syscalls.
- Kernel B has no `IKCONFIG_PROC`. `/proc/filesystems` is the fact it gives (`proc_fs_fuse`).
- Same run, before the hang: `walk_t0` (timeouts 0) took 30857 requests in 10.4 s, about 337 us each with 16 in flight.

The open questions only the hosted run answers:
- whether kernel B accepts the INIT reply (`mount_stat`);
- whether readahead stays within `max_read` (`read_sha256_match`);
- the per-request floor over Firecracker's vsock (`rtt_fstat_p50_us`).
