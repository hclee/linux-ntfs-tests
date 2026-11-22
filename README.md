# linux-ntfs tests

Tests for the Linux NTFS drivers: the read-write `fs/ntfs` driver
(linkinjeon/ntfs.git, branch `ntfs-next`) and `fs/ntfs3`. Each test boots a
kernel you built in QEMU, makes NTFS volumes, drives the driver into a known
bug and checks the data, the on-disk metadata (`ntfsck`) and the kernel log
(KASAN, lockdep, UBSAN).

Most tests are reproducers of driver bugs: they fail on a kernel without the
fix and pass with it. `tests/expected/ntfs-next.txt` lists what plain
ntfs-next is expected to give, and CI flags any test whose result changes.

## What you need

- x86-64 Linux with KVM access (`/dev/kvm`); root is not needed.
- QEMU (`qemu-system-x86_64`), gcc with a static libc (the VM's init program
  is linked statically), make, cpio, python3, zstd and xz.
- What a kernel build needs (bc, bison, flex, libelf, openssl headers);
  ccache is used when installed.
- ntfs-3g for `mkntfs` and the FUSE driver (several tests cross-check with
  it; Arch Linux ships `mkntfs` in its own `ntfsprogs` package), xfsprogs
  for `xfs_io` and attr for `setfattr`.
- ntfsprogs-plus (<https://github.com/ntfsprogs-plus/ntfsprogs-plus>) for
  `ntfsck` and `ntfsinfo`, in `PATH` or named by `NTFSCK` and `NTFSINFO`.
  The expected results were made with ntfs-3g's mkntfs; install
  ntfsprogs-plus under its own prefix if its mkntfs should not take over.
- Optional: an xfstests checkout with fsx built (`XFSTESTS=/path/to/xfstests`)
  for `fsx_parallel`, and with `src/log-writes/replay-log` for the crash suite.

Debian or Ubuntu (Ubuntu 26.04 is tested in CI):

```bash
sudo apt install qemu-system-x86 gcc make libc6-dev cpio python3 zstd xz-utils \
    bc bison flex libelf-dev libssl-dev ccache perl kmod dwarves ntfs-3g xfsprogs \
    autoconf automake libtool pkg-config libblkid-dev uuid-dev libgnutls28-dev \
    libgcrypt20-dev git attr
```

Arch Linux (tested in CI):

```bash
sudo pacman -S --needed qemu-base gcc make cpio python zstd xz bc bison flex libelf \
    openssl ccache perl kmod pahole ntfs-3g ntfsprogs xfsprogs autoconf automake libtool pkgconf \
    util-linux-libs gnutls libgcrypt git attr
```

ntfsprogs-plus from source:

```bash
git clone --depth 1 https://github.com/ntfsprogs-plus/ntfsprogs-plus.git
cd ntfsprogs-plus && ./autogen.sh && ./configure --prefix=/opt/ntfsprogs-plus && make && sudo make install
export NTFSCK=/opt/ntfsprogs-plus/sbin/ntfsck NTFSINFO=/opt/ntfsprogs-plus/bin/ntfsinfo
```

The guest mounts the host's root file system read-only over virtio-9p and
runs the host's own tools (PATH /usr/local/sbin, /usr/local/bin, /usr/bin,
/usr/sbin), so whatever is installed on the host is what the tests use.
`vm/build_kernel.sh` builds in a private mount namespace so ccache results
are shared between source trees; where unprivileged user namespaces are
blocked (Ubuntu 24.04: `kernel.apparmor_restrict_unprivileged_userns=1`) it
builds in place instead.

## Quick start

```bash
git clone --depth 1 --branch ntfs-next https://git.kernel.org/pub/scm/linux/kernel/git/linkinjeon/ntfs.git ../ntfs
vm/build_kernel.sh ../ntfs ../build-ntfs debug
tests/run_reproducers.sh ../build-ntfs /var/tmp/repro | tee /var/tmp/repro.txt
tests/compare_results.py tests/expected/ntfs-next.txt /var/tmp/repro.txt
```

One test:

```bash
tests/run_reproducers.sh ../build-ntfs /var/tmp/repro short_write_size.sh
```

Each test leaves `WORKDIR/<test>/shell.log` (the guest script under `bash
-x`) and `console.log` (the kernel log). `CLUSTERS="512 4096"` limits the
cluster sizes; `MEM`, `SMP` and `TIMEOUT` size the VM; `JOBS=4` runs four
VMs at once. Every script prints
its usage with `--help`.

## Layout

| Path | What |
|---|---|
| `vm/build_kernel.sh` | builds a kernel for the VM: virtio, 9p, loop and ntfs built in, ntfs3 as a module; `debug` adds KASAN, lockdep, UBSAN |
| `vm/run_vm.sh`, `vm/init.c`, `vm/vm_shell.py` | boot the kernel in QEMU and run a guest script as root |
| `vm/check_patches.sh` | per-commit gcc/clang W=1, sparse and checkpatch of a patch series, reporting only what each commit adds |
| `tests/run_reproducers.sh` | runs the reproducers and prints one line per test |
| `tests/run_guest_script.sh` | runs one guest script |
| `tests/run_kernel_tests.sh` | the Python suites for the online defragmentation ioctls (`SUITE=move`, `online`, `crash`) |
| `tests/*.sh` | the guest scripts (reproducers) |
| `tests/*.c` | C helpers, built by `make -C tests` |
| `tests/*.py` | helpers; `ntfsdefrag.py` is an independent NTFS parser and offline defragmenter the suites use to check images |

## Tests

| Test | Checks |
|---|---|
| delalloc_accounting | free space reported by statfs() while delayed allocations are pending, after truncate, unlink and remount |
| delalloc_alloc_failure | a cluster allocation that fails with ENOMEM keeps other files' delalloc reservations |
| delalloc_failed_write | a failed buffered write into a hole releases its reservation |
| delalloc_partial_fail | what a failed unaligned write into a hole leaves allocated |
| delalloc_st_blocks | st_blocks with delayed allocation matches what it is after writeback and remount |
| delalloc_zero_race | writes into holes racing with FIEMAP_FLAG_SYNC writeback never expose old disk contents |
| hole_fill_stale | direct I/O writes and write faults into holes never expose old disk contents |
| short_copy_stale | a buffered write whose copy stops inside a cluster leaves the rest of it zeroed |
| short_write_size | a write that runs out of space does not leave the file size past the bytes written |
| keep_size_short_write | a short write keeps space preallocated with FALLOC_FL_KEEP_SIZE |
| killed_short_write | a writer killed by SIGKILL during its copy (userfaultfd) leaves zeroes, not old data |
| killed_write_mmap | a killed writer on a file with data past its initialized size, with a shared mapping made meanwhile: neither old data nor the mapped page's data lost |
| stale_wb_race | writeback does not write through a mapping cached before collapse/insert range, punch hole or truncate |
| writeback_fragmented_cost | fsync time of a dirty file, contiguous versus 4000 extents (measurement, not pass/fail; not run by default) |
| ntfs_compressed_* | compressed files and directories: fragmented free space, directory operations, stage-by-stage cross-checks with ntfs-3g and ntfs3, reservations and error paths |
| sparse_cu_* | sparse files with unusual compression unit values, including crafted images |
| slab_cache_names | slab cache names stay unique with both NTFS drivers loaded |
| fsx_parallel | xfstests' fsx, several instances in parallel |
| ntfs3_extent_records, ntfs3_readdir_large | fs/ntfs3: attribute lists and extents, large directories (need fs/ntfs3 built as configured by build_kernel.sh) |

The suites run by `tests/run_kernel_tests.sh` need a kernel with the fs/ntfs
online defragmentation series (`NTFS_IOC_MOVE_CLUSTERS`, `FS_IOC_GETFSMAP`);
`SUITE=online` also needs an `ntfsdefrag` build (`NTFSDEFRAG`, and
`NTFSDEFRAG_FI` for its fault-injection build).

## CI

`.github/workflows/ci.yml` lints on Arch Linux, Fedora, Debian testing and
Ubuntu 26.04 on every push and pull request. The `ntfs-next` jobs build
ntfs-next as a debug kernel and run the reproducers under KVM on Arch Linux
and on Ubuntu 26.04, split over four runners per distribution. The results
job of each distribution fails when a result differs from
`tests/expected/ntfs-next.txt`: a regression, or a fix that reached
ntfs-next (then update the file). It runs on pushes to master, on pull
requests, weekly and by hand (workflow_dispatch); changes to Markdown files
alone start nothing. Each runner uploads its test logs as an artifact. At the
time of writing a run with a warm compiler cache takes 15 minutes, most of it
ntfs_compressed_stages, whose run time varies between 5 and 11 minutes from
runner to runner.

## Licence

GPL-2.0-or-later (see `LICENSE`; each file carries an SPDX line), so the
tests can move into xfstests, kernel selftests or ntfsprogs-plus unchanged.
