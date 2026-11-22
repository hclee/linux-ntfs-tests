#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Reproducer for writeback reusing a cached mapping after the runlist
changed under it (fs/ntfs, without "ntfs: revalidate the cached writeback
mapping after runlist changes").

ntfs_writeback_range() maps a range once and writes every later dirty folio
of the same writeback pass that falls inside that mapping through it. A
collapse or insert range, a hole punch or a truncate running in the middle
of a pass shifts or frees the clusters, and a folio dirtied again after it
can then be written to the old place.

One file, modelled in memory. Writeback threads loop sync_file_range(WRITE)
over the whole file (WB_SYNC_NONE passes, which pick up folios dirtied after
they started), while the main thread applies random buffered writes,
collapse/insert range, punch hole and truncate to the file and the model.
Every few operations the file is fsynced, its page cache dropped
(POSIX_FADV_DONTNEED) and the contents read back from the disk and compared.

  stale_wb_race.py FILE CLUSTER_SIZE SECONDS [THREADS]

Exit status 1 on the first mismatch (offset and bytes printed), 0 otherwise.
THREADS (default 2) writeback threads; 0 is a control run without them.
Example: python3 stale_wb_race.py /mnt/t/f 4096 60 2
"""
import ctypes
import os
import random
import sys
import threading
import time

if len(sys.argv) < 4 or sys.argv[1] in ("-h", "--help"):
    print(__doc__.strip())
    sys.exit(0 if len(sys.argv) > 1 else 2)
path, cluster, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
threads = int(sys.argv[4]) if len(sys.argv) > 4 else 2
libc = ctypes.CDLL(None, use_errno=True)
libc.sync_file_range.argtypes = [ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong, ctypes.c_uint]
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
SYNC_FILE_RANGE_WRITE = 2
FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE = 0x01, 0x02
FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE = 0x08, 0x20


def fallocate(fd, mode, off, n):
    if libc.fallocate(fd, mode, off, n):
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


rnd = random.Random(int(os.environ.get("SEED", "1")))
unit = max(cluster, 4096)
size = 4096 * unit if unit <= 4096 else 512 * unit
model = bytearray(rnd.randbytes(size))
fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, model)
os.fsync(fd)
stop = threading.Event()


def syncer():
    while not stop.is_set():
        libc.sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE)


ts = [threading.Thread(target=syncer, daemon=True) for _ in range(threads)]
for t in ts:
    t.start()
ops = {"write": 0, "collapse": 0, "insert": 0, "punch": 0, "truncate": 0, "check": 0}
unsupported = set()
end = time.time() + seconds
bad = None
step = 0
while time.time() < end and bad is None:
    step += 1
    kind = rnd.choices(["write", "collapse", "insert", "punch", "truncate"], [8, 2, 2, 2, 1])[0]
    cur = len(model)
    try:
        if kind == "write":
            for _ in range(rnd.randrange(1, 16)):
                off = rnd.randrange(max(cur, 1))
                data = rnd.randbytes(rnd.randrange(1, 4 * unit))
                os.pwrite(fd, data, off)
                if off + len(data) > len(model):
                    model.extend(bytes(off + len(data) - len(model)))
                model[off:off + len(data)] = data
        elif kind in ("collapse", "insert", "punch") and kind not in unsupported:
            nclu = cur // cluster
            if nclu < 8:
                continue
            a = rnd.randrange(nclu - 4) * cluster
            n = rnd.randrange(1, min(64, nclu - a // cluster - 1)) * cluster
            if kind == "collapse":
                fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, a, n)
                del model[a:a + n]
            elif kind == "insert":
                fallocate(fd, FALLOC_FL_INSERT_RANGE, a, n)
                model[a:a] = bytes(n)
            else:
                fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, a, n)
                model[a:a + n] = bytes(n)
        elif kind == "truncate":
            new = rnd.randrange(size // 2, size + size // 2)
            os.ftruncate(fd, new)
            if new < len(model):
                del model[new:]
            else:
                model.extend(bytes(new - len(model)))
        ops[kind] += 1
    except OSError as e:
        if e.errno in (95, 22) and kind in ("collapse", "insert", "punch"):
            unsupported.add(kind)
            print(f"{kind}: {os.strerror(e.errno)}, not used further")
            continue
        raise
    if step % 25 == 0:
        os.fsync(fd)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        got = os.pread(fd, len(model) + 1, 0)
        ops["check"] += 1
        if got != bytes(model):
            i = next((k for k in range(min(len(got), len(model))) if got[k] != model[k]), min(len(got), len(model)))
            bad = f"step {step}: contents differ at {i} (size {len(got)} vs {len(model)}): " \
                  f"got {got[i:i + 16].hex()} want {bytes(model[i:i + 16]).hex()}"
stop.set()
for t in ts:
    t.join()
print(f"ops {ops}, size {len(model)}")
if bad:
    print("STALE:", bad)
    sys.exit(1)
