#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Stale data race between buffered writes into holes and writeback.

    delalloc_zero_race.py PATH CLUSTER SECONDS [FIEMAP_THREADS]

When a buffered write starts or ends inside a cluster that is a hole,
->iomap_begin() turns the cluster into delayed allocation and zeroes the part
of it outside the write in the page cache, so that writeback writes the whole
cluster.  Writeback that runs meanwhile (here: FIEMAP with FIEMAP_FLAG_SYNC
from other threads, i.e. filemap_write_and_wait() without the inode lock)
allocates the delalloc run.  If that makes the zeroing give up, the rest of
the cluster keeps whatever the reused clusters held before, and the file
shows it below initialized_size.

Each round fills the file with a pattern and frees its clusters again
(fsync, truncate to 0, truncate back up), so reallocated clusters hold the
pattern, then writes small pieces into the holes at offsets that are not
cluster aligned, and checks that everything but the pieces reads back as
zeroes, from the page cache and again from disk.  Exit status 1 and the first
bad range on stale data.
"""
import fcntl
import os
import random
import struct
import sys
import threading
import time

path, cs, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
nclu = 48
size = nclu * cs
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 1
stop = threading.Event()


def fiemap_sync():
    hdr = struct.pack("=QQIIII", 0, 0xFFFFFFFFFFFFFFFF, FIEMAP_FLAG_SYNC, 0, 32, 0)
    buf = bytearray(hdr + bytes(56 * 32))
    while not stop.is_set():
        try:
            fd = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            continue
        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, buf)
        except OSError:
            pass
        finally:
            os.close(fd)


def drop_caches():
    os.sync()
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("3\n")


def check(fd, pieces, where):
    data = os.pread(fd, size + cs, 0)
    exp = bytearray(size)
    for off, b in pieces:
        exp[off:off + len(b)] = b
    if data != bytes(exp):
        i = next(i for i in range(min(len(data), len(exp))) if data[i] != exp[i])
        j = i
        while j < len(exp) and j < len(data) and data[j] != exp[j]:
            j += 1
        print(f"{where}: stale data at {i}..{j} (cluster {i // cs}): got {data[i:i + 16].hex()} "
              f"want {bytes(exp[i:i + 16]).hex()}", flush=True)
        return False
    return True


# FIEMAP_THREADS (default 3); 0 is the control run without the race
threads = [threading.Thread(target=fiemap_sync)
           for _ in range(int(sys.argv[4]) if len(sys.argv) > 4 else 3)]
for t in threads:
    t.start()
rnd = random.Random(cs)
end = time.time() + seconds
rounds = 0
ok = True
fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
try:
    while ok and time.time() < end:
        rounds += 1
        os.pwrite(fd, bytes([0xA0 + rounds % 16]) * size, 0)
        os.fsync(fd)
        os.ftruncate(fd, 0)
        os.ftruncate(fd, size)
        pieces = []
        # one write far out first, so the next ones end below
        # initialized_size (the "last cluster" zeroing in ->iomap_begin())
        tail = (size - cs // 2 - 100, bytes([0x5A]) * 100)
        os.pwrite(fd, tail[1], tail[0])
        pieces.append(tail)
        for k in range(1, nclu - 3, 3):
            off = k * cs + rnd.randrange(1, cs)
            n = rnd.choice((rnd.randrange(1, 200), cs + rnd.randrange(1, cs)))
            b = bytes([rnd.randrange(1, 256)]) * n
            os.pwrite(fd, b, off)
            pieces.append((off, b))
        ok = check(fd, pieces, f"round {rounds} cached")
        if ok:
            drop_caches()
            ok = check(fd, pieces, f"round {rounds} after drop_caches")
finally:
    stop.set()
    for t in threads:
        t.join()
    os.close(fd)
print(f"{rounds} rounds, {'ok' if ok else 'STALE DATA'}", flush=True)
sys.exit(0 if ok else 1)
