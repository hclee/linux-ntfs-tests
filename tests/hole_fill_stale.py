#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Stale data race between direct I/O or mmap writes into holes and readers.

    hole_fill_stale.py MNT CLUSTER SECONDS dio|buffered|mkwrite [READERS]

Direct I/O writes and write faults into a hole allocate clusters right away
(ntfs_attr_map_cluster() from ->iomap_begin()), and writeback allocates the
delalloc run of a buffered write.  If the new cluster numbers are visible in
the runlist before the clusters are zeroed or written on disk, a reader that
is not serialised by the inode lock (page faults on another mapping, splice)
maps them and reads whatever the reused clusters held, and the page cache can
keep that copy.

Each pass fills the free space with a marker file (bytes 0xEE), deletes it,
and creates a sparse file T (16 MiB of holes below initialized_size).  A
writer process then fills the holes piece by piece, each piece with a byte of
its own (never 0xEE):
  dio      O_DIRECT pwrite() of 1-8 clusters at a 4 KiB aligned offset that is
           not always cluster aligned
  buffered the same pieces with buffered pwrite()
  mkwrite  a store into one page of a hole cluster through a shared mapping
READERS processes (default 3) read the cluster range of the piece being
written while it is written, after dropping the clean page cache with
POSIX_FADV_DONTNEED (which also starts writeback of the dirty part), through
a fresh mapping or splice().  The marker byte must never show up: not in a
reader, not in a full read of T after the pass, not after a remount (the
caller remounts and runs this with SECONDS=0 to check only).
Exit status 1 and the first bad range on stale data.
"""
import mmap
import multiprocessing
import os
import random
import sys
import time

MARK = 0xEE
mnt, cs, seconds, mode = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
readers = int(sys.argv[5]) if len(sys.argv) > 5 else 3
T = os.path.join(mnt, "T")
SIZE = 16 << 20
PG = mmap.PAGESIZE
mp = multiprocessing.get_context("fork")


def check_whole(where):
    with open(T, "rb") as f:
        d = f.read()
    i = d.find(bytes([MARK]))
    if i >= 0:
        print("STALE %s: marker at %d (cluster %d)" % (where, i, i // cs))
        return False
    return True


def fill_marker():
    if os.path.exists(T):
        os.unlink(T)
    p = os.path.join(mnt, "marker")
    fd = os.open(p, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    buf = bytes([MARK]) * (1 << 20)
    try:
        while True:
            os.write(fd, buf)
    except OSError:
        pass
    os.fsync(fd)
    os.close(fd)
    os.unlink(p)
    os.sync()


def make_sparse():
    fd = os.open(T, os.O_CREAT | os.O_RDWR, 0o644)
    os.ftruncate(fd, SIZE)
    os.pwrite(fd, b"\x01" * PG, SIZE - PG)
    os.fsync(fd)
    os.close(fd)
    st = os.stat(T)
    if st.st_blocks * 512 > SIZE // 4:
        print("setup: T is not sparse (st_blocks %d)" % st.st_blocks)
        sys.exit(2)


def reader(cur, stop, bad):
    fd = os.open(T, os.O_RDONLY)
    rp, wp = os.pipe()
    n = 0
    while not stop.value:
        off, ln = cur[0], cur[1]
        if ln == 0:
            continue
        os.posix_fadvise(fd, off, ln, os.POSIX_FADV_DONTNEED)
        if n & 1:
            # mmap() needs a page aligned offset; 512 byte clusters are not
            a = off & ~(mmap.PAGESIZE - 1)
            m = mmap.mmap(fd, ln + off - a, mmap.MAP_SHARED, mmap.PROT_READ, offset=a)
            d = m[off - a:]
            m.close()
        else:
            d = b""
            o = off
            while len(d) < ln:
                k = os.splice(fd, wp, min(ln - len(d), 65536), offset_src=o)
                if k <= 0:
                    break
                o += k
                d += os.read(rp, k)
        n += 1
        i = d.find(bytes([MARK]))
        if i >= 0:
            bad.value = off + i
            stop.value = 1
            print("STALE reader: marker at %d (cluster %d), %d reads" % (off + i, (off + i) // cs, n))
    os.close(fd)


def writer_dio(cur, stop, deadline):
    fd = os.open(T, os.O_RDWR | (os.O_DIRECT if mode == "dio" else 0))
    nclu = (SIZE - PG) // cs
    holes = list(range(nclu))
    random.shuffle(holes)
    done = set()
    buf = mmap.mmap(-1, 8 * cs)
    val = 1
    rounds = 0
    for c in holes:
        if stop.value or time.time() > deadline:
            break
        if c in done:
            continue
        n = 1
        while n < 8 and c + n < nclu and c + n not in done:
            n += 1
        n = random.randint(1, n)
        start = c * cs
        if cs > PG and random.random() < 0.5:
            start += random.randrange(0, cs, PG)	# not cluster aligned
        ln = (c + n) * cs - start
        if cs > PG and n > 1 and random.random() < 0.5:
            ln -= random.randrange(0, cs, PG)	# end inside a cluster
        val = val % 250 + 1
        if val == MARK:
            val += 1
        buf[:ln] = bytes([val]) * ln
        cur[0] = c * cs
        cur[1] = n * cs
        os.pwrite(fd, memoryview(buf)[:ln], start)
        cur[1] = 0
        done.update(range(c, c + n))
        rounds += 1
    os.close(fd)
    return rounds


def writer_mkwrite(cur, stop, deadline):
    fd = os.open(T, os.O_RDWR)
    m = mmap.mmap(fd, SIZE, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    nclu = (SIZE - PG) // cs
    holes = list(range(nclu))
    random.shuffle(holes)
    val = 1
    rounds = 0
    for c in holes:
        if stop.value or time.time() > deadline:
            break
        val = val % 250 + 1
        if val == MARK:
            val += 1
        page = random.randrange(0, max(cs, PG), PG)
        cur[0] = c * cs // PG * PG
        cur[1] = max(cs, PG)
        m[c * cs + page % cs] = val
        cur[1] = 0
        rounds += 1
    m.close()
    os.close(fd)
    return rounds


def main():
    if seconds == 0:
        sys.exit(0 if check_whole("after remount") else 1)
    deadline = time.time() + seconds
    passes = rounds = 0
    ok = True
    while ok and time.time() < deadline:
        fill_marker()
        make_sparse()
        cur = mp.Array("q", 2, lock=False)
        stop = mp.Value("i", 0, lock=False)
        bad = mp.Value("q", -1, lock=False)
        procs = [mp.Process(target=reader, args=(cur, stop, bad)) for _ in range(readers)]
        for p in procs:
            p.start()
        w = writer_mkwrite if mode == "mkwrite" else writer_dio
        rounds += w(cur, stop, deadline)
        stop.value = 1
        for p in procs:
            p.join()
        passes += 1
        if bad.value >= 0:
            ok = False
        ok = check_whole("page cache after pass %d" % passes) and ok
    print("%s c%d: %d passes, %d pieces, %s" % (mode, cs, passes, rounds, "ok" if ok else "STALE"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
