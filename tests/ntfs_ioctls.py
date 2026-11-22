# SPDX-License-Identifier: GPL-2.0-or-later
"""
Python bindings for the ioctls used by online NTFS defragmentation:
FIEMAP, FS_IOC_GETFSMAP and NTFS_IOC_MOVE_CLUSTERS (fs/ntfs), plus small
helpers (cluster size of an image, drop caches). Stdlib only, so it runs in
the test VM with the host's python3.
"""
import ctypes
import errno
import fcntl
import os
import struct

# --- ioctl numbers (asm-generic encoding, x86_64) --------------------------


def _ioc(direction, typ, nr, size):
    t = ord(typ) if isinstance(typ, str) else typ
    return (direction << 30) | (size << 16) | (t << 8) | nr


def _iowr(typ, nr, size):
    return _ioc(3, typ, nr, size)


FIEMAP_HDR = struct.Struct("=QQIIII")            # struct fiemap (32 bytes)
FIEMAP_EXT = struct.Struct("=QQQQQI12x")         # struct fiemap_extent (56 bytes)
FS_IOC_FIEMAP = _iowr("f", 11, FIEMAP_HDR.size)
FIEMAP_FLAG_SYNC = 0x1
FIEMAP_EXTENT_LAST = 0x1
FIEMAP_EXTENT_UNKNOWN = 0x2
FIEMAP_EXTENT_DELALLOC = 0x4
FIEMAP_EXTENT_ENCODED = 0x8
FIEMAP_EXTENT_NOT_ALIGNED = 0x100
FIEMAP_EXTENT_DATA_INLINE = 0x200
FIEMAP_EXTENT_UNWRITTEN = 0x800

FSMAP = struct.Struct("=IIQQQQ24x")              # struct fsmap (64 bytes)
FSMAP_HEAD = struct.Struct("=IIII48x")           # head without keys (64 bytes)
FSMAP_HEAD_SIZE = FSMAP_HEAD.size + 2 * FSMAP.size
FS_IOC_GETFSMAP = _iowr("X", 59, FSMAP_HEAD_SIZE)
FMR_OWN_FREE = 1
FMR_OWN_UNKNOWN = 2
FMR_OF_SPECIAL_OWNER = 0x10
FMR_OF_LAST = 0x20
FMH_OF_DEV_T = 0x1

MOVE = struct.Struct("=QQQQI12x")                # struct ntfs_move_clusters (48 bytes)
NTFS_IOC_MAGIC = 0xEF
NTFS_IOC_MOVE_CLUSTERS = _iowr(NTFS_IOC_MAGIC, 5, MOVE.size)


def fiemap(fd, start=0, length=(1 << 64) - 1, flags=FIEMAP_FLAG_SYNC, max_extents=None):
    """Return a list of (logical, physical, length, flags) in bytes."""
    out = []
    while True:
        n = 1024 if max_extents is None else max_extents
        buf = bytearray(FIEMAP_HDR.size + n * FIEMAP_EXT.size)
        FIEMAP_HDR.pack_into(buf, 0, start, length, flags, 0, n, 0)
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buf)
        mapped = FIEMAP_HDR.unpack_from(buf, 0)[3]
        last = False
        for i in range(mapped):
            lo, ph, ln, _r1, _r2, fl = FIEMAP_EXT.unpack_from(buf, FIEMAP_HDR.size + i * FIEMAP_EXT.size)
            out.append((lo, ph, ln, fl))
            last = bool(fl & FIEMAP_EXTENT_LAST)
        if last or mapped < n or max_extents is not None:
            return out
        lo, _ph, ln, _fl = out[-1]
        length -= lo + ln - start
        start = lo + ln
        flags &= ~FIEMAP_FLAG_SYNC


def file_runs(fd, cluster, sync=True):
    """
    FIEMAP as merged runs of clusters: sorted list of (vcn, lcn, n). Unmappable
    extents are skipped. FIEMAP works in bytes and may report one cluster in
    two extents (e.g. split at the initialized size), so extents are rounded
    to whole clusters and overlapping or adjacent ones merged.
    """
    raw = []
    for lo, ph, ln, fl in fiemap(fd, flags=FIEMAP_FLAG_SYNC if sync else 0):
        if fl & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_ENCODED |
                 FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_NOT_ALIGNED):
            continue                    # not on clusters of its own (resident, ...)
        v0 = lo // cluster
        v1 = -(-(lo + ln) // cluster)
        l0 = (ph - (lo - v0 * cluster)) // cluster
        raw.append((v0, l0, v1 - v0))
    runs = []
    for v, l, n in sorted(raw):
        if runs:
            pv, pl, pn = runs[-1]
            if v <= pv + pn and l - v == pl - pv:      # same mapping: overlap or adjacent
                runs[-1] = (pv, pl, max(pn, v + n - pv))
                continue
            if v < pv + pn:
                raise RuntimeError(f"FIEMAP maps VCN {v} twice: {runs[-1]} and {(v, l, n)}")
        runs.append((v, l, n))
    return runs


def getfsmap_raw(fd, low=(0, 0, 0, 0, 0), high=None, count=1024, iflags=0, reserved=0,
                 key_reserved=0):
    """One FS_IOC_GETFSMAP call. Keys are (device, flags, physical, owner, offset, length)-ish
    tuples: (device, physical, owner, offset, length). Returns (oflags, entries, records)."""
    if high is None:
        high = (0xFFFFFFFF, (1 << 64) - 1, (1 << 64) - 1, (1 << 64) - 1, 0)
    buf = bytearray(FSMAP_HEAD_SIZE + count * FSMAP.size)
    FSMAP_HEAD.pack_into(buf, 0, iflags, 0, count, 0)
    if reserved:
        struct.pack_into("=Q", buf, 16, reserved)
    for i, key in enumerate((low, high)):
        dev, phys, owner, off, ln = key
        FSMAP.pack_into(buf, FSMAP_HEAD.size + i * FSMAP.size, dev, 0, phys, owner, off, ln)
        if key_reserved:
            struct.pack_into("=Q", buf, FSMAP_HEAD.size + i * FSMAP.size + 40, key_reserved)
    fcntl.ioctl(fd, FS_IOC_GETFSMAP, buf)
    _if, oflags, _cnt, entries = FSMAP_HEAD.unpack_from(buf, 0)
    recs = []
    for i in range(min(entries, count)):
        recs.append(FSMAP.unpack_from(buf, FSMAP_HEAD_SIZE + i * FSMAP.size))
    return oflags, entries, recs


def getfsmap(fd, batch=4096):
    """All records as (physical, length, owner, flags), following fsmap_advance()."""
    out = []
    low = (0, 0, 0, 0, 0)
    while True:
        _of, entries, recs = getfsmap_raw(fd, low=low, count=batch)
        for dev, flags, phys, owner, off, ln in recs:
            out.append((phys, ln, owner, flags))
        if not recs or recs[-1][1] & FMR_OF_LAST:
            return out
        dev, flags, phys, owner, off, ln = recs[-1]
        low = (dev, phys, owner, off, ln)


def free_extents(fd, cluster):
    """Free space as a sorted list of (lcn, n)."""
    return [(p // cluster, ln // cluster) for p, ln, owner, _f in getfsmap(fd) if owner == FMR_OWN_FREE]


def move_clusters(fd, vcn, lcn, n, flags=0, reserved=0):
    """NTFS_IOC_MOVE_CLUSTERS; returns the number of clusters moved, raises OSError."""
    buf = bytearray(MOVE.pack(vcn, lcn, n, 0, flags))
    if reserved:
        struct.pack_into("=I", buf, 36, reserved)
    fcntl.ioctl(fd, NTFS_IOC_MOVE_CLUSTERS, buf)
    return MOVE.unpack(buf)[3]


def move_errno(fd, vcn, lcn, n, **kw):
    """Like move_clusters() but returns -errno instead of raising."""
    try:
        return move_clusters(fd, vcn, lcn, n, **kw)
    except OSError as e:
        return -e.errno


def image_cluster_size(path):
    with open(path, "rb") as f:
        b = f.read(512)
    sector = struct.unpack_from("<H", b, 11)[0]
    spc = b[13]
    return sector * ((1 << (256 - spc)) if spc > 128 else spc)


def drop_caches():
    os.sync()
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("3\n")


def errname(code):
    return errno.errorcode.get(-code, str(code)) if code < 0 else str(code)
