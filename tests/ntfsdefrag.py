#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ntfsdefrag.py - offline, in-place NTFS defragmenter for Linux (HDD-oriented).

Unlike the online ntfs3_defrag.py (copy + rename through the kernel driver), this
tool works on an UNMOUNTED volume (block device or image file) and relocates
clusters in place, exactly like Windows' FSCTL_MOVE_FILE does:

  * MFT record numbers (file IDs), hard links, Alternate Data Streams, security
    descriptors, DOS attributes, timestamps, reparse points, EFS/compressed data
    are untouched - only the runlist (VCN -> LCN mapping) of an attribute changes.
  * Placement is exact: the target clusters are chosen by our own allocator, no
    steering of a kernel allocator is involved.
  * Every move is crash-safe: data is copied into FREE clusters and verified, a
    write-ahead journal (stored OUTSIDE the volume) records the old/new MFT records,
    then $Bitmap (new bits) -> MFT record -> $Bitmap (old bits) are written, each
    step flushed. A crash at any point leaves at worst leaked clusters, and
    `ntfsdefrag.py recover` (run automatically) rolls the interrupted group back
    or forward.

Commands:
  analyze  DEV            read-only fragmentation report (default)
  check    DEV            read-only consistency check (runlists vs. $Bitmap)
  defrag   DEV [opts]     defragment (use --dry-run to only simulate)
  recover  DEV            replay/rollback an interrupted run from the journal

Never run it on a mounted volume; it refuses to (O_EXCL + mountinfo check).
"""

from __future__ import annotations

import argparse
import bisect
import ctypes
import errno
import fcntl
import hashlib
import json
import mmap
import os
import signal
import stat
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

VERSION = "1.0"

# --------------------------------------------------------------------------------------
# NTFS constants
# --------------------------------------------------------------------------------------

AT_STANDARD_INFORMATION = 0x10
AT_ATTRIBUTE_LIST = 0x20
AT_FILE_NAME = 0x30
AT_OBJECT_ID = 0x40
AT_SECURITY_DESCRIPTOR = 0x50
AT_VOLUME_NAME = 0x60
AT_VOLUME_INFORMATION = 0x70
AT_DATA = 0x80
AT_INDEX_ROOT = 0x90
AT_INDEX_ALLOCATION = 0xA0
AT_BITMAP = 0xB0
AT_REPARSE_POINT = 0xC0
AT_EA_INFORMATION = 0xD0
AT_EA = 0xE0
AT_LOGGED_UTILITY_STREAM = 0x100
AT_END = 0xFFFFFFFF

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM",
}

MFT_RECORD_IN_USE = 0x0001
MFT_RECORD_IS_DIRECTORY = 0x0002

ATTR_IS_COMPRESSED = 0x0001
ATTR_IS_ENCRYPTED = 0x4000
ATTR_IS_SPARSE = 0x8000

VOLUME_IS_DIRTY = 0x0001

FILE_MFT = 0
FILE_MFTMIRR = 1
FILE_LOGFILE = 2
FILE_VOLUME = 3
FILE_BITMAP = 6
FILE_EXTEND = 11
FIRST_USER_RECORD = 24  # records 0..23 are reserved for metadata

REF_MASK = (1 << 48) - 1

BLKGETSIZE64 = 0x80081272
BLKSSZGET = 0x1268
BLKFLSBUF = 0x1261

MiB = 1024 * 1024
GiB = 1024 * MiB


class NtfsError(Exception):
    pass


def fmt_bytes(n: float) -> str:
    for unit, div in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if abs(n) >= div:
            return f"{n / div:.2f} {unit}"
    return f"{int(n)} B"


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"


# --------------------------------------------------------------------------------------
# Runlists (mapping pairs)
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class Run:
    vcn: int
    length: int
    lcn: Optional[int]  # None = sparse hole

    @property
    def end_vcn(self) -> int:
        return self.vcn + self.length


def decode_mapping_pairs(buf: bytes, pos: int, end: int, start_vcn: int) -> List[Run]:
    runs: List[Run] = []
    vcn = start_vcn
    lcn = 0
    while pos < end:
        hdr = buf[pos]
        if hdr == 0:
            break
        pos += 1
        ln_sz = hdr & 0x0F
        of_sz = hdr >> 4
        if ln_sz == 0 or ln_sz > 8 or of_sz > 8 or pos + ln_sz + of_sz > end:
            raise NtfsError(f"corrupt mapping pairs header 0x{hdr:02x}")
        length = int.from_bytes(buf[pos : pos + ln_sz], "little", signed=True)
        pos += ln_sz
        if length <= 0:
            raise NtfsError("corrupt mapping pairs: non-positive run length")
        if of_sz == 0:
            runs.append(Run(vcn, length, None))
        else:
            lcn += int.from_bytes(buf[pos : pos + of_sz], "little", signed=True)
            pos += of_sz
            if lcn < 0:
                raise NtfsError("corrupt mapping pairs: negative LCN")
            runs.append(Run(vcn, length, lcn))
        vcn += length
    return runs


def _signed_len(v: int) -> int:
    """Minimal number of bytes holding v as a two's complement signed integer."""
    n = 1
    while not (-(1 << (8 * n - 1)) <= v < (1 << (8 * n - 1))):
        n += 1
    return n


def encode_mapping_pairs(runs: Sequence[Run]) -> bytes:
    out = bytearray()
    prev_lcn = 0
    for r in runs:
        ln_sz = _signed_len(r.length)
        if r.lcn is None:
            out.append(ln_sz)
            out += r.length.to_bytes(ln_sz, "little", signed=True)
            continue
        delta = r.lcn - prev_lcn
        of_sz = _signed_len(delta)
        out.append((of_sz << 4) | ln_sz)
        out += r.length.to_bytes(ln_sz, "little", signed=True)
        out += delta.to_bytes(of_sz, "little", signed=True)
        prev_lcn = r.lcn
    out.append(0)
    return bytes(out)


def merge_runs(runs: Iterable[Run]) -> List[Run]:
    out: List[Run] = []
    for r in runs:
        if out:
            p = out[-1]
            if p.end_vcn == r.vcn and (
                (p.lcn is None and r.lcn is None)
                or (p.lcn is not None and r.lcn is not None and p.lcn + p.length == r.lcn)
            ):
                p.length += r.length
                continue
        out.append(Run(r.vcn, r.length, r.lcn))
    return out


def physical_extents(runs: Sequence[Run]) -> List[Tuple[int, int]]:
    """Allocated (lcn, length) extents in VCN order, physically adjacent ones merged."""
    out: List[Tuple[int, int]] = []
    for r in runs:
        if r.lcn is None:
            continue
        if out and out[-1][0] + out[-1][1] == r.lcn:
            out[-1] = (out[-1][0], out[-1][1] + r.length)
        else:
            out.append((r.lcn, r.length))
    return out


# --------------------------------------------------------------------------------------
# Low level device access
# --------------------------------------------------------------------------------------


class Device:
    """Block device or image file, opened exclusively."""

    def __init__(self, path: str, writable: bool, allow_mounted: bool = False) -> None:
        self.path = path
        self.writable = writable
        st = os.stat(path)
        self.is_blockdev = stat.S_ISBLK(st.st_mode)
        flags = os.O_RDWR if writable else os.O_RDONLY
        if allow_mounted and not writable:
            # read-only peek at a mounted volume (used by the online tool)
            self.fd = os.open(path, flags | getattr(os, "O_CLOEXEC", 0))
            self.size = os.lseek(self.fd, 0, os.SEEK_END)
            self.logical_block = 512
            self.align = 512
            self.dfd = -1
            self.direct_ok = False
            return
        if self.is_blockdev:
            # O_EXCL on a block device fails with EBUSY if it is mounted (or opened
            # exclusively by anyone else) and keeps the kernel from mounting it meanwhile.
            flags |= os.O_EXCL
        check_not_mounted(path, st)
        try:
            self.fd = os.open(path, flags | getattr(os, "O_CLOEXEC", 0))
        except OSError as e:
            if e.errno == errno.EBUSY:
                raise NtfsError(f"{path} is in use (mounted?) - unmount it first") from e
            raise
        if not self.is_blockdev:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                raise NtfsError(f"{path} is locked by another process") from e
        if self.is_blockdev:
            buf = bytearray(8)
            fcntl.ioctl(self.fd, BLKGETSIZE64, buf)
            self.size = struct.unpack("<Q", buf)[0]
            b2 = bytearray(4)
            fcntl.ioctl(self.fd, BLKSSZGET, b2)
            self.logical_block = struct.unpack("<I", b2)[0]
        else:
            self.size = st.st_size
            self.logical_block = 512
        self.align = max(512, self.logical_block)
        self.dfd = -1  # O_DIRECT descriptor for bulk copies (lazily opened)
        self.direct_ok: Optional[bool] = None

    def close(self) -> None:
        if self.dfd != -1:
            os.close(self.dfd)
            self.dfd = -1
        os.close(self.fd)

    def pread(self, off: int, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = os.pread(self.fd, n - len(out), off + len(out))
            if not chunk:
                raise NtfsError(f"short read at offset {off + len(out)}")
            out += chunk
        return bytes(out)

    def pwrite(self, off: int, data: bytes) -> None:
        if not self.writable:
            raise NtfsError("internal error: write on read-only device")
        mv = memoryview(data)
        done = 0
        while done < len(mv):
            n = os.pwrite(self.fd, mv[done:], off + done)
            if n <= 0:
                raise NtfsError(f"short write at offset {off + done}")
            done += n

    def flush(self) -> None:
        if self.writable:
            os.fsync(self.fd)
            if self.dfd != -1:
                os.fsync(self.dfd)

    # ---- bulk I/O (O_DIRECT when possible, never pollutes the page cache) ----

    def _direct_fd(self) -> int:
        if self.direct_ok is None:
            self.direct_ok = False
            o_direct = getattr(os, "O_DIRECT", 0)
            if o_direct:
                try:
                    self.dfd = os.open(
                        self.path, (os.O_RDWR if self.writable else os.O_RDONLY) | o_direct
                    )
                    # Probe: some filesystems (tmpfs) accept the flag but fail the I/O.
                    probe = mmap.mmap(-1, 4096)
                    os.preadv(self.dfd, [probe], 0)
                    probe.close()
                    self.direct_ok = True
                except OSError:
                    if self.dfd != -1:
                        os.close(self.dfd)
                    self.dfd = -1
        return self.dfd if self.direct_ok else -1

    def bulk_read_into(self, off: int, view: memoryview) -> None:
        dfd = self._direct_fd()
        n = len(view)
        if dfd != -1 and off % self.align == 0 and n % self.align == 0:
            done = 0
            while done < n:
                got = os.preadv(dfd, [view[done:]], off + done)
                if got <= 0:
                    raise NtfsError(f"short read at {off + done}")
                done += got
            return
        done = 0
        while done < n:
            got = os.preadv(self.fd, [view[done:]], off + done)
            if got <= 0:
                raise NtfsError(f"short read at {off + done}")
            done += got
        try:
            os.posix_fadvise(self.fd, off, n, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass

    def bulk_write_from(self, off: int, view: memoryview) -> None:
        dfd = self._direct_fd()
        n = len(view)
        if dfd != -1 and off % self.align == 0 and n % self.align == 0:
            done = 0
            while done < n:
                w = os.pwritev(dfd, [view[done:]], off + done)
                if w <= 0:
                    raise NtfsError(f"short write at {off + done}")
                done += w
            return
        done = 0
        while done < n:
            w = os.pwritev(self.fd, [view[done:]], off + done)
            if w <= 0:
                raise NtfsError(f"short write at {off + done}")
            done += w


def check_not_mounted(path: str, st: os.stat_result) -> None:
    """Refuse mounted devices and image files attached to a loop device."""
    real = os.path.realpath(path)
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if "-" not in parts:
                    continue
                src = parts[parts.index("-") + 2]
                if src == real or (
                    stat.S_ISBLK(st.st_mode)
                    and parts[2] == f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
                ):
                    raise NtfsError(f"{path} is mounted on {parts[4]} - unmount it first")
    except OSError:
        pass
    if not stat.S_ISBLK(st.st_mode):
        try:
            for name in os.listdir("/sys/block"):
                bf = f"/sys/block/{name}/loop/backing_file"
                if not os.path.exists(bf):
                    continue
                with open(bf, encoding="utf-8", errors="replace") as f:
                    backing = f.read().strip().removesuffix(" (deleted)")
                try:
                    bst = os.stat(backing)
                except OSError:
                    continue
                if (bst.st_dev, bst.st_ino) == (st.st_dev, st.st_ino):
                    raise NtfsError(f"{path} is attached to /dev/{name} - detach it first")
        except OSError:
            pass


# --------------------------------------------------------------------------------------
# MFT records
# --------------------------------------------------------------------------------------


def apply_fixups(buf: bytearray, sector: int, what: str = "record") -> None:
    """Undo the update sequence array in place. Raises on torn/corrupt records."""
    usa_ofs, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt < 2 or usa_ofs + usa_cnt * 2 > len(buf) or (usa_cnt - 1) * sector != len(buf):
        raise NtfsError(f"bad update sequence array in {what}")
    usn = buf[usa_ofs : usa_ofs + 2]
    for i in range(1, usa_cnt):
        end = i * sector - 2
        if buf[end : end + 2] != usn:
            raise NtfsError(f"fixup mismatch (torn write?) in {what}")
        buf[end : end + 2] = buf[usa_ofs + 2 * i : usa_ofs + 2 * i + 2]


def protect_fixups(buf: bytearray, sector: int) -> bytearray:
    """Return an on-disk image of a (fixed-up) record: new USN, sector tails saved."""
    out = bytearray(buf)
    usa_ofs, usa_cnt = struct.unpack_from("<HH", out, 4)
    usn = struct.unpack_from("<H", out, usa_ofs)[0] + 1
    if usn == 0xFFFF or usn == 0:
        usn = 1
    struct.pack_into("<H", out, usa_ofs, usn)
    for i in range(1, usa_cnt):
        end = i * sector - 2
        out[usa_ofs + 2 * i : usa_ofs + 2 * i + 2] = out[end : end + 2]
        struct.pack_into("<H", out, end, usn)
    return out


@dataclass(slots=True)
class AttrSeg:
    """One attribute record (segment) inside one MFT record."""

    rec: int
    offset: int
    type: int
    name: str
    flags: int
    instance: int
    nonresident: bool
    length: int
    lowest_vcn: int = 0
    highest_vcn: int = -1
    mp_offset: int = 0
    comp_unit: int = 0
    alloc_size: int = 0
    data_size: int = 0
    init_size: int = 0
    value: bytes = b""
    runs: List[Run] = field(default_factory=list)


@dataclass(slots=True)
class Record:
    num: int
    flags: int
    seq: int
    base: int  # 0 for base records
    bytes_in_use: int
    bytes_alloc: int
    attrs: List[AttrSeg]


def parse_record(num: int, buf: bytes) -> Record:
    if buf[:4] != b"FILE":
        raise NtfsError(f"MFT record {num}: bad signature {buf[:4]!r}")
    seq, _links, a_off, flags, in_use, alloc = struct.unpack_from("<HHHHII", buf, 16)
    base = struct.unpack_from("<Q", buf, 32)[0] & REF_MASK
    if in_use > len(buf) or alloc != len(buf) or a_off >= in_use:
        raise NtfsError(f"MFT record {num}: bad header sizes")
    attrs: List[AttrSeg] = []
    pos = a_off
    while pos + 8 <= in_use:
        a_type, a_len = struct.unpack_from("<II", buf, pos)
        if a_type == AT_END:
            break
        if a_len < 16 or pos + a_len > in_use or a_len % 8:
            raise NtfsError(f"MFT record {num}: corrupt attribute at 0x{pos:x}")
        nonres, name_len, name_off, a_flags, inst = struct.unpack_from("<BBHHH", buf, pos + 8)
        name = ""
        if name_len:
            name = buf[pos + name_off : pos + name_off + 2 * name_len].decode("utf-16-le", "replace")
        seg = AttrSeg(num, pos, a_type, name, a_flags, inst, bool(nonres), a_len)
        if nonres:
            (seg.lowest_vcn, seg.highest_vcn, seg.mp_offset, seg.comp_unit) = struct.unpack_from(
                "<qqHB", buf, pos + 16
            )
            seg.alloc_size, seg.data_size, seg.init_size = struct.unpack_from("<qqq", buf, pos + 40)
            if seg.mp_offset >= a_len:
                raise NtfsError(f"MFT record {num}: bad mapping pairs offset")
            seg.runs = decode_mapping_pairs(buf, pos + seg.mp_offset, pos + a_len, seg.lowest_vcn)
            covered = sum(r.length for r in seg.runs)
            if seg.highest_vcn >= seg.lowest_vcn and covered != seg.highest_vcn - seg.lowest_vcn + 1:
                raise NtfsError(
                    f"MFT record {num}: runlist of {ATTR_NAMES.get(a_type, hex(a_type))} covers "
                    f"{covered} clusters, header says {seg.highest_vcn - seg.lowest_vcn + 1}"
                )
        else:
            v_len, v_off = struct.unpack_from("<IH", buf, pos + 16)
            if v_off + v_len > a_len:
                raise NtfsError(f"MFT record {num}: bad resident value")
            seg.value = bytes(buf[pos + v_off : pos + v_off + v_len])
        attrs.append(seg)
        pos += a_len
    return Record(num, flags, seq, base, in_use, alloc, attrs)


# --------------------------------------------------------------------------------------
# Streams (complete non-resident attributes) and files
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class Stream:
    base: int
    type: int
    name: str
    flags: int
    segs: List[AttrSeg]
    runs: List[Run]
    movable: bool = True
    why_fixed: str = ""

    @property
    def clusters(self) -> int:
        return sum(r.length for r in self.runs if r.lcn is not None)

    @property
    def extents(self) -> List[Tuple[int, int]]:
        return physical_extents(self.runs)

    @property
    def fragments(self) -> int:
        return len(self.extents)

    @property
    def first_lcn(self) -> int:
        for r in self.runs:
            if r.lcn is not None:
                return r.lcn
        return -1

    def key(self) -> Tuple[int, int, str]:
        return (self.base, self.type, self.name)

    def describe(self) -> str:
        t = ATTR_NAMES.get(self.type, hex(self.type))
        if self.type == AT_DATA:
            return f":{self.name}" if self.name else ""
        return f" [{t}{':' + self.name if self.name else ''}]"


@dataclass(slots=True)
class FileInfo:
    num: int
    is_dir: bool
    parent: int = -1
    name: str = ""
    name_ns_rank: int = 9


# --------------------------------------------------------------------------------------
# Volume
# --------------------------------------------------------------------------------------


class Volume:
    def __init__(self, path: str, writable: bool = False, allow_mounted: bool = False) -> None:
        self.dev = Device(path, writable, allow_mounted)
        try:
            self._load_boot()
            self._load_mft_runs()
        except Exception:
            self.dev.close()
            raise
        self.records: Dict[int, Record] = {}
        self.files: Dict[int, FileInfo] = {}
        self.streams: Dict[Tuple[int, int, str], Stream] = {}
        self.bitmap = bytearray()
        self.bitmap_runs: List[Run] = []
        self.bad_records: List[str] = []

    def close(self) -> None:
        self.dev.close()

    # ---- boot sector ----

    def _load_boot(self) -> None:
        b = self.dev.pread(0, 512)
        if b[3:11] != b"NTFS    " or b[510:512] != b"\x55\xaa":
            raise NtfsError("not an NTFS volume (bad boot sector signature)")
        self.sector = struct.unpack_from("<H", b, 0x0B)[0]
        spc = b[0x0D]
        spc = 1 << (256 - spc) if spc > 0x80 else spc
        if self.sector not in (256, 512, 1024, 2048, 4096) or spc == 0:
            raise NtfsError("unsupported sector/cluster geometry")
        self.cluster = self.sector * spc
        self.total_sectors = struct.unpack_from("<Q", b, 0x28)[0]
        self.total_clusters = self.total_sectors * self.sector // self.cluster
        self.mft_lcn, self.mftmirr_lcn = struct.unpack_from("<QQ", b, 0x30)
        cpr = struct.unpack_from("<b", b, 0x40)[0]
        self.rec_size = (1 << -cpr) if cpr < 0 else cpr * self.cluster
        cpi = struct.unpack_from("<b", b, 0x44)[0]
        self.idx_size = (1 << -cpi) if cpi < 0 else cpi * self.cluster
        self.serial = struct.unpack_from("<Q", b, 0x48)[0]
        if self.rec_size not in (1024, 2048, 4096) or self.rec_size % self.sector:
            raise NtfsError(f"unsupported MFT record size {self.rec_size}")
        if self.total_clusters * self.cluster > self.dev.size:
            raise NtfsError("volume is larger than the device - truncated image?")
        # USA sector size is always 512 bytes regardless of the device sector size
        self.usa_sector = 512

    # ---- MFT ----

    def _read_raw_record_at(self, lcn: int, idx: int) -> bytearray:
        return bytearray(self.dev.pread(lcn * self.cluster + idx * self.rec_size, self.rec_size))

    def _load_mft_runs(self) -> None:
        raw = self._read_raw_record_at(self.mft_lcn, 0)
        apply_fixups(raw, self.usa_sector, "$MFT record 0")
        rec0 = parse_record(0, raw)
        segs = [a for a in rec0.attrs if a.type == AT_DATA and not a.name and a.nonresident]
        if not segs:
            raise NtfsError("$MFT has no non-resident $DATA")
        self.mft_runs = list(segs[0].runs)
        self.mft_size = segs[0].data_size
        has_list = any(a.type == AT_ATTRIBUTE_LIST for a in rec0.attrs)
        if has_list and segs[0].highest_vcn + 1 < segs[0].alloc_size // self.cluster:
            # $MFT itself has extension records; they live inside the part we can map.
            for ext in self._mft_extension_records(rec0):
                raw = self.read_record_raw(ext)
                apply_fixups(raw, self.usa_sector, f"$MFT extension record {ext}")
                r = parse_record(ext, raw)
                for a in r.attrs:
                    if a.type == AT_DATA and not a.name and a.nonresident:
                        self.mft_runs.extend(a.runs)
            self.mft_runs = merge_runs(sorted(self.mft_runs, key=lambda r: r.vcn))
        self.mft_records = self.mft_size // self.rec_size

    def _mft_extension_records(self, rec0: Record) -> List[int]:
        al = next(a for a in rec0.attrs if a.type == AT_ATTRIBUTE_LIST)
        data = al.value if not al.nonresident else self.read_stream_bytes(al.runs, al.data_size)
        out = []
        pos = 0
        while pos + 26 <= len(data):
            a_type, rlen = struct.unpack_from("<IH", data, pos)
            if rlen == 0:
                break
            ref = struct.unpack_from("<Q", data, pos + 16)[0] & REF_MASK
            if a_type == AT_DATA and ref != 0 and ref not in out:
                out.append(ref)
            pos += rlen
        return out

    def vcn_to_lcn(self, runs: Sequence[Run], vcn: int) -> Tuple[Optional[int], int]:
        """LCN for vcn and number of clusters contiguous from there."""
        for r in runs:
            if r.vcn <= vcn < r.end_vcn:
                if r.lcn is None:
                    return None, r.end_vcn - vcn
                return r.lcn + (vcn - r.vcn), r.end_vcn - vcn
        raise NtfsError(f"VCN {vcn} not mapped")

    def record_pieces(self, num: int) -> List[Tuple[int, int]]:
        """(disk offset, length) pieces of MFT record `num`; >1 piece if it spans runs."""
        out: List[Tuple[int, int]] = []
        byte = num * self.rec_size
        left = self.rec_size
        while left > 0:
            vcn, within = divmod(byte, self.cluster)
            lcn, cont = self.vcn_to_lcn(self.mft_runs, vcn)
            if lcn is None:
                raise NtfsError(f"MFT record {num} maps to a hole")
            n = min(left, cont * self.cluster - within)
            off = lcn * self.cluster + within
            if out and out[-1][0] + out[-1][1] == off:
                out[-1] = (out[-1][0], out[-1][1] + n)
            else:
                out.append((off, n))
            byte += n
            left -= n
        return out

    def read_record_raw(self, num: int) -> bytearray:
        return bytearray(b"".join(self.dev.pread(o, n) for o, n in self.record_pieces(num)))

    def write_record_raw(self, num: int, disk: bytes) -> None:
        pos = 0
        for o, n in self.record_pieces(num):
            self.dev.pwrite(o, disk[pos : pos + n])
            pos += n
        if num < self.mirror_count():
            self.dev.pwrite(self.mftmirr_lcn * self.cluster + num * self.rec_size, disk)

    def read_record(self, num: int) -> Tuple[Record, bytearray]:
        raw = self.read_record_raw(num)
        fixed = bytearray(raw)
        apply_fixups(fixed, self.usa_sector, f"MFT record {num}")
        return parse_record(num, fixed), fixed

    def mirror_count(self) -> int:
        return getattr(self, "_mirror_count", 4)

    def write_record(self, num: int, fixed: bytearray) -> bytes:
        """Write a fixed-up record image (applies a fresh USA). Returns the on-disk bytes."""
        disk = bytes(protect_fixups(fixed, self.usa_sector))
        self.write_record_raw(num, disk)
        return disk

    def read_stream_bytes(self, runs: Sequence[Run], size: int) -> bytes:
        out = bytearray()
        for r in runs:
            if len(out) >= size:
                break
            n = min(r.length * self.cluster, size - len(out))
            if r.lcn is None:
                out += bytes(n)
            else:
                out += self.dev.pread(r.lcn * self.cluster, n)
        return bytes(out[:size])

    def iter_raw_records(self) -> Iterator[Tuple[int, bytearray]]:
        """Read the whole MFT sequentially in large chunks (records may span runs)."""
        chunk_clusters = max(1, (8 * MiB) // self.cluster)
        num = 0
        carry = bytearray()
        for r in self.mft_runs:
            if r.lcn is None:
                raise NtfsError("$MFT has a sparse run")
            done = 0
            while done < r.length:
                n = min(chunk_clusters, r.length - done)
                carry += self.dev.pread((r.lcn + done) * self.cluster, n * self.cluster)
                done += n
                usable = len(carry) - len(carry) % self.rec_size
                for i in range(0, usable, self.rec_size):
                    if num >= self.mft_records:
                        return
                    yield num, bytearray(carry[i : i + self.rec_size])
                    num += 1
                del carry[:usable]

    # ---- full scan ----

    def scan(self, progress: bool = False) -> None:
        t0 = time.monotonic()
        self.records, self.files, self.streams, self.bad_records = {}, {}, {}, []
        recs: Dict[int, Record] = {}
        for num, raw in self.iter_raw_records():
            if raw[:4] != b"FILE":
                continue
            try:
                apply_fixups(raw, self.usa_sector, f"MFT record {num}")
                rec = parse_record(num, raw)
            except NtfsError as e:
                flags = struct.unpack_from("<H", raw, 22)[0] if len(raw) > 24 else 0
                if flags & MFT_RECORD_IN_USE:
                    self.bad_records.append(str(e))
                continue
            if not rec.flags & MFT_RECORD_IN_USE:
                continue
            recs[num] = rec
            if progress and num % 50000 == 0:
                sys.stderr.write(f"\r  reading MFT: {num}/{self.mft_records} records")
        if progress:
            sys.stderr.write(f"\r  reading MFT: {self.mft_records} records in {time.monotonic() - t0:.1f}s\n")
        self.records = recs
        mirr = recs.get(FILE_MFTMIRR)
        if mirr:
            for a in mirr.attrs:
                if a.type == AT_DATA and not a.name:
                    self._mirror_count = max(1, (a.data_size if a.nonresident else len(a.value)) // self.rec_size)

        # group segments into streams by base record
        segs_by_key: Dict[Tuple[int, int, str], List[AttrSeg]] = {}
        for num, rec in recs.items():
            base = rec.base if rec.base else num
            if rec.base and rec.base not in recs:
                self.bad_records.append(f"extension record {num} points to missing base {rec.base}")
                continue
            if not rec.base:
                self.files.setdefault(num, FileInfo(num, False)).is_dir = bool(
                    rec.flags & MFT_RECORD_IS_DIRECTORY
                )
            for a in rec.attrs:
                if a.type == AT_FILE_NAME and len(a.value) >= 66:
                    fi2 = self.files.setdefault(base, FileInfo(base, False))
                    parent = struct.unpack_from("<Q", a.value, 0)[0] & REF_MASK
                    nlen = a.value[64]
                    ns = a.value[65]
                    rank = {1: 0, 3: 1, 0: 2, 2: 3}.get(ns, 4)  # Win32 > Win32&DOS > POSIX > DOS
                    if rank < fi2.name_ns_rank:
                        fi2.name_ns_rank = rank
                        fi2.parent = parent
                        fi2.name = a.value[66 : 66 + 2 * nlen].decode("utf-16-le", "replace")
                if a.nonresident:
                    segs_by_key.setdefault((base, a.type, a.name), []).append(a)
        for key, segs in segs_by_key.items():
            segs.sort(key=lambda s: s.lowest_vcn)
            runs: List[Run] = []
            expect = 0
            ok = True
            for s in segs:
                if s.lowest_vcn != expect and s.highest_vcn >= s.lowest_vcn:
                    ok = False
                runs.extend(s.runs)
                expect = s.highest_vcn + 1
            st = Stream(key[0], key[1], key[2], segs[0].flags, segs, runs)
            if not ok:
                st.movable = False
                st.why_fixed = "attribute segments do not cover a continuous VCN range"
                self.bad_records.append(f"record {key[0]} {ATTR_NAMES.get(key[1])}: VCN gap between segments")
            self.streams[key] = st
        self._classify_streams()
        self._load_bitmap()

    def _classify_streams(self) -> None:
        for st in self.streams.values():
            if not st.movable:
                continue
            if st.base < FIRST_USER_RECORD:
                st.movable, st.why_fixed = False, "NTFS metadata file"
            elif self._under_extend(st.base):
                st.movable, st.why_fixed = False, "$Extend metadata"
            elif st.clusters == 0:
                st.movable, st.why_fixed = False, "no allocated clusters"

    def _under_extend(self, num: int) -> bool:
        seen = 0
        while num not in (5, -1) and seen < 64:
            fi = self.files.get(num)
            if fi is None:
                return False
            if fi.parent == FILE_EXTEND:
                return True
            if fi.parent == num:
                return False
            num = fi.parent
            seen += 1
        return False

    def path_of(self, num: int) -> str:
        parts: List[str] = []
        seen = 0
        while num != 5 and seen < 256:
            fi = self.files.get(num)
            if fi is None or not fi.name:
                parts.append(f"<rec {num}>")
                break
            parts.append(fi.name)
            if fi.parent == num:
                break
            num = fi.parent
            seen += 1
        return "/" + "/".join(reversed(parts))

    # ---- $Bitmap ----

    def _load_bitmap(self) -> None:
        st = self.streams.get((FILE_BITMAP, AT_DATA, ""))
        if st is None:
            raise NtfsError("$Bitmap has no non-resident $DATA")
        size = st.segs[0].data_size
        need = (self.total_clusters + 7) // 8
        if size < need:
            raise NtfsError(f"$Bitmap too small ({size} < {need} bytes)")
        self.bitmap_runs = st.runs
        self.bitmap = bytearray(self.read_stream_bytes(st.runs, size))
        self.bitmap_size = size

    def bitmap_dirty_write(self, first_cluster: int, last_cluster: int) -> None:
        """Write the bitmap bytes covering clusters [first, last] (sector aligned)."""
        b0 = first_cluster // 8
        b1 = last_cluster // 8 + 1
        al = self.dev.align
        a0 = (b0 // al) * al
        a1 = min(-(-b1 // al) * al, len(self.bitmap))
        pos = a0
        while pos < a1:
            vcn, within = divmod(pos, self.cluster)
            lcn, cont = self.vcn_to_lcn(self.bitmap_runs, vcn)
            if lcn is None:
                raise NtfsError("$Bitmap has a hole")
            n = min(a1 - pos, cont * self.cluster - within)
            self.dev.pwrite(lcn * self.cluster + within, bytes(self.bitmap[pos : pos + n]))
            pos += n

    def is_free(self, lcn: int, n: int) -> bool:
        return count_set_bits(self.bitmap, lcn, n) == 0

    # ---- volume flags / logfile ----

    def volume_flags(self) -> Tuple[int, Tuple[int, int]]:
        rec = self.records.get(FILE_VOLUME) or self.read_record(FILE_VOLUME)[0]
        for a in rec.attrs:
            if a.type == AT_VOLUME_INFORMATION and len(a.value) >= 12:
                return struct.unpack_from("<H", a.value, 10)[0], (a.value[8], a.value[9])
        raise NtfsError("$Volume has no $VOLUME_INFORMATION")

    def set_volume_dirty(self, dirty: bool) -> None:
        rec, fixed = self.read_record(FILE_VOLUME)
        for a in rec.attrs:
            if a.type == AT_VOLUME_INFORMATION:
                v_off = struct.unpack_from("<H", fixed, a.offset + 20)[0]
                p = a.offset + v_off + 10
                flags = struct.unpack_from("<H", fixed, p)[0]
                new = (flags | VOLUME_IS_DIRTY) if dirty else (flags & ~VOLUME_IS_DIRTY)
                if new != flags:
                    struct.pack_into("<H", fixed, p, new)
                    self.write_record(FILE_VOLUME, fixed)
                    self.dev.flush()
                return
        raise NtfsError("$Volume has no $VOLUME_INFORMATION")

    def logfile_state(self) -> str:
        """'clean', 'empty' (reset by ntfs-3g) or 'dirty'."""
        st = self.streams.get((FILE_LOGFILE, AT_DATA, ""))
        if st is None:
            return "dirty"
        lcn = st.first_lcn
        page = self.dev.pread(lcn * self.cluster, 4096)
        if page.count(0xFF) == len(page):
            return "empty"
        if page[:4] != b"RSTR":
            return "dirty"
        try:
            buf = bytearray(page)
            sys_page = struct.unpack_from("<I", buf, 0x10)[0]
            if sys_page not in (4096, 8192, 16384, 32768, 65536) or sys_page > len(buf):
                buf = bytearray(self.dev.pread(lcn * self.cluster, sys_page))
            apply_fixups(buf, 512, "$LogFile restart page")
            ra_off = struct.unpack_from("<H", buf, 0x18)[0]
            client_in_use = struct.unpack_from("<H", buf, ra_off + 0x0A)[0]
            ra_flags = struct.unpack_from("<H", buf, ra_off + 0x0C)[0]
        except (NtfsError, struct.error):
            return "dirty"
        if client_in_use == 0xFFFF or ra_flags & 0x0002:
            return "clean"
        return "dirty"

    def hibernated(self) -> bool:
        root = 5
        for num, fi in self.files.items():
            if fi.parent == root and fi.name.lower() == "hiberfil.sys":
                st = self.streams.get((num, AT_DATA, ""))
                if st is None or st.first_lcn < 0:
                    rec = self.records.get(num)
                    if rec:
                        for a in rec.attrs:
                            if a.type == AT_DATA and not a.name and not a.nonresident:
                                return a.value[:4].lower() in (b"hibr", b"wake")
                    return False
                head = self.dev.pread(st.first_lcn * self.cluster, 4096)
                return head[:4].lower() in (b"hibr", b"wake")
        return False


# --------------------------------------------------------------------------------------
# Bit helpers
# --------------------------------------------------------------------------------------

_POPCOUNT = bytes(bin(i).count("1") for i in range(256))


def count_set_bits(bm: bytearray, start: int, n: int) -> int:
    if n <= 0:
        return 0
    end = start + n
    total = 0
    while start < end and start & 7:
        total += (bm[start >> 3] >> (start & 7)) & 1
        start += 1
    while end > start and end & 7:
        end -= 1
        total += (bm[end >> 3] >> (end & 7)) & 1
    if end > start:
        total += int.from_bytes(bm[start >> 3 : end >> 3], "little").bit_count()
    return total


def set_bits(bm: bytearray, start: int, n: int, value: bool) -> None:
    end = start + n
    while start < end and start & 7:
        if value:
            bm[start >> 3] |= 1 << (start & 7)
        else:
            bm[start >> 3] &= ~(1 << (start & 7)) & 0xFF
        start += 1
    while end > start and end & 7:
        end -= 1
        if value:
            bm[end >> 3] |= 1 << (end & 7)
        else:
            bm[end >> 3] &= ~(1 << (end & 7)) & 0xFF
    if end > start:
        bm[start >> 3 : end >> 3] = (b"\xff" if value else b"\x00") * ((end - start) >> 3)


def free_extents_from_bitmap(bm: bytearray, total: int) -> List[Tuple[int, int]]:
    """All free (start, length) runs, using fast byte-level scanning."""
    out: List[Tuple[int, int]] = []
    nbytes = (total + 7) // 8
    mv = bytes(bm[:nbytes])
    pos = 0
    run_start = -1
    while pos < nbytes:
        if run_start < 0:
            # skip fully used bytes quickly
            nxt = _find_not(mv, 0xFF, pos)
            if nxt < 0:
                break
            pos = nxt
            byte = mv[pos]
            for bit in range(8):
                c = pos * 8 + bit
                if c >= total:
                    break
                if not (byte >> bit) & 1:
                    if run_start < 0:
                        run_start = c
                elif run_start >= 0:
                    out.append((run_start, c - run_start))
                    run_start = -1
            pos += 1
        else:
            nxt = _find_not(mv, 0x00, pos)
            if nxt < 0:
                pos = nbytes
                break
            pos = nxt
            byte = mv[pos]
            for bit in range(8):
                c = pos * 8 + bit
                if c >= total:
                    break
                if not (byte >> bit) & 1:
                    if run_start < 0:
                        run_start = c
                elif run_start >= 0:
                    out.append((run_start, c - run_start))
                    run_start = -1
            pos += 1
    if run_start >= 0:
        out.append((run_start, min(total, nbytes * 8) - run_start))
    return [(s, n) for s, n in out if n > 0 and s < total]


def _find_not(buf: bytes, value: int, pos: int) -> int:
    """Index of first byte != value at or after pos, -1 if none."""
    pat = bytes([value])
    n = len(buf)
    step = 1 << 16
    while pos < n:
        chunk = buf[pos : pos + step]
        stripped = chunk.lstrip(pat)
        if stripped:
            return pos + len(chunk) - len(stripped)
        pos += step
    return -1


# --------------------------------------------------------------------------------------
# Consistency check (cluster accounting vs. $Bitmap)
# --------------------------------------------------------------------------------------


@dataclass
class CheckResult:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    leaked_clusters: int = 0
    used_clusters: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors


def check_volume(vol: Volume, max_report: int = 20) -> CheckResult:
    res = CheckResult()
    total = vol.total_clusters
    used = bytearray(len(vol.bitmap))
    for msg in vol.bad_records:
        res.errors.append(msg)
    owners: List[Tuple[int, int, Stream]] = []
    for st in vol.streams.values():
        for lcn, n in st.extents:
            if lcn + n > total:
                res.errors.append(
                    f"record {st.base}{st.describe()}: extent {lcn}+{n} beyond volume end {total}"
                )
                continue
            if count_set_bits(used, lcn, n):
                res.errors.append(
                    f"record {st.base}{st.describe()}: extent {lcn}+{n} is cross-linked"
                )
                owners.append((lcn, n, st))
            set_bits(used, lcn, n, True)
            res.used_clusters += n
    # compare to $Bitmap in 1 MiB chunks
    nbytes = (total + 7) // 8
    tail_mask_bits = total % 8
    step = 1 << 20
    in_use_free = 0
    first_bad: List[int] = []
    for off in range(0, nbytes, step):
        end = min(nbytes, off + step)
        a = int.from_bytes(used[off:end], "little")
        b = int.from_bytes(vol.bitmap[off:end], "little")
        if end == nbytes and tail_mask_bits:
            mask = (1 << ((end - off - 1) * 8 + tail_mask_bits)) - 1
            a &= mask
            b &= mask
        bad = a & ~b
        if bad:
            in_use_free += bad.bit_count()
            if len(first_bad) < max_report:
                first_bad.append(off * 8 + ((bad & -bad).bit_length() - 1))
        res.leaked_clusters += (b & ~a).bit_count()
    if in_use_free:
        res.errors.append(
            f"{in_use_free} clusters are in use but marked FREE in $Bitmap "
            f"(first at LCN {first_bad[0]})"
        )
    if res.leaked_clusters:
        res.warnings.append(
            f"{res.leaked_clusters} clusters are marked used in $Bitmap but owned by no attribute"
        )
    del res.errors[max_report * 5 :]
    return res


# --------------------------------------------------------------------------------------
# Free space index
# --------------------------------------------------------------------------------------


class FreeSpace:
    """
    Free cluster runs indexed by start (for merging / first-fit) and by (length, start)
    (for best-fit). An optional forbidden zone (MFT zone) is never handed out.
    """

    def __init__(self, extents: Iterable[Tuple[int, int]], zone: Tuple[int, int] = (0, 0)) -> None:
        self.len_of: Dict[int, int] = {}
        self.end_of: Dict[int, int] = {}
        self.starts: List[int] = []
        self.by_len: List[Tuple[int, int]] = []
        for s, n in extents:
            if n > 0:
                self.len_of[s] = n
                self.end_of[s + n] = s
        self.starts = sorted(self.len_of)
        self.by_len = sorted((n, s) for s, n in self.len_of.items())
        self.zone = zone

    # -- raw maintenance --
    def _add(self, s: int, n: int) -> None:
        self.len_of[s] = n
        self.end_of[s + n] = s
        bisect.insort(self.starts, s)
        bisect.insort(self.by_len, (n, s))

    def _remove(self, s: int) -> int:
        n = self.len_of.pop(s)
        del self.end_of[s + n]
        i = bisect.bisect_left(self.starts, s)
        del self.starts[i]
        j = bisect.bisect_left(self.by_len, (n, s))
        del self.by_len[j]
        return n

    @property
    def total(self) -> int:
        return sum(self.len_of.values())

    @property
    def count(self) -> int:
        return len(self.starts)

    def largest(self, k: int = 1) -> List[Tuple[int, int]]:
        return [(s, n) for n, s in self.by_len[-k:][::-1]]

    def release(self, s: int, n: int) -> None:
        if n <= 0:
            return
        i = bisect.bisect_right(self.starts, s) - 1
        if i >= 0:
            ps = self.starts[i]
            if ps + self.len_of[ps] > s:
                raise NtfsError(f"internal: double free at LCN {s}")
        if i + 1 < len(self.starts) and self.starts[i + 1] < s + n:
            raise NtfsError(f"internal: double free at LCN {s}")
        if s in self.end_of:
            prev = self.end_of[s]
            n += self._remove(prev)
            s = prev
        if s + n in self.len_of:
            n += self._remove(s + n)
        self._add(s, n)

    def take(self, s: int, n: int) -> None:
        i = bisect.bisect_right(self.starts, s) - 1
        if i < 0:
            raise NtfsError(f"internal: allocating used clusters at LCN {s}")
        gs = self.starts[i]
        gn = self.len_of[gs]
        if s + n > gs + gn:
            raise NtfsError(f"internal: allocating used clusters at LCN {s}+{n}")
        self._remove(gs)
        if s > gs:
            self._add(gs, s - gs)
        if gs + gn > s + n:
            self._add(s + n, gs + gn - s - n)

    def free_parts_in(self, a: int, b: int) -> List[Tuple[int, int]]:
        out = []
        i = max(0, bisect.bisect_right(self.starts, a) - 1)
        while i < len(self.starts) and self.starts[i] < b:
            s = self.starts[i]
            e = s + self.len_of[s]
            lo, hi = max(a, s), min(b, e)
            if lo < hi:
                out.append((lo, hi - lo))
            i += 1
        return out

    # -- placement queries --
    def _usable(self, s: int, n_gap: int, need: int, limit: Optional[int]) -> Optional[int]:
        """Lowest start inside gap (s, n_gap) for `need` clusters avoiding the zone."""
        e = s + n_gap
        z0, z1 = self.zone
        cands = [s]
        if z0 < z1 and s < z1 and e > z0:
            cands = [s] if s + need <= z0 else []
            cands.append(max(s, z1))
        for c in cands:
            if c + need <= e and not (c < z1 and c + need > z0):
                if limit is None or c < limit:
                    return c
        return None

    def best_fit(self, need: int) -> Optional[int]:
        i = bisect.bisect_left(self.by_len, (need, -1))
        while i < len(self.by_len):
            n, s = self.by_len[i]
            c = self._usable(s, n, need, None)
            if c is not None:
                return c
            i += 1
        return None

    def first_fit(self, need: int, limit: Optional[int] = None) -> Optional[int]:
        best: Optional[int] = None
        for k, s in enumerate(self.starts):
            if limit is not None and s >= limit:
                return None
            if k >= 256:
                break
            c = self._usable(s, self.len_of[s], need, limit)
            if c is not None:
                return c
        else:
            return None
        i = bisect.bisect_left(self.by_len, (need, -1))
        while i < len(self.by_len):
            n, s = self.by_len[i]
            if best is None or s < best:
                c = self._usable(s, n, need, limit)
                if c is not None and (best is None or c < best):
                    best = c
            i += 1
        return best

    def largest_chunks(self, need: int, min_chunk: int) -> Optional[List[Tuple[int, int]]]:
        """Cover `need` clusters with as few (largest) usable chunks as possible."""
        out: List[Tuple[int, int]] = []
        left = need
        for n, s in reversed(self.by_len):
            if left <= 0:
                break
            if n < min(min_chunk, left):
                break
            z0, z1 = self.zone
            parts = [(s, n)]
            if z0 < z1 and s < z1 and s + n > z0:
                parts = [(p, q) for p, q in ((s, max(0, z0 - s)), (max(s, z1), s + n - max(s, z1))) if q > 0]
            for p, q in sorted(parts, key=lambda x: -x[1]):
                if left <= 0 or q < min(min_chunk, left):
                    continue
                take = min(q, left)
                out.append((p, take))
                left -= take
        if left > 0:
            return None
        return out


# --------------------------------------------------------------------------------------
# Record patching
# --------------------------------------------------------------------------------------


def patch_mapping_pairs(fixed: bytearray, rec_num: int, seg: AttrSeg, new_runs: List[Run]) -> None:
    """
    Replace the mapping pairs of attribute `seg` (located by type/name/lowest_vcn in the
    freshly parsed record image `fixed`) with `new_runs`. Grows the attribute (shifting
    later attributes) if necessary. Raises NtfsError if the record has no room.
    """
    rec = parse_record(rec_num, fixed)
    cur = None
    for a in rec.attrs:
        if a.nonresident and a.type == seg.type and a.name == seg.name and a.lowest_vcn == seg.lowest_vcn:
            cur = a
            break
    if cur is None:
        raise NtfsError(f"record {rec_num}: attribute segment vanished")
    mp = encode_mapping_pairs(new_runs)
    need_len = (cur.mp_offset + len(mp) + 7) & ~7
    off = cur.offset
    if need_len > cur.length:
        delta = need_len - cur.length
        if rec.bytes_in_use + delta > rec.bytes_alloc:
            raise NtfsError(f"record {rec_num}: no room for the new runlist (+{delta} bytes)")
        tail_from = off + cur.length
        fixed[tail_from + delta : rec.bytes_in_use + delta] = fixed[tail_from : rec.bytes_in_use]
        struct.pack_into("<I", fixed, off + 4, need_len)
        struct.pack_into("<I", fixed, 24, rec.bytes_in_use + delta)
        cur_len = need_len
    else:
        cur_len = cur.length
    start = off + cur.mp_offset
    fixed[start : off + cur_len] = mp + bytes(off + cur_len - start - len(mp))
    # sanity: re-parse and compare
    chk = parse_record(rec_num, fixed)
    for a in chk.attrs:
        if a.nonresident and a.type == seg.type and a.name == seg.name and a.lowest_vcn == seg.lowest_vcn:
            if [(r.vcn, r.length, r.lcn) for r in a.runs] != [(r.vcn, r.length, r.lcn) for r in merge_runs(new_runs)] and \
               [(r.vcn, r.length, r.lcn) for r in merge_runs(a.runs)] != [(r.vcn, r.length, r.lcn) for r in merge_runs(new_runs)]:
                raise NtfsError(f"record {rec_num}: runlist round-trip mismatch")
            return
    raise NtfsError(f"record {rec_num}: patched attribute not found")


def remap_runs(runs: Sequence[Run], targets: Sequence[Tuple[int, int]]) -> Tuple[List[Run], List[Tuple[int, int, int]]]:
    """
    Map allocated clusters of `runs` (in VCN order) onto `targets`. Holes are kept.
    Returns (new_runs, copy_ops[(src_lcn, dst_lcn, n)]).
    """
    new: List[Run] = []
    ops: List[Tuple[int, int, int]] = []
    ti = 0
    t_lcn, t_left = targets[0] if targets else (0, 0)
    for r in runs:
        if r.lcn is None:
            new.append(Run(r.vcn, r.length, None))
            continue
        done = 0
        while done < r.length:
            if t_left == 0:
                ti += 1
                t_lcn, t_left = targets[ti]
            n = min(t_left, r.length - done)
            new.append(Run(r.vcn + done, n, t_lcn))
            ops.append((r.lcn + done, t_lcn, n))
            t_lcn += n
            t_left -= n
            done += n
    return merge_runs(new), ops


def remap_selected(
    runs: Sequence[Run], select: Sequence[Tuple[int, int]], targets: Sequence[Tuple[int, int]]
) -> Tuple[List[Run], List[Tuple[int, int, int]]]:
    """
    Like remap_runs, but only clusters inside the physical ranges `select` are moved
    (in VCN order) onto `targets`; everything else keeps its LCN.
    """
    sel = sorted(select)
    starts = [a for a, _ in sel]
    pieces: List[Run] = []
    for r in runs:
        if r.lcn is None:
            pieces.append(Run(r.vcn, r.length, None))
            continue
        pos = 0
        while pos < r.length:
            lcn = r.lcn + pos
            i = bisect.bisect_right(starts, lcn) - 1
            if i >= 0 and sel[i][0] <= lcn < sel[i][0] + sel[i][1]:
                n = min(r.length - pos, sel[i][0] + sel[i][1] - lcn)
                pieces.append(Run(r.vcn + pos, n, -1 - lcn))  # marked for moving
            else:
                nxt = starts[i + 1] if i + 1 < len(starts) else lcn + r.length
                n = min(r.length - pos, max(1, nxt - lcn))
                pieces.append(Run(r.vcn + pos, n, lcn))
            pos += n
    new: List[Run] = []
    ops: List[Tuple[int, int, int]] = []
    ti = -1
    t_lcn = t_left = 0
    for p in pieces:
        if p.lcn is None or p.lcn >= 0:
            new.append(p)
            continue
        src = -1 - p.lcn
        done = 0
        while done < p.length:
            if t_left == 0:
                ti += 1
                t_lcn, t_left = targets[ti]
            n = min(t_left, p.length - done)
            new.append(Run(p.vcn + done, n, t_lcn))
            ops.append((src + done, t_lcn, n))
            t_lcn += n
            t_left -= n
            done += n
    moved = sum(n for _, _, n in ops)
    if moved != sum(n for _, n in select):
        raise NtfsError("internal: selected ranges are not all owned by the stream")
    return merge_runs(new), ops


def slice_runs(runs: Sequence[Run], lo: int, hi: int) -> List[Run]:
    """Runs restricted to VCN range [lo, hi] (inclusive)."""
    out: List[Run] = []
    for r in runs:
        a, b = max(lo, r.vcn), min(hi + 1, r.end_vcn)
        if a < b:
            out.append(Run(a, b - a, None if r.lcn is None else r.lcn + (a - r.vcn)))
    return out


# --------------------------------------------------------------------------------------
# Write-ahead journal (kept outside the volume)
# --------------------------------------------------------------------------------------


class Journal:
    """
    Holds at most one open transaction group. File format: one JSON document followed by
    a line "#sha256=<hex>". A file without a valid checksum is a torn journal write,
    meaning no metadata had been touched yet (journal is synced before any metadata write).
    """

    def __init__(self, path: str) -> None:
        self.path = path
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def write(self, doc: dict) -> None:
        body = json.dumps(doc, separators=(",", ":"))
        data = body + "\n#sha256=" + hashlib.sha256(body.encode()).hexdigest() + "\n"
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        dfd = os.open(os.path.dirname(os.path.abspath(self.path)), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def read(self) -> Optional[dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            return None
        body, sep, tail = text.rpartition("\n#sha256=")
        if not sep or hashlib.sha256(body.encode()).hexdigest() != tail.strip():
            return {"torn": True}
        return json.loads(body)

    @property
    def marker(self) -> str:
        return self.path + ".dirty-by-ntfsdefrag"

    def set_marker(self, on: bool) -> None:
        if on:
            with open(self.marker, "w") as f:
                f.write(f"{time.time()}\n")
                f.flush()
                os.fsync(f.fileno())
        else:
            try:
                os.unlink(self.marker)
            except FileNotFoundError:
                pass

    def has_marker(self) -> bool:
        return os.path.exists(self.marker)

    def clear(self) -> None:
        for p in (self.path, self.path + ".tmp"):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def default_journal_path(serial: int) -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "ntfsdefrag", f"{serial:016x}.journal")


def crash_point(name: str) -> None:
    """Test hook: NTFSDEFRAG_CRASH_AT=name:N kills the process at the N-th hit."""
    spec = os.environ.get("NTFSDEFRAG_CRASH_AT")
    if not spec:
        return
    want, _, cnt = spec.partition(":")
    if want != name:
        return
    left = int(cnt or "1") - 1
    os.environ["NTFSDEFRAG_CRASH_AT"] = f"{want}:{left}"
    if left <= 0:
        sys.stderr.write(f"[test] simulated crash at {name}\n")
        sys.stderr.flush()
        os._exit(99)


def apply_bit_ranges(vol: Volume, ranges: Sequence[Tuple[int, int]], value: bool) -> None:
    for lcn, n in ranges:
        set_bits(vol.bitmap, lcn, n, value)
    for lcn, n in merge_ranges(ranges):
        vol.bitmap_dirty_write(lcn, lcn + n - 1)


def merge_ranges(ranges: Iterable[Tuple[int, int]], slack: int = 4096 * 8) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for s, n in sorted(ranges):
        if out and s <= out[-1][0] + out[-1][1] + slack:
            e = max(out[-1][0] + out[-1][1], s + n)
            out[-1] = (out[-1][0], e - out[-1][0])
        else:
            out.append((s, n))
    return out


def recover(vol: Volume, journal: Journal, verbose: bool = True) -> str:
    """Bring the volume to a consistent state after an interrupted run."""
    doc = journal.read()
    if doc is None:
        return "no journal"
    if doc.get("torn"):
        journal.clear()
        return "torn journal discarded (no metadata had been written)"
    if doc.get("serial") != vol.serial:
        raise NtfsError("journal belongs to a different volume (serial mismatch)")
    if not vol.bitmap:
        vol.scan()  # needs $Bitmap; torn user records are tolerated by scan()
    recs = doc["records"]
    state = []
    for num_s, (old_hex, new_hex) in recs.items():
        cur = bytes(vol.read_record_raw(int(num_s)))
        state.append("new" if cur.hex() == new_hex else "old" if cur.hex() == old_hex else "torn")
    sets = [tuple(x) for x in doc["set"]]
    clears = [tuple(x) for x in doc["clear"]]
    if all(s == "new" for s in state):
        apply_bit_ranges(vol, sets, True)
        vol.dev.flush()
        apply_bit_ranges(vol, clears, False)
        vol.dev.flush()
        outcome = f"rolled forward group {doc['group']} ({len(recs)} records)"
    else:
        for (num_s, (old_hex, _)), s in zip(recs.items(), state):
            if s != "old":
                vol.write_record_raw(int(num_s), bytes.fromhex(old_hex))
        vol.dev.flush()
        apply_bit_ranges(vol, clears, True)
        apply_bit_ranges(vol, sets, False)
        vol.dev.flush()
        outcome = f"rolled back group {doc['group']} ({state.count('new')} new, {state.count('torn')} torn records restored)"
    journal.clear()
    if verbose:
        print(f"[recover] {outcome}")
    return outcome


# --------------------------------------------------------------------------------------
# Mover
# --------------------------------------------------------------------------------------


@dataclass
class Options:
    dry_run: bool = True
    verify: bool = True
    compact: bool = False
    passes: int = 3
    buffer_bytes: int = 64 * MiB
    group_bytes: int = 256 * MiB
    group_moves: int = 64
    mft_zone_clusters: Optional[int] = None
    max_evacuation_ratio: float = 2.0
    min_chunk_bytes: int = 64 * MiB
    ignore_fragments_over: int = 0  # bytes; 0 = every fragment counts
    verbose: bool = False
    show_paths: bool = True
    time_limit: float = 0.0


@dataclass
class Stats:
    moves: int = 0
    moved_clusters: int = 0
    defragmented: int = 0
    improved: int = 0
    evacuations: int = 0
    compacted: int = 0
    skipped: Dict[str, int] = field(default_factory=dict)
    groups: int = 0

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1


STOP = False


def _on_signal(signum: int, _frame: object) -> None:
    global STOP
    if STOP:
        sys.stderr.write("\n[signal] already stopping - finishing the current group\n")
    else:
        sys.stderr.write(f"\n[signal] {signal.Signals(signum).name}: finishing the current group, then stopping\n")
    STOP = True


class Mover:
    """Executes moves in crash-safe transaction groups and keeps the model in sync."""

    def __init__(self, vol: Volume, fs: FreeSpace, opts: Options, journal: Optional[Journal], stats: Stats) -> None:
        self.vol = vol
        self.fs = fs
        self.opts = opts
        self.journal = journal
        self.stats = stats
        self.group_id = 0
        self.pending_records: Dict[int, Tuple[bytes, bytearray]] = {}  # num -> (old disk, new fixed)
        self.pending_set: List[Tuple[int, int]] = []
        self.pending_clear: List[Tuple[int, int]] = []
        self.pending_bytes = 0
        self.pending_moves = 0
        self.buf: Optional[mmap.mmap] = None
        self.copied_bytes = 0
        self.t_start = time.monotonic()
        self.on_commit: List = []
        self.dry_overlay: Dict[int, bytearray] = {}  # dry-run: records "written" so far

    def _buffer(self) -> mmap.mmap:
        if self.buf is None:
            size = max(self.vol.cluster, (self.opts.buffer_bytes // self.vol.cluster) * self.vol.cluster)
            self.buf = mmap.mmap(-1, size)
        return self.buf

    def _record_image(self, num: int) -> bytearray:
        if num in self.pending_records:
            return self.pending_records[num][1]
        if num in self.dry_overlay:
            fixed = bytearray(self.dry_overlay[num])
            self.pending_records[num] = (b"", fixed)
            return fixed
        raw = self.vol.read_record_raw(num)
        fixed = bytearray(raw)
        apply_fixups(fixed, self.vol.usa_sector, f"MFT record {num}")
        self.pending_records[num] = (bytes(raw), fixed)
        return fixed

    def move(
        self, st: Stream, targets: List[Tuple[int, int]], select: Optional[List[Tuple[int, int]]] = None
    ) -> bool:
        """
        Relocate the allocated clusters of `st` (or only those inside the physical ranges
        `select`) onto `targets`, which the caller has already taken from the free space.
        """
        vol = self.vol
        if select is None:
            new_runs, ops = remap_runs(st.runs, targets)
        else:
            new_runs, ops = remap_selected(st.runs, select, targets)
        # 1) prepare new record images (fails early if a record has no room)
        snapshot = {n: bytearray(v[1]) for n, v in self.pending_records.items()}
        added: List[int] = []
        try:
            for seg in st.segs:
                if seg.highest_vcn < seg.lowest_vcn:
                    continue
                if seg.rec not in self.pending_records:
                    added.append(seg.rec)
                img = self._record_image(seg.rec)
                cur = parse_record(seg.rec, img)
                live = next(
                    (a for a in cur.attrs if a.nonresident and a.type == seg.type and a.name == seg.name and a.lowest_vcn == seg.lowest_vcn),
                    None,
                )
                if live is None or merge_runs(live.runs) != merge_runs(slice_runs(st.runs, seg.lowest_vcn, seg.highest_vcn)):
                    raise NtfsError(f"record {seg.rec}: on-disk runlist differs from the model")
                patch_mapping_pairs(img, seg.rec, seg, slice_runs(new_runs, seg.lowest_vcn, seg.highest_vcn))
        except NtfsError as e:
            for n in added:
                self.pending_records.pop(n, None)
            for n, img in snapshot.items():
                self.pending_records[n] = (self.pending_records[n][0], img)
            for lcn, n in targets:
                self.fs.release(lcn, n)
            self.stats.skip(f"cannot rewrite runlist: {e}")
            return False

        # 2) copy (and verify) the data into the free target clusters
        if not self.opts.dry_run:
            self._copy(ops)
            crash_point("after_copy")

        # 3) update the model; source clusters become free only after commit
        old_ext = st.extents if select is None else list(select)
        st.runs = new_runs
        for seg in st.segs:
            seg.runs = slice_runs(new_runs, seg.lowest_vcn, seg.highest_vcn)
        self.pending_set.extend(targets)
        self.pending_clear.extend(old_ext)
        moved = sum(n for _, _, n in ops)
        self.pending_bytes += moved * vol.cluster
        self.pending_moves += 1
        self.stats.moves += 1
        self.stats.moved_clusters += moved
        if self.pending_bytes >= self.opts.group_bytes or self.pending_moves >= self.opts.group_moves:
            self.commit()
        return True

    def _copy(self, ops: List[Tuple[int, int, int]]) -> None:
        cl = self.vol.cluster
        buf = self._buffer()
        cap = len(buf) // cl
        mv = memoryview(buf)
        digests: List[Tuple[int, int, bytes]] = []
        for src, dst, n in ops:
            done = 0
            while done < n:
                k = min(cap, n - done)
                view = mv[: k * cl]
                self.vol.dev.bulk_read_into((src + done) * cl, view)
                if self.opts.verify:
                    digests.append((dst + done, k, hashlib.blake2b(view, digest_size=16).digest()))
                self.vol.dev.bulk_write_from((dst + done) * cl, view)
                self.copied_bytes += k * cl
                done += k
        self.vol.dev.flush()
        if self.opts.verify:
            for dst, k, dg in digests:
                view = mv[: k * cl]
                self.vol.dev.bulk_read_into(dst * cl, view)
                if hashlib.blake2b(view, digest_size=16).digest() != dg:
                    raise NtfsError(
                        f"VERIFY FAILED: data written at LCN {dst} reads back differently - "
                        "aborting before any metadata change (check the disk!)"
                    )
        mv.release()

    def commit(self) -> None:
        if not self.pending_records and not self.pending_set:
            return
        vol = self.vol
        self.group_id += 1
        if not self.opts.dry_run:
            # the journal stores the exact on-disk images (old and new) of every record
            new_disk: Dict[int, bytes] = {
                n: bytes(protect_fixups(img, vol.usa_sector)) for n, (old, img) in self.pending_records.items()
            }
            assert self.journal is not None
            self.journal.write(
                {
                    "serial": vol.serial,
                    "group": self.group_id,
                    "records": {str(n): [old.hex(), new_disk[n].hex()] for n, (old, _) in self.pending_records.items()},
                    "set": self.pending_set,
                    "clear": self.pending_clear,
                }
            )
            crash_point("after_journal")
            apply_bit_ranges(vol, self.pending_set, True)
            vol.dev.flush()
            crash_point("after_bitmap_set")
            for k, (n, disk) in enumerate(new_disk.items()):
                vol.write_record_raw(n, disk)
                if k == 0:
                    crash_point("mid_records")
            vol.dev.flush()
            crash_point("after_records")
            apply_bit_ranges(vol, self.pending_clear, False)
            vol.dev.flush()
            crash_point("after_bitmap_clear")
            self.journal.clear()
        else:
            for n, (_, img) in self.pending_records.items():
                self.dry_overlay[n] = bytearray(img)
            for lcn, n in self.pending_set:
                set_bits(vol.bitmap, lcn, n, True)
            for lcn, n in self.pending_clear:
                set_bits(vol.bitmap, lcn, n, False)
        for lcn, n in self.pending_clear:
            self.fs.release(lcn, n)
        self.stats.groups += 1
        self.pending_records.clear()
        self.pending_set = []
        self.pending_clear = []
        self.pending_bytes = 0
        self.pending_moves = 0
        for cb in self.on_commit:
            cb()

    def close(self) -> None:
        if self.buf is not None:
            self.buf.close()
            self.buf = None


# --------------------------------------------------------------------------------------
# Planner
# --------------------------------------------------------------------------------------


class Defragmenter:
    def __init__(self, vol: Volume, opts: Options, journal: Optional[Journal]) -> None:
        self.vol = vol
        self.opts = opts
        self.stats = Stats()
        self.zone = self._mft_zone()
        self.fs = FreeSpace(free_extents_from_bitmap(vol.bitmap, vol.total_clusters), self.zone)
        self.mover = Mover(vol, self.fs, opts, journal, self.stats)
        self.mover.on_commit.append(self._invalidate)
        self._occ: Optional[List[Tuple[int, int, int]]] = None  # (start, end, stream idx | -1)
        self._occ_streams: List[Stream] = []
        self.reserved: List[Tuple[int, int]] = []  # windows taken for a pending split move
        self.deadline = time.monotonic() + opts.time_limit if opts.time_limit else 0.0
        self.last_report = 0.0

    # --- helpers ---
    def _mft_zone(self) -> Tuple[int, int]:
        vol = self.vol
        if self.opts.mft_zone_clusters == 0:
            return (0, 0)
        mft = vol.streams.get((FILE_MFT, AT_DATA, ""))
        if mft is None:
            return (0, 0)
        end = max(lcn + n for lcn, n in mft.extents)
        size = self.opts.mft_zone_clusters
        if size is None:
            # like Windows: keep room for the MFT to grow - 1/8 of its size, at least
            # 64 MiB, at most 1/64 of the volume
            mft_cl = mft.clusters
            size = max(64 * MiB // vol.cluster, mft_cl // 8)
            size = min(size, vol.total_clusters // 64)
        return (end, min(vol.total_clusters, end + size))

    def _invalidate(self) -> None:
        self._occ = None

    def _stopped(self) -> bool:
        if STOP:
            return True
        if self.deadline and time.monotonic() > self.deadline:
            return True
        return False

    def counts_as_fragmented(self, st: Stream) -> bool:
        ext = st.extents
        if len(ext) <= 1:
            return False
        lim = self.opts.ignore_fragments_over
        if lim:
            # a file whose fragments are all huge is "good enough" for an HDD
            if all(n * self.vol.cluster >= lim for _, n in ext):
                return False
        return True

    def label(self, st: Stream) -> str:
        if self.opts.show_paths:
            return f"{self.vol.path_of(st.base)}{st.describe()}"
        return f"[rec {st.base}]{st.describe()}"

    def _progress(self, phase: str, i: int, n: int) -> None:
        if not sys.stderr.isatty():
            return
        now = time.monotonic()
        if now - self.last_report < 1.0 and i != n:
            return
        self.last_report = now
        el = now - self.mover.t_start
        rate = self.mover.copied_bytes / el if el > 0 else 0
        sys.stderr.write(
            f"\r  {phase}: {i}/{n} | moved {fmt_bytes(self.stats.moved_clusters * self.vol.cluster)}"
            f" | {fmt_bytes(rate)}/s | {fmt_duration(el)}   "
        )
        if i == n:
            sys.stderr.write("\n")

    # --- occupancy for window search ---
    def _occupancy(self) -> List[Tuple[int, int, int]]:
        if self._occ is not None:
            return self._occ
        vol = self.vol
        occ: List[Tuple[int, int, int]] = []
        self._occ_streams = []
        for st in vol.streams.values():
            idx = len(self._occ_streams) if st.movable else -1
            if st.movable:
                self._occ_streams.append(st)
            for lcn, n in st.extents:
                occ.append((lcn, lcn + n, idx))
        z0, z1 = self.zone
        if z1 > z0:
            occ.append((z0, z1, -1))
        for s, n in self.reserved:
            occ.append((s, s + n, -1))
        occ.sort()
        self._occ = occ
        return occ

    def find_windows(
        self, st: Stream, need: int, k: int = 6
    ) -> List[Tuple[int, int]]:
        """
        Up to k cheapest windows (cost, start) of `need` clusters that contain no
        immovable data. Cost = clusters that must be moved out: whole foreign streams
        touching the window, plus the extents of `st` itself lying in it.
        """
        occ = self._occupancy()
        total = self.vol.total_clusters
        sts = self._occ_streams
        limit = int(need * self.opts.max_evacuation_ratio)
        me = next((i for i, x in enumerate(sts) if x is st), -2)
        cands = sorted({0} | {e for _, e, _ in occ})
        best: List[Tuple[int, int]] = []
        j = k2 = 0
        inwin: Dict[int, int] = {}
        cost = blockers = 0
        n_occ = len(occ)
        for w in cands:
            we = w + need
            if we > total:
                break
            while k2 < n_occ and occ[k2][0] < we:
                s, e, idx = occ[k2]
                if idx < 0:
                    blockers += 1
                elif idx == me:
                    cost += e - s
                else:
                    c = inwin.get(idx, 0)
                    if c == 0:
                        cost += sts[idx].clusters
                    inwin[idx] = c + 1
                k2 += 1
            while j < k2 and occ[j][1] <= w:
                s, e, idx = occ[j]
                if idx < 0:
                    blockers -= 1
                elif idx == me:
                    cost -= e - s
                else:
                    c = inwin[idx] - 1
                    if c == 0:
                        del inwin[idx]
                        cost -= sts[idx].clusters
                    else:
                        inwin[idx] = c
                j += 1
            if blockers or cost > limit:
                continue
            if len(best) < k or cost < best[-1][0]:
                # keep candidates spread out: replace a near-duplicate if cheaper
                dup = next((i for i, (_, bw) in enumerate(best) if abs(bw - w) < max(1, need // 2)), None)
                if dup is not None:
                    if cost < best[dup][0]:
                        best[dup] = (cost, w)
                        best.sort()
                    continue
                best.append((cost, w))
                best.sort()
                del best[k:]
                if cost == 0 and len(best) == k:
                    break
        return best

    def _window_content(self, st: Stream, w: int, need: int) -> Tuple[List[Stream], List[Tuple[int, int]]]:
        occ = self._occupancy()
        sts = self._occ_streams
        evac: List[Stream] = []
        own: List[Tuple[int, int]] = []
        seen = set()
        i = max(0, bisect.bisect_left(occ, (w, -1, -2)) - 64)
        for s, e, idx in occ[i:]:
            if s >= w + need:
                break
            if e <= w or idx < 0:
                continue
            if sts[idx] is st:
                own.append((s, e - s))
            elif idx not in seen:
                seen.add(idx)
                evac.append(sts[idx])
        return evac, own

    # --- strategies ---
    def place_contiguous(self, st: Stream) -> bool:
        need = st.clusters
        start = self.fs.best_fit(need)
        if start is not None:
            self.fs.take(start, need)
            return self._do_move(st, [(start, need)], "defrag")
        return False

    def _alloc_outside(self, need: int, max_chunks: int) -> Optional[List[Tuple[int, int]]]:
        """Contiguous if possible, otherwise at most `max_chunks` largest chunks (taken)."""
        dst = self.fs.best_fit(need)
        if dst is not None:
            self.fs.take(dst, need)
            return [(dst, need)]
        if max_chunks <= 1:
            return None
        chunks = self.fs.largest_chunks(need, 1)
        if chunks is None or len(chunks) > max_chunks:
            return None
        for s, n in chunks:
            self.fs.take(s, n)
        return chunks

    def make_room(self, st: Stream, need: int) -> Optional[int]:
        """
        Free a window of `need` clusters by moving other data (and pieces of `st`) out
        of it. On success the window is taken from the free space and its start returned.
        """
        start = self.fs.best_fit(need)
        if start is not None:
            self.fs.take(start, need)
            return start
        for cost, w in self.find_windows(st, need):
            if self._stopped():
                return None
            r = self._evacuate(st, w, need, cost)
            if r is not None:
                return r
        return None

    def _evacuate(self, st: Stream, w: int, need: int, cost: int) -> Optional[int]:
        evac, own = self._window_content(st, w, need)
        reserved = self.fs.free_parts_in(w, w + need)
        for s, n in reserved:
            self.fs.take(s, n)

        def undo(plan) -> None:
            for _, dst, _ in plan:
                for s, n in dst:
                    self.fs.release(s, n)
            for s, n in reserved:
                self.fs.release(s, n)

        plan: List[Tuple[Stream, List[Tuple[int, int]], Optional[List[Tuple[int, int]]]]] = []
        if own:
            dst = self._alloc_outside(sum(n for _, n in own), len(own) + 1)
            if dst is None:
                undo(plan)
                return None
            plan.append((st, dst, own))
        for ev in sorted(evac, key=lambda s: -s.clusters):
            # A contiguous evacuee must stay contiguous; one that is fragmented anyway
            # (and gets its own turn) may be split as needed.
            limit = (1 << 30) if self.counts_as_fragmented(ev) else ev.fragments
            dst = self._alloc_outside(ev.clusters, limit)
            if dst is None:
                undo(plan)
                return None
            plan.append((ev, dst, None))
        if self.opts.verbose:
            print(f"    window LCN {w}+{need}: moving {len(evac)} streams and {len(own)} own pieces out "
                  f"({fmt_bytes(cost * self.vol.cluster)})")
        for k, (ev, dst, sel) in enumerate(plan):
            if not self.mover.move(ev, dst, sel):
                for _, d2, _ in plan[k + 1 :]:
                    for s, n in d2:
                        self.fs.release(s, n)
                self.mover.commit()
                for s, n in reserved:
                    self.fs.release(s, n)
                return None
            if ev is not st:
                self.stats.evacuations += 1
        self.mover.commit()  # the window's old clusters are free now
        for s, n in reserved:
            self.fs.release(s, n)
        if self.fs.free_parts_in(w, w + need) != [(w, need)]:
            raise NtfsError(f"internal: window at LCN {w} is not free after evacuation")
        self.fs.take(w, need)
        return w

    def place_by_evacuation(self, st: Stream) -> bool:
        w = self.make_room(st, st.clusters)
        if w is None:
            return False
        return self._do_move(st, [(w, st.clusters)], "defrag")

    def place_split(self, st: Stream) -> bool:
        """Split into 2, 4, 8 ... pieces, each getting its own (possibly evacuated) window."""
        need = st.clusters
        old = st.fragments
        k = 2
        while k * 2 <= old and need // k >= 1:
            if self._stopped():
                return False
            sizes = [need // k + (1 if i < need % k else 0) for i in range(k)]
            got: List[Tuple[int, int]] = []
            ok = True
            for sz in sizes:
                w = self.make_room(st, sz)
                if w is None:
                    ok = False
                    break
                got.append((w, sz))
                self.reserved.append((w, sz))
                self._occ = None
            for r in got:
                self.reserved.remove(r)
            self._occ = None
            if ok:
                got.sort()
                return self._do_move(st, got, f"split/{k}")
            for s, n in got:
                self.fs.release(s, n)
            k *= 2
        return False

    def place_partial(self, st: Stream) -> bool:
        need = st.clusters
        old = st.fragments
        min_chunk = max(1, min(self.opts.min_chunk_bytes // self.vol.cluster, need // 4))
        chunks = self.fs.largest_chunks(need, min_chunk)
        if not chunks or len(chunks) * 2 > old:
            return False
        for s, n in chunks:
            self.fs.take(s, n)
        return self._do_move(st, sorted(chunks), "partial")

    def _do_move(self, st: Stream, targets: List[Tuple[int, int]], kind: str) -> bool:
        before = st.fragments
        first = st.first_lcn
        ok = self.mover.move(st, targets)
        if ok and (self.opts.verbose or self.opts.dry_run and self.opts.verbose):
            print(
                f"  {kind:8s} {self.label(st)}: {before} -> {st.fragments} fragments, "
                f"{fmt_bytes(st.clusters * self.vol.cluster)} LCN {first} -> {st.first_lcn}"
            )
        return ok

    # --- passes ---
    def defrag_pass(self) -> int:
        cands = [s for s in self.vol.streams.values() if s.movable and self.counts_as_fragmented(s)]
        cands.sort(key=lambda s: -s.clusters)
        changed = 0
        for i, st in enumerate(cands, 1):
            if self._stopped():
                break
            self._progress("defragment", i, len(cands))
            if not self.counts_as_fragmented(st):
                continue
            before = st.fragments
            if self.place_contiguous(st) or self.place_by_evacuation(st):
                self.stats.defragmented += 1
                changed += 1
            elif self.place_split(st) or self.place_partial(st):
                self.stats.improved += 1
                changed += 1
            else:
                self.stats.skip("no free space for it (yet)")
            del before
        self.mover.commit()
        return changed

    def compact_pass(self) -> int:
        """Move streams from high LCNs into the lowest free gaps that hold them whole."""
        cands = [s for s in self.vol.streams.values() if s.movable and s.clusters > 0]
        cands.sort(key=lambda s: -s.first_lcn)
        changed = 0
        for i, st in enumerate(cands, 1):
            if self._stopped():
                break
            self._progress("compact", i, len(cands))
            need = st.clusters
            if st.fragments > 1:
                continue
            dst = self.fs.first_fit(need, limit=st.first_lcn)
            if dst is None:
                continue
            self.fs.take(dst, need)
            if self._do_move(st, [(dst, need)], "compact"):
                self.stats.compacted += 1
                changed += 1
        self.mover.commit()
        return changed

    def run(self) -> None:
        for p in range(1, self.opts.passes + 1):
            if self._stopped():
                break
            n = self.defrag_pass()
            if self.opts.verbose:
                print(f"  pass {p}: {n} streams relocated")
            if n == 0:
                break
        if self.opts.compact:
            for p in range(1, self.opts.passes + 1):
                if self._stopped():
                    break
                n = self.compact_pass()
                if n == 0:
                    break
                # compaction may have opened room for files that were stuck
                self.defrag_pass()
        self.mover.commit()
        self.mover.close()


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------


@dataclass
class Report:
    files: int
    streams: int
    fragmented: int
    fragments: int
    excess: int
    frag_bytes: int
    used_bytes: int
    free_bytes: int
    free_extents: int
    largest_free: int
    mft_fragments: int
    tail_lcn: int
    top: List[Tuple[int, int, str]]


def make_report(vol: Volume, opts: Optional[Options] = None, top_n: int = 15, zone: Tuple[int, int] = (0, 0)) -> Report:
    opts = opts or Options()
    files = sum(1 for f in vol.files.values() if f.num >= FIRST_USER_RECORD and not f.is_dir)
    user = [s for s in vol.streams.values() if s.base >= FIRST_USER_RECORD and s.clusters > 0]
    lim = opts.ignore_fragments_over

    def frag(s: Stream) -> bool:
        e = s.extents
        return len(e) > 1 and not (lim and all(n * vol.cluster >= lim for _, n in e))

    fr = [s for s in user if frag(s)]
    free = free_extents_from_bitmap(vol.bitmap, vol.total_clusters)
    mft = vol.streams.get((FILE_MFT, AT_DATA, ""))
    tail = max((s.extents[-1][0] + s.extents[-1][1] for s in user if s.extents), default=0)
    top = sorted(fr, key=lambda s: -s.fragments)[:top_n]
    return Report(
        files=files,
        streams=len(user),
        fragmented=len(fr),
        fragments=sum(s.fragments for s in user),
        excess=sum(s.fragments - 1 for s in fr),
        frag_bytes=sum(s.clusters for s in fr) * vol.cluster,
        used_bytes=sum(s.clusters for s in user) * vol.cluster,
        free_bytes=sum(n for _, n in free) * vol.cluster,
        free_extents=len(free),
        largest_free=max((n for _, n in free), default=0) * vol.cluster,
        mft_fragments=mft.fragments if mft else 0,
        tail_lcn=tail,
        top=[(s.fragments, s.clusters * vol.cluster, f"{vol.path_of(s.base)}{s.describe()}" if opts.show_paths else f"[rec {s.base}]{s.describe()}") for s in top],
    )


def print_report(vol: Volume, r: Report, title: str) -> None:
    print(f"--- {title} ---")
    print(f"  files: {r.files}   non-resident streams: {r.streams}   MFT fragments: {r.mft_fragments}")
    pct = 100.0 * r.frag_bytes / r.used_bytes if r.used_bytes else 0.0
    print(
        f"  fragmented streams: {r.fragmented} ({fmt_bytes(r.frag_bytes)}, {pct:.1f}% of data)"
        f"   excess fragments: {r.excess}"
    )
    print(
        f"  free space: {fmt_bytes(r.free_bytes)} in {r.free_extents} extents, "
        f"largest {fmt_bytes(r.largest_free)}"
    )
    print(f"  end of last user data: {100.0 * r.tail_lcn / max(1, vol.total_clusters):.1f}% of the volume")
    if r.top:
        print("  most fragmented:")
        for n, b, name in r.top:
            print(f"    {n:7d} frags {fmt_bytes(b):>11s}  {name}")


def print_map(vol: Volume, width: int = 64, rows: int = 16) -> None:
    cells = width * rows
    per = max(1, -(-vol.total_clusters // cells))
    frag_bm = bytearray(len(vol.bitmap))
    for s in vol.streams.values():
        if s.base >= FIRST_USER_RECORD and s.fragments > 1:
            for lcn, n in s.extents:
                set_bits(frag_bm, lcn, n, True)
    line = ""
    print(f"  cluster map ({fmt_bytes(per * vol.cluster)} per cell; . free  - partly used  # full  X fragmented)")
    for c in range(cells):
        a = c * per
        n = min(per, vol.total_clusters - a)
        if n <= 0:
            break
        u = count_set_bits(vol.bitmap, a, n)
        fz = count_set_bits(frag_bm, a, n)
        ch = "X" if fz else ("." if u == 0 else "#" if u == n else "-")
        line += ch
        if len(line) == width:
            print("   " + line)
            line = ""
    if line:
        print("   " + line)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def open_volume(path: str, writable: bool) -> Volume:
    vol = Volume(path, writable)
    vol.scan(progress=sys.stderr.isatty())
    return vol


def preflight(vol: Volume, force: bool) -> None:
    flags, ver = vol.volume_flags()
    if ver[0] < 3:
        raise NtfsError(f"NTFS version {ver[0]}.{ver[1]} is not supported")
    problems = []
    if flags & VOLUME_IS_DIRTY:
        problems.append("volume is marked DIRTY - run chkdsk (Windows) or ntfsfix first")
    ls = vol.logfile_state()
    if ls == "dirty":
        problems.append("$LogFile is not clean (unclean shutdown or Windows Fast Startup) - boot Windows and shut it down fully")
    if vol.hibernated():
        problems.append("Windows is hibernated on this volume (hiberfil.sys) - resume and shut down Windows first")
    if problems and not force:
        raise NtfsError("refusing to write:\n  - " + "\n  - ".join(problems))
    for p in problems:
        print(f"[warning] {p} (--force given)")


def cmd_analyze(args: argparse.Namespace) -> int:
    vol = open_volume(args.device, False)
    try:
        opts = Options(show_paths=not args.anonymize, ignore_fragments_over=int(args.ignore_fragments_over * MiB))
        print(f"NTFS volume {args.device}: {fmt_bytes(vol.total_clusters * vol.cluster)}, "
              f"cluster {vol.cluster} B, MFT record {vol.rec_size} B, serial {vol.serial:016x}")
        flags, ver = vol.volume_flags()
        print(f"  NTFS {ver[0]}.{ver[1]}, flags 0x{flags:04x}, $LogFile: {vol.logfile_state()}"
              f"{', HIBERNATED' if vol.hibernated() else ''}")
        print_report(vol, make_report(vol, opts, args.top), "fragmentation")
        if args.map:
            print_map(vol)
        chk = check_volume(vol)
        for e in chk.errors:
            print(f"  [ERROR] {e}")
        for w in chk.warnings:
            print(f"  [warn] {w}")
        return 0 if chk.ok else 2
    finally:
        vol.close()


def cmd_check(args: argparse.Namespace) -> int:
    vol = open_volume(args.device, False)
    try:
        chk = check_volume(vol)
        for e in chk.errors:
            print(f"[ERROR] {e}")
        for w in chk.warnings:
            print(f"[warn] {w}")
        print("consistent" if chk.ok else "INCONSISTENT")
        return 0 if chk.ok else 2
    finally:
        vol.close()


def cmd_recover(args: argparse.Namespace) -> int:
    vol = Volume(args.device, True)
    try:
        j = Journal(args.journal or default_journal_path(vol.serial))
        print(recover(vol, j))
        vol.scan()
        chk = check_volume(vol)
        dirty = vol.volume_flags()[0] & VOLUME_IS_DIRTY
        if chk.ok and dirty and (j.has_marker() or args.clear_dirty):
            vol.set_volume_dirty(False)
            j.set_marker(False)
            print("[recover] dirty flag (set by ntfsdefrag) cleared")
        print("consistent" if chk.ok else "INCONSISTENT: " + "; ".join(chk.errors[:5]))
        return 0 if chk.ok else 2
    finally:
        vol.close()


def cmd_defrag(args: argparse.Namespace) -> int:
    opts = Options(
        dry_run=args.dry_run,
        verify=not args.no_verify,
        compact=args.compact,
        passes=args.passes,
        buffer_bytes=int(args.buffer_mb * MiB),
        mft_zone_clusters=None,
        max_evacuation_ratio=args.evacuation_ratio,
        min_chunk_bytes=int(args.min_chunk_mb * MiB),
        ignore_fragments_over=int(args.ignore_fragments_over * MiB),
        verbose=args.verbose,
        show_paths=not args.anonymize,
        time_limit=args.time_limit * 60,
    )
    vol = Volume(args.device, not args.dry_run)
    try:
        if args.mft_zone_mb is not None:
            opts.mft_zone_clusters = int(args.mft_zone_mb * MiB) // vol.cluster
        journal = None
        if not args.dry_run:
            journal = Journal(args.journal or default_journal_path(vol.serial))
            doc = journal.read()
            if doc is not None:
                print("[recover] unfinished transaction found from a previous run")
                recover(vol, journal)
        vol.scan(progress=sys.stderr.isatty())
        print(f"NTFS volume {args.device}: {fmt_bytes(vol.total_clusters * vol.cluster)}, cluster {vol.cluster} B"
              f"{' [DRY RUN]' if args.dry_run else ''}")
        chk = check_volume(vol)
        if not chk.ok:
            for e in chk.errors:
                print(f"[ERROR] {e}")
            print("refusing to defragment an inconsistent volume (fix it with chkdsk first)")
            return 2
        dirty_by_us = False
        if not args.dry_run:
            assert journal is not None
            if vol.volume_flags()[0] & VOLUME_IS_DIRTY and journal.has_marker():
                # left dirty by an interrupted ntfsdefrag run; the volume checked out fine
                vol.set_volume_dirty(False)
            preflight(vol, args.force)
            if not vol.volume_flags()[0] & VOLUME_IS_DIRTY:
                journal.set_marker(True)
                vol.set_volume_dirty(True)
                dirty_by_us = True
        before = make_report(vol, opts, args.top)
        print_report(vol, before, "before")
        d = Defragmenter(vol, opts, journal)
        if d.zone[1] > d.zone[0]:
            print(f"  MFT zone kept free: LCN {d.zone[0]}..{d.zone[1]} ({fmt_bytes((d.zone[1] - d.zone[0]) * vol.cluster)})")
        old_int = signal.signal(signal.SIGINT, _on_signal)
        old_term = signal.signal(signal.SIGTERM, _on_signal)
        t0 = time.monotonic()
        try:
            d.run()
        finally:
            signal.signal(signal.SIGINT, old_int)
            signal.signal(signal.SIGTERM, old_term)
        el = time.monotonic() - t0
        after = make_report(vol, opts, args.top)
        print_report(vol, after, "after (simulated)" if args.dry_run else "after")
        s = d.stats
        print(
            f"moves: {s.moves} ({fmt_bytes(s.moved_clusters * vol.cluster)} relocated), "
            f"fully defragmented: {s.defragmented}, improved: {s.improved}, "
            f"evacuated: {s.evacuations}, compacted: {s.compacted}, groups: {s.groups}, time {fmt_duration(el)}"
        )
        for why, n in sorted(s.skipped.items(), key=lambda x: -x[1]):
            print(f"  not moved ({n}): {why}")
        if not args.dry_run:
            # independent re-read of everything from disk
            vol.dev.flush()
            vol.scan()
            chk = check_volume(vol)
            if chk.ok and dirty_by_us:
                vol.set_volume_dirty(False)
                assert journal is not None
                journal.set_marker(False)
            print("post-check: " + ("consistent" if chk.ok else "INCONSISTENT: " + "; ".join(chk.errors[:5])))
            if not chk.ok:
                return 2
        return 130 if STOP else 0
    finally:
        vol.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ntfsdefrag.py",
        description="Offline in-place NTFS defragmenter (the volume must NOT be mounted).",
    )
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd")

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("device", help="block device (e.g. /dev/sdX1) or image file")
        sp.add_argument("--anonymize", action="store_true", help="do not print file names")
        sp.add_argument("--top", type=int, default=15, help="how many of the most fragmented files to list")
        sp.add_argument("--ignore-fragments-over", type=float, default=0, metavar="MiB",
                        help="treat a file as unfragmented if all its fragments are at least this big (0 = off)")

    a = sub.add_parser("analyze", help="read-only fragmentation report")
    common(a)
    a.add_argument("--map", action="store_true", help="print a cluster map")
    a.set_defaults(func=cmd_analyze)

    c = sub.add_parser("check", help="read-only consistency check")
    c.add_argument("device")
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("recover", help="finish/roll back an interrupted run")
    r.add_argument("device")
    r.add_argument("--journal")
    r.add_argument("--clear-dirty", action="store_true", help="clear the volume dirty flag if consistent")
    r.set_defaults(func=cmd_recover)

    d = sub.add_parser("defrag", help="defragment")
    common(d)
    d.add_argument("--dry-run", action="store_true", help="simulate only, write nothing")
    d.add_argument("--compact", action="store_true",
                   help="also move files towards the start of the disk (consolidates free space; much more I/O)")
    d.add_argument("--passes", type=int, default=3)
    d.add_argument("--buffer-mb", type=float, default=64)
    d.add_argument("--no-verify", action="store_true", help="skip read-back verification of copied data")
    d.add_argument("--evacuation-ratio", type=float, default=2.0,
                   help="max data moved out of the way per byte of the file being defragmented")
    d.add_argument("--min-chunk-mb", type=float, default=64,
                   help="partial defragmentation never creates fragments smaller than this")
    d.add_argument("--mft-zone-mb", type=float, default=None,
                   help="free space kept after $MFT for its growth (default: auto, 0 = none)")
    d.add_argument("--time-limit", type=float, default=0, metavar="MIN", help="stop cleanly after MIN minutes")
    d.add_argument("--journal", help="journal file (default ~/.local/state/ntfsdefrag/<serial>.journal)")
    d.add_argument("--force", action="store_true", help="ignore dirty/hibernation/$LogFile safety checks")
    d.add_argument("-v", "--verbose", action="store_true")
    d.set_defaults(func=cmd_defrag)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("analyze", "check", "defrag", "recover", "-h", "--help", "--version"):
        argv.insert(0, "analyze")
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 1
    try:
        return args.func(args)
    except NtfsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
