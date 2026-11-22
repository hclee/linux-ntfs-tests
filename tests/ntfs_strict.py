#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Strict on-disk checks of an NTFS image for the crash tests, built on the
parser of this repo (ntfsdefrag.py):

  - stream_runs(vol, num): the unnamed $DATA of file record `num`, found the
    way a driver finds it: through the attribute list when there is one. Each
    list entry must name an in-use extent record of this file with the same
    sequence number, holding the extent with the listed lowest VCN, and the
    extents must cover [0, allocated size) without gap or overlap. Extent
    records of the file that the list does not name are reported too.
  - bitmap_problems(vol): clusters that a stream uses but $Bitmap calls free,
    and clusters two streams use; returns (problems, leaked clusters).
  - volume_flags(vol): the flags of $VOLUME_INFORMATION (0x0001 = dirty).

  ntfs_strict.py IMG FILE_RECORD...   prints the checks for an image
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ntfsdefrag as proto  # noqa: E402

AT_VOLUME_INFORMATION = 0x70


class Corrupt(Exception):
    pass


def attr_list_entries(vol, rec):
    """(type, name, lowest_vcn, record, sequence) of the attribute list of rec, or None."""
    al = [a for a in rec.attrs if a.type == proto.AT_ATTRIBUTE_LIST]
    if not al:
        return None
    a = al[0]
    data = vol.read_stream_bytes(a.runs, a.data_size) if a.nonresident else a.value
    out = []
    pos = 0
    while pos + 26 <= len(data):
        typ, rlen, nlen, noff = struct.unpack_from("<IHBB", data, pos)
        if rlen < 26 or pos + rlen > len(data):
            raise Corrupt(f"record {rec.num}: bad attribute list entry at {pos}")
        lowest, ref = struct.unpack_from("<qQ", data, pos + 8)
        name = data[pos + noff:pos + noff + 2 * nlen].decode("utf-16-le", "replace")
        out.append((typ, name, lowest, ref & proto.REF_MASK, ref >> 48))
        pos += rlen
    return out


def stream_runs(vol, num, typ=proto.AT_DATA, name=""):
    """(runs, data size) of a non-resident stream of base record num."""
    rec, _ = vol.read_record(num)
    if not rec.flags & proto.MFT_RECORD_IN_USE or rec.base:
        raise Corrupt(f"record {num} is not an in-use base record")
    entries = attr_list_entries(vol, rec)
    if entries is None:
        segs = [a for a in rec.attrs if a.type == typ and a.name == name]
        if len(segs) != 1:
            raise Corrupt(f"record {num}: {len(segs)} extents of the stream without an attribute list")
    else:
        segs = []
        named = set()
        for etyp, ename, lowest, ref, seq in entries:
            if etyp != typ or ename != name:
                continue
            named.add(ref)
            r = rec if ref == num else vol.read_record(ref)[0]
            if ref != num:
                if not r.flags & proto.MFT_RECORD_IN_USE:
                    raise Corrupt(f"record {num}: attribute list names record {ref}, which is free")
                if r.base != num or r.seq != seq:
                    raise Corrupt(f"record {num}: attribute list names record {ref} seq {seq}, "
                                  f"which belongs to {r.base} seq {r.seq}")
            seg = [a for a in r.attrs if a.type == typ and a.name == name and a.nonresident
                   and a.lowest_vcn == lowest]
            if len(seg) != 1:
                raise Corrupt(f"record {num}: record {ref} has no extent starting at VCN {lowest}")
            segs.append(seg[0])
        orphans = [n for n, r in vol.records.items()
                   if r.base == num and n not in named and
                   any(a.type == typ and a.name == name for a in r.attrs)] if vol.records else []
        if orphans:
            raise Corrupt(f"record {num}: extent records {orphans} are not in the attribute list")
    if not segs or not segs[0].nonresident:
        raise Corrupt(f"record {num}: the stream is resident or missing")
    expect = 0
    runs = []
    for s in segs:
        if s.lowest_vcn != expect:
            raise Corrupt(f"record {num}: extent at VCN {s.lowest_vcn}, expected {expect}")
        runs += s.runs
        expect = s.highest_vcn + 1
    if expect * vol.cluster != segs[0].alloc_size:
        raise Corrupt(f"record {num}: extents end at VCN {expect}, allocated size "
                      f"{segs[0].alloc_size}")
    return runs, segs[0].data_size


def bitmap_problems(vol):
    """Compare $Bitmap with the clusters the streams use (vol.scan() first)."""
    total = vol.total_clusters
    used = bytearray(total)
    problems = []
    for (num, typ, name), st in vol.streams.items():
        for r in st.runs:
            if r.lcn is None:
                continue
            if r.lcn < 0 or r.lcn + r.length > total:
                problems.append(f"record {num} type {typ:#x}: run {r.lcn}+{r.length} outside the volume")
                continue
            seg = used[r.lcn:r.lcn + r.length]
            if any(seg):
                problems.append(f"record {num} type {typ:#x}: clusters {r.lcn}+{r.length} cross-linked")
            used[r.lcn:r.lcn + r.length] = b"\1" * r.length
    bm = vol.bitmap
    lost = leaked = 0
    first_lost = None
    for lcn in range(total):
        bit = bm[lcn >> 3] >> (lcn & 7) & 1
        if used[lcn] and not bit:
            lost += 1
            first_lost = lcn if first_lost is None else first_lost
        elif bit and not used[lcn]:
            leaked += 1
    if lost:
        problems.append(f"$Bitmap: {lost} used clusters marked free (first {first_lost})")
    return problems, leaked


def data_extents(path, num):
    """Number of extents of the unnamed $DATA of record num of an image or
    device (1 without an attribute list). Sync and drop caches first when
    the volume is mounted."""
    vol = proto.Volume(path, allow_mounted=True)
    try:
        rec, _ = vol.read_record(num)
        entries = attr_list_entries(vol, rec)
        if entries is None:
            return 1
        return sum(1 for t, n, *_ in entries if t == proto.AT_DATA and n == "")
    finally:
        vol.close()


def extents_info(path, num):
    """The extents of the unnamed $DATA of record num, in VCN order, as dicts:
    rec (MFT record), lowest, highest, mp_offset, length (of the attribute
    record), free (unused bytes of the MFT record), runs."""
    vol = proto.Volume(path, allow_mounted=True)
    try:
        rec, _ = vol.read_record(num)
        entries = attr_list_entries(vol, rec)
        refs = [num] if entries is None else \
            [ref for t, n, _lo, ref, _s in entries if t == proto.AT_DATA and n == ""]
        out = []
        for ref in dict.fromkeys(refs):
            r = rec if ref == num else vol.read_record(ref)[0]
            for a in r.attrs:
                if a.type == proto.AT_DATA and a.name == "" and a.nonresident:
                    out.append({"rec": ref, "lowest": a.lowest_vcn, "highest": a.highest_vcn,
                                "mp_offset": a.mp_offset, "length": a.length,
                                "free": r.bytes_alloc - r.bytes_in_use, "runs": a.runs})
        return sorted(out, key=lambda e: e["lowest"])
    finally:
        vol.close()


def _nbytes(v):
    n = 1
    while not -(1 << (8 * n - 1)) <= v < 1 << (8 * n - 1):
        n += 1
    return n


def mapping_pairs_size(runs):
    """Bytes of the mapping pairs of runs [(vcn, lcn or None, length)] (NTFS 3.x)."""
    size, prev = 1, 0
    for _v, lcn, n in runs:
        size += 1 + _nbytes(n)
        if lcn is not None:
            size += _nbytes(lcn - prev)
            prev = lcn
    return size


def replace_runs(runs, vcn, n, lcn):
    """runs [(vcn, lcn, length)] with [vcn, vcn + n) moved to lcn, physically
    contiguous neighbours merged (what the driver's runlist switch does)."""
    pieces = []
    for v, l, ln in runs:
        for a, b in ((v, min(v + ln, vcn)), (max(v, vcn), min(v + ln, vcn + n)), (max(v, vcn + n), v + ln)):
            if a < b:
                inside = vcn <= a and b <= vcn + n
                pieces.append((a, None if l is None else (lcn + a - vcn if inside else l + a - v), b - a))
    out = []
    for v, l, ln in pieces:
        if out and out[-1][0] + out[-1][2] == v and (
                (l is None and out[-1][1] is None) or
                (l is not None and out[-1][1] is not None and out[-1][1] + out[-1][2] == l)):
            out[-1] = (out[-1][0], out[-1][1], out[-1][2] + ln)
        else:
            out.append((v, l, ln))
    return out


def volume_flags(vol):
    rec, _ = vol.read_record(proto.FILE_VOLUME)
    for a in rec.attrs:
        if a.type == AT_VOLUME_INFORMATION and not a.nonresident:
            return struct.unpack_from("<H", a.value, 10)[0]
    raise Corrupt("no $VOLUME_INFORMATION")


if __name__ == "__main__":
    vol = proto.Volume(sys.argv[1], allow_mounted=True)
    vol.scan()
    print(f"flags {volume_flags(vol):#06x}", bitmap_problems(vol))
    for n in sys.argv[2:]:
        runs, size = stream_runs(vol, int(n))
        print(n, size, len(runs), "runs")
