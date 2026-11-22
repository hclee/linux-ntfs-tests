#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Dump the raw attribute record headers of NTFS MFT records (what the drivers
validate when they enumerate attributes, e.g. ntfs3's mi_enum_attr()).

  dump_attr_headers.py IMG MFTNO...

For every attribute: offset, type, length, name, flags, and for non-resident
ones lowest/highest VCN, mapping pairs offset, compression unit,
allocated/data/initialized size and, if the header has room for it, the
compressed size. Follows the runlist of $MFT's unnamed $DATA (record 0), so
any record can be dumped as long as $MFT has no extent records. Read-only."""
import struct, sys

NAMES = {0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
         0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
         0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
         0xa0: "$INDEX_ALLOCATION", 0xb0: "$BITMAP", 0xc0: "$REPARSE_POINT",
         0xd0: "$EA_INFORMATION", 0xe0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM"}

def geometry(f):
    f.seek(0)
    bs = f.read(512)
    spc = bs[13]
    cs = struct.unpack_from("<H", bs, 11)[0] * ((1 << (256 - spc)) if spc > 128 else spc)
    c = struct.unpack_from("<b", bs, 0x40)[0]
    return cs, struct.unpack_from("<q", bs, 0x30)[0], c * cs if c > 0 else 1 << -c

def fixup(rec):
    usa_ofs, usa_cnt = struct.unpack_from("<HH", rec, 4)
    for i in range(1, usa_cnt):
        p = i * 512 - 2
        rec[p:p + 2] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    return rec

def runlist(mp):
    """decode mapping pairs -> [(vcn, lcn or None, length)]"""
    runs, vcn, lcn, i = [], 0, 0, 0
    while i < len(mp) and mp[i]:
        lsz, osz = mp[i] & 0xf, mp[i] >> 4
        ln = int.from_bytes(mp[i + 1:i + 1 + lsz], "little")
        if osz:
            lcn += int.from_bytes(mp[i + 1 + lsz:i + 1 + lsz + osz], "little", signed=True)
            runs.append((vcn, lcn, ln))
        else:
            runs.append((vcn, None, ln))
        vcn += ln
        i += 1 + lsz + osz
    return runs

MFT_RUNS = None

def read_record(f, mftno):
    global MFT_RUNS
    cs, mft_lcn, rs = geometry(f)
    if MFT_RUNS is None:
        f.seek(mft_lcn * cs)
        r0 = fixup(bytearray(f.read(rs)))
        a = struct.unpack_from("<H", r0, 0x14)[0]
        while True:
            t, ln = struct.unpack_from("<II", r0, a)
            if t == 0x80 and r0[a + 8] and not r0[a + 9]:
                mpo = struct.unpack_from("<H", r0, a + 0x20)[0]
                MFT_RUNS = runlist(r0[a + mpo:a + ln])
                break
            a += ln
    byte = mftno * rs
    for vcn, lcn, ln in MFT_RUNS:
        if vcn * cs <= byte < (vcn + ln) * cs and lcn is not None:
            f.seek(lcn * cs + byte - vcn * cs)
            break
    else:
        return bytearray(rs)
    rec = bytearray(f.read(rs))
    usa_ofs, usa_cnt = struct.unpack_from("<HH", rec, 4)
    for i in range(1, usa_cnt):
        p = i * 512 - 2
        rec[p:p + 2] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    return rec

def dump(img, mftno):
    with open(img, "rb") as f:
        rec = read_record(f, mftno)
    if rec[:4] != b"FILE":
        print(f"record {mftno}: no FILE signature")
        return
    flags, used, alloc = struct.unpack_from("<HII", rec, 0x16)
    base = struct.unpack_from("<Q", rec, 0x20)[0] & 0xFFFFFFFFFFFF
    print(f"record {mftno}: flags={flags:#x} used={used} allocated={alloc} base={base}")
    a = struct.unpack_from("<H", rec, 0x14)[0]
    while a + 8 <= used:
        t, ln = struct.unpack_from("<II", rec, a)
        if t == 0xFFFFFFFF:
            break
        nr, nlen, noff, aflags, inst = rec[a + 8], rec[a + 9], *struct.unpack_from("<HHH", rec, a + 10)
        name = rec[a + noff:a + noff + 2 * nlen].decode("utf-16-le") if nlen else ""
        s = f"  @{a:#05x} {NAMES.get(t, hex(t))}{':' + name if name else ''} len={ln} flags={aflags:#06x} inst={inst}"
        if nr:
            lvcn, hvcn, mpo, cu = struct.unpack_from("<qqHB", rec, a + 0x10)
            asz, dsz, isz = struct.unpack_from("<qqq", rec, a + 0x28)
            s += f" nonres lvcn={lvcn} hvcn={hvcn} mp_off={mpo} cu={cu} alloc={asz} data={dsz} init={isz}"
            if mpo >= 0x48 and ln >= 0x48:
                s += f" compressed={struct.unpack_from('<q', rec, a + 0x40)[0]}"
        else:
            vl, vo = struct.unpack_from("<IH", rec, a + 0x10)
            s += f" res value_len={vl} value_off={vo}"
        print(s)
        if ln == 0:
            break
        a += ln

if __name__ == "__main__":
    for n in sys.argv[2:]:
        dump(sys.argv[1], int(n, 0))
