#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Alter an NTFS image for driver robustness tests: overwrite the
compression_unit byte of the first non-resident $DATA attribute (named or
unnamed) of one MFT record, keeping the update-sequence fixups valid.

  set_compression_unit.py IMG MFTNO CU [named|unnamed]

Use "ntfsinfo -F /path IMG" to find MFTNO. Assumes the record lies in the
first $MFT extent (true for small, freshly made images). Prints old and new value."""
import struct, sys
img, mftno, cu = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
want_named = (sys.argv[4] if len(sys.argv) > 4 else "named") == "named"
with open(img, "r+b") as f:
    bs = f.read(512)
    bps = struct.unpack_from("<H", bs, 11)[0]
    spc = bs[13]
    spc = 1 << (256 - spc) if spc > 128 else spc
    cs = bps * spc
    mft_lcn = struct.unpack_from("<q", bs, 0x30)[0]
    c = struct.unpack_from("<b", bs, 0x40)[0]
    rs = c * cs if c > 0 else 1 << -c
    off = mft_lcn * cs + mftno * rs
    f.seek(off)
    rec = bytearray(f.read(rs))
    assert rec[:4] == b"FILE", rec[:4]
    usa_ofs, usa_cnt = struct.unpack_from("<HH", rec, 4)
    usn = rec[usa_ofs:usa_ofs + 2]
    for i in range(1, usa_cnt):	# undo fixups
        p = i * 512 - 2
        assert rec[p:p + 2] == usn
        rec[p:p + 2] = rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    a = struct.unpack_from("<H", rec, 0x14)[0]
    while True:
        t, ln = struct.unpack_from("<II", rec, a)
        if t == 0xFFFFFFFF:
            sys.exit("attribute not found")
        nr, nlen = rec[a + 8], rec[a + 9]
        if t == 0x80 and nr and bool(nlen) == want_named:
            print(f"rec {mftno} attr@{a} flags={struct.unpack_from('<H', rec, a + 12)[0]:#x} cu {rec[a + 0x22]} -> {cu}")
            rec[a + 0x22] = cu
            break
        a += ln
    for i in range(1, usa_cnt):	# redo fixups
        p = i * 512 - 2
        rec[usa_ofs + 2 * i:usa_ofs + 2 * i + 2] = rec[p:p + 2]
        rec[p:p + 2] = usn
    f.seek(off)
    f.write(rec)
