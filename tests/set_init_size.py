#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Set the initialized size of the unnamed $DATA attribute of a file on an
unmounted NTFS image, as Windows leaves it after SetFileValidData() or an
extension without zeroing (fs/ntfs never writes such a file itself).

    set_init_size.py IMAGE FILENAME NEW_INIT_SIZE

Only for test images: it finds the file by its $FILE_NAME in the first 1024
MFT records, rewrites the field in place and keeps the update sequence.
Example: set_init_size.py /mnt/k.img f 0
"""
import struct
import sys

if len(sys.argv) != 4 or sys.argv[1] in ("-h", "--help"):
    print(__doc__.strip())
    sys.exit(0 if len(sys.argv) > 1 else 2)
img, name, new_init = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(img, "r+b") as f:
    boot = f.read(512)
    bps = struct.unpack_from("<H", boot, 0x0B)[0]
    spc = boot[0x0D]
    cs = bps * spc
    mft_lcn = struct.unpack_from("<q", boot, 0x30)[0]
    cpr = struct.unpack_from("<b", boot, 0x40)[0]
    rec_size = cs * cpr if cpr > 0 else 1 << -cpr
    for i in range(1024):
        off = mft_lcn * cs + i * rec_size
        f.seek(off)
        raw = bytearray(f.read(rec_size))
        if raw[:4] != b"FILE":
            continue
        usa_ofs, usa_cnt = struct.unpack_from("<HH", raw, 4)
        rec = bytearray(raw)
        for k in range(1, usa_cnt):     # undo the fixups to parse
            rec[k * bps - 2:k * bps] = raw[usa_ofs + 2 * k:usa_ofs + 2 * k + 2]
        a = struct.unpack_from("<H", rec, 0x14)[0]
        found, data = False, None
        while a + 8 <= rec_size:
            typ, alen = struct.unpack_from("<II", rec, a)
            if typ == 0xFFFFFFFF or alen == 0:
                break
            nonres, nlen = rec[a + 8], rec[a + 9]
            if typ == 0x30 and not nonres:
                v = a + struct.unpack_from("<H", rec, a + 0x14)[0]
                fnlen = rec[v + 0x40]
                if rec[v + 0x42:v + 0x42 + 2 * fnlen].decode("utf-16-le") == name:
                    found = True
            if typ == 0x80 and nonres and nlen == 0:
                data = a
            a += alen
        if not found or data is None:
            continue
        pos = data + 0x38
        for k in range(1, usa_cnt):
            if pos < k * bps and pos + 8 > k * bps - 2:
                sys.exit("initialized size field overlaps a fixup; not handled")
        size = struct.unpack_from("<q", rec, data + 0x30)[0]
        if new_init > size:
            sys.exit(f"{new_init} is past the data size {size}")
        struct.pack_into("<q", raw, pos, new_init)
        f.seek(off)
        f.write(raw)
        print(f"record {i}: initialized size {new_init} (data size {size})")
        sys.exit(0)
sys.exit(f"no file named {name} with a non-resident $DATA")
