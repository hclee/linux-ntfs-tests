#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Print the volume flags of an unmounted NTFS image as hex (e.g. 0x0001 =
VOLUME_IS_DIRTY), read from $VOLUME_INFORMATION in $Volume (MFT record 3).
Works on dirty volumes that some tools refuse to open.

  volume_flags.py IMG"""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dump_attr_headers import read_record

with open(sys.argv[1], "rb") as f:
    rec = read_record(f, 3)
a = struct.unpack_from("<H", rec, 0x14)[0]
while True:
    t, ln = struct.unpack_from("<II", rec, a)
    if t == 0xFFFFFFFF or ln == 0:
        sys.exit("no $VOLUME_INFORMATION")
    if t == 0x70:
        vo = struct.unpack_from("<H", rec, a + 0x14)[0]
        print(f"{struct.unpack_from('<H', rec, a + vo + 10)[0]:#06x}")
        break
    a += ln
