#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fragment the free space of a mounted (any driver) NTFS volume so that the
next big file needs many runs and therefore attribute-list extent records.

  make_fragmented.py MOUNTPOINT [CHUNK_BYTES [MAX_FILES]]

Fills the volume with files of CHUNK_BYTES (default 4096) under
MOUNTPOINT/frag/ until it is full (ENOSPC) or MAX_FILES (default 60000) exist,
then deletes every other one, leaving CHUNK_BYTES holes all over the volume.
Prints the number of holes."""
import errno, os, sys
mnt = sys.argv[1]
chunk = int(sys.argv[2]) if len(sys.argv) > 2 else 4096
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
d = os.path.join(mnt, "frag")
os.makedirs(d, exist_ok=True)
blob = os.urandom(chunk)
n = 0
while n < limit:
    p = os.path.join(d, f"f{n:05d}")
    try:
        with open(p, "wb") as f:
            f.write(blob)
    except OSError as e:
        if e.errno != errno.ENOSPC:
            raise
        try:
            os.unlink(p)
        except OSError:
            pass
        break
    n += 1
os.sync()
for i in range(0, n, 2):
    os.unlink(os.path.join(d, f"f{i:05d}"))
os.sync()
print(f"fragmented {mnt}: {n} files of {chunk} bytes, {(n + 1) // 2} holes")
