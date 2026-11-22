#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare file contents on a mounted NTFS volume with expected SHA-256 sums.

  verify_tree.py ROOT [--manifest FIXTURE.json [--ads] [--skip REL]...]
                      [--expect EXPECT.json]...

--manifest  fixture manifest (JSON next to a fixture image, see FIXTURES):
            every entry with a sha256 is read under ROOT; --ads also reads the
            fixture's alternate data streams as "host:stream" (needs a driver
            with a Windows-style stream interface, e.g. the kernel ntfs driver
            mounted with streams_interface=windows, or ntfs-3g)
--skip      manifest-relative path to leave out (e.g. a file modified on purpose)
--expect    expectation file written by sparse_ops.py (absolute paths; ROOT is
            ignored for these, so mount at the same place as when writing)
Prints every mismatch and "verify ROOT: ok=N bad=M"; exit status 1 on mismatch.
Example: verify_tree.py /mnt --expect /var/tmp/sparse/exp-512.json
"""
import hashlib, json, os, sys


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
    print(__doc__.strip())
    sys.exit(0 if len(sys.argv) > 1 else 2)
root, args = sys.argv[1], sys.argv[2:]
def opts(n):
    return [args[i + 1] for i, a in enumerate(args) if a == n]
skip = set(opts("--skip"))
ok = bad = 0

def check(p, want_sha, want_size=None):
    global ok, bad
    try:
        if sha(p) == want_sha and (want_size is None or os.path.getsize(p) == want_size):
            ok += 1
        else:
            bad += 1
            print("DIFF", p)
    except OSError as e:
        bad += 1
        print("ERR", p, e)

for mf in opts("--manifest"):
    m = json.load(open(mf))
    for rel, meta in m["manifest"].items():
        if "sha256" in meta and rel not in skip:
            check(os.path.join(root, rel), meta["sha256"])
    if "--ads" in args:
        host = os.path.join(root, m["info"]["ads_host"])
        for name, h in m["ads"].items():
            check(host + ":" + name, h)
for ef in opts("--expect"):
    for p, meta in json.load(open(ef)).items():
        check(p, meta["sha256"], meta["size"])
print(f"verify {root}: ok={ok} bad={bad}")
sys.exit(1 if bad else 0)
