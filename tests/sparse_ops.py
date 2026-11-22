#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Sparse-file workload with an in-memory reference model (runs anywhere, used
inside the test VM on NTFS mounts of the kernel ntfs/ntfs3 drivers and ntfs-3g).

  sparse_ops.py PATH CLUSTER SEED EXPECT.json [--new [--simple|--dense]]
                [--no-range] [--pwrite-only]

Applies a deterministic (SEED) sequence of operations sized in CLUSTER units to
PATH (a file or a "file:stream" path) and to a bytearray model, re-reading the
whole file after each group and exiting non-zero on the first mismatch:
  --new          create PATH (sparse: truncate + scattered writes)
  --simple       with --new: only the creation step (seek-writes leaving holes)
  --dense        with --new: one contiguous 6 MiB write, no holes
  default        writes into holes, extension past EOF, aligned and unaligned
                 FALLOC_FL_PUNCH_HOLE, truncate down/up, fallocate (with and
                 without KEEP_SIZE), COLLAPSE_RANGE and INSERT_RANGE
  --no-range     skip COLLAPSE/INSERT_RANGE
  --pwrite-only  only pwrite/truncate (for drivers without fallocate, e.g. ntfs-3g)
The expected sha256 and size of PATH are merged into EXPECT.json (keyed by the
path), for verify_tree.py --expect after remounts or with other drivers."""
import ctypes, ctypes.util, hashlib, json, os, random, sys

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
KEEP, PUNCH, COLLAPSE, INSERT = 0x01, 0x02, 0x08, 0x20

path, cs, seed, expf = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
new = "--new" in sys.argv
no_range = "--no-range" in sys.argv
rnd = random.Random(seed)
log = []

def fall(fd, mode, off, ln):
    r = libc.fallocate(fd, mode, off, ln)
    if r:
        e = ctypes.get_errno()
        raise OSError(e, f"fallocate(mode={mode:#x}, {off}, {ln}): {os.strerror(e)}")

if new:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
    model = bytearray()
else:
    fd = os.open(path, os.O_RDWR)
    with open(path, "rb") as f:
        model = bytearray(f.read())

def pwrite(off, ln):
    data = rnd.randbytes(ln)
    os.pwrite(fd, data, off)
    if off > len(model):
        model.extend(bytes(off - len(model)))
    model[off:off + ln] = data
    log.append(f"pwrite {off} {ln}")

def trunc(sz):
    os.ftruncate(fd, sz)
    if sz < len(model):
        del model[sz:]
    else:
        model.extend(bytes(sz - len(model)))
    log.append(f"truncate {sz}")

PWRITE_ONLY = "--pwrite-only" in sys.argv

def punch(off, ln):
    if PWRITE_ONLY:
        ln = min(off + ln, len(model)) - off
        if ln > 0:
            os.pwrite(fd, bytes(ln), off)
            model[off:off + ln] = bytes(ln)
        log.append(f"zero {off} {ln}")
        return
    fall(fd, PUNCH | KEEP, off, ln)
    end = min(off + ln, len(model))
    if off < end:
        model[off:end] = bytes(end - off)
    log.append(f"punch {off} {ln}")

def alloc(off, ln, keep):
    if PWRITE_ONLY:
        return
    fall(fd, KEEP if keep else 0, off, ln)
    if not keep and off + ln > len(model):
        model.extend(bytes(off + ln - len(model)))
    log.append(f"falloc{' keep' if keep else ''} {off} {ln}")

def collapse(off, ln):
    fall(fd, COLLAPSE, off, ln)
    del model[off:off + ln]
    log.append(f"collapse {off} {ln}")

def insert(off, ln):
    fall(fd, INSERT, off, ln)
    model[off:off] = bytes(ln)
    log.append(f"insert {off} {ln}")

def check(tag):
    os.fsync(fd)
    with open(path, "rb") as f:
        got = f.read()
    if got != bytes(model):
        bad = next((i for i in range(min(len(got), len(model))) if got[i] != model[i]), None)
        sys.exit(f"MISMATCH after {tag}: size {len(got)} vs {len(model)}, first diff at {bad}; log={log}")

try:
    if new and "--dense" in sys.argv:
        pwrite(0, (6 << 20) + 123)
        raise StopIteration
    if new:
        trunc(48 << 20)                       # sparse from birth
        pwrite(5 * cs + 333, 7000)
        pwrite(1 << 20, 3 * cs)
        pwrite((30 << 20) + 17, 100000)
    else:
        pwrite(3 * cs + 4097, 9000)           # likely into a hole
    check("seed")
    if "--simple" in sys.argv:
        pwrite(len(model) + 40 * cs + 5, 3 * cs)
        check("simple")
        raise StopIteration
    sz = len(model)
    pwrite(sz + 5 * cs + 77, (1 << 20) + 5)    # extend past EOF leaving a hole
    pwrite(33 * cs, 2 * cs)                    # cluster-aligned overwrite
    punch(3 * cs + 100, 20 * cs)               # unaligned punch
    punch(64 * cs, 32 * cs)                    # aligned punch
    check("punch")
    trunc(len(model) - 2 * cs - 5)
    trunc(len(model) + (3 << 20))              # extend with hole
    pwrite(len(model) - 50, 100)
    alloc(40 * cs, 4 * cs, False)
    alloc(len(model) + cs, 2 * cs, True)       # beyond EOF, keep size
    check("alloc")
    if not no_range and not PWRITE_ONLY:
        collapse(8 * cs, 16 * cs)
        insert(4 * cs, 8 * cs)
        check("range")
    pwrite(10 * cs + 1, 3 * cs)                # rewrite into inserted hole
    punch(0, cs)
    check("final")
except StopIteration:
    pass
finally:
    os.close(fd)

exp = {}
if os.path.exists(expf):
    exp = json.load(open(expf))
exp[path] = {"sha256": hashlib.sha256(model).hexdigest(), "size": len(model)}
json.dump(exp, open(expf, "w"), indent=1)
print(f"OK {path} size={len(model)} ops={len(log)}")
