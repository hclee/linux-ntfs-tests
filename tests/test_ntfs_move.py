#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
In-VM tests of the fs/ntfs online defragmentation ioctls:
FS_IOC_GETFSMAP and NTFS_IOC_MOVE_CLUSTERS (plus FIEMAP).

Runs INSIDE the test VM as root (see run_kernel_tests.sh):

    python3 test_ntfs_move.py WORKDIR

WORKDIR/config.json:
    {"ntfsck": "/path/ntfsck", "prototype": "/path/ntfsdefrag.py",
     "clusters": [512, 4096, 65536], "stress_seconds": 60, "only": "regex"}

For every cluster size a fresh volume is made with mkntfs in a guest tmpfs,
loop-mounted with the in-kernel ntfs driver (mount -i -t ntfs) and
fragmented with the driver itself. After each test the volume is unmounted
and checked: ntfsck -n must be clean, the on-disk runlists and $Bitmap
(read by an independent parser, ntfsdefrag.py from the repo) must agree,
and every file must have the contents the test expects, also after a
remount. dmesg must not contain any KASAN/lockdep/UBSAN/WARNING report.

Results: WORKDIR/results.json and WORKDIR/test.log.
"""
import errno
import hashlib
import json
import mmap
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ntfs_ioctls as I  # noqa: E402
import ntfs_strict as strict  # noqa: E402

WORK = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.getcwd()
CFG = json.load(open(os.path.join(WORK, "config.json")))
NTFSCK = CFG["ntfsck"]
PROTO_DIR = os.path.dirname(os.path.abspath(CFG["prototype"]))
sys.path.insert(0, PROTO_DIR)
import ntfsdefrag as proto  # noqa: E402

TMPFS = "/mnt"                  # exists on the read-only host root shared with the VM
TMP = TMPFS + "/ntfs-move-test"
MNT = TMP + "/mnt"
LOG = open(os.path.join(WORK, "test.log"), "a", buffering=1)
DMESG_BAD = re.compile(r"BUG:|WARNING:|KASAN|UBSAN|possible circular|possible recursive|"
                       r"inconsistent lock|lockdep|Oops|general protection|"
                       r"ntfs.*(error|corrupt)|hung_task|soft lockup", re.I)


def log(*a):
    print(*a, file=LOG)


def run(cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{cmd} -> {r.returncode}: {r.stdout[-2000:]} {r.stderr[-2000:]}")
    return r


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def dmesg_mark():
    with open("/dev/kmsg", "w") as f:
        f.write(f"ntfs-move-test: mark {time.time()}\n")


def dmesg_since_mark():
    out = run(["dmesg"], check=False).stdout.splitlines()
    idx = max((i for i, l in enumerate(out) if "ntfs-move-test: mark" in l), default=-1)
    return out[idx + 1:]


class Volume:
    """A loop-mounted test volume in guest tmpfs."""

    def __init__(self, cluster, size_mb):
        self.cluster = cluster
        self.img = f"{TMP}/vol-{cluster}.img"
        self.size = size_mb << 20
        self.loop = None
        self.expected = {}          # path -> sha256 of the expected contents
        self.mount_opts = []
        with open(self.img, "wb") as f:
            f.truncate(self.size)
        run(["mkntfs", "-q", "-F", "-Q", "-c", str(cluster), "-L", "movetest", self.img])
        self.mount()

    def mount(self, ro=False):
        os.makedirs(MNT, exist_ok=True)
        self.loop = run(["losetup", "-f", "--show", self.img]).stdout.strip()
        opts = ["-o", "ro"] if ro else []
        run(["mount", "-i", "-t", "ntfs", *opts, *self.mount_opts, self.loop, MNT])

    def umount(self):
        for attempt in range(10):
            r = run(["umount", MNT], check=False)
            if r.returncode == 0:
                break
            users = run(["fuser", "-vm", MNT], check=False)
            log(f"umount busy (attempt {attempt}): {r.stderr.strip()} users: {users.stdout} {users.stderr}")
            time.sleep(0.5)
        else:
            raise RuntimeError(f"umount {MNT} failed: {r.stderr}")
        run(["losetup", "-d", self.loop])
        # the detach completes asynchronously
        for _ in range(500):
            if not run(["losetup", "-j", self.img], check=False).stdout.strip():
                break
            time.sleep(0.01)
        self.loop = None

    def path(self, name):
        return os.path.join(MNT, name)

    def fd_root(self):
        return os.open(MNT, os.O_RDONLY | os.O_DIRECTORY)

    def free(self):
        fd = self.fd_root()
        try:
            return I.free_extents(fd, self.cluster)
        finally:
            os.close(fd)

    def runs(self, name):
        fd = os.open(self.path(name), os.O_RDONLY)
        try:
            return I.file_runs(fd, self.cluster)
        finally:
            os.close(fd)

    def record(self, name):
        self.expected[name] = sha(self.path(name))

    def verify_contents(self, where):
        bad = []
        for name, digest in sorted(self.expected.items()):
            got = sha(self.path(name))
            if got != digest:
                bad.append(f"{where}: {name} contents changed")
        return bad

    def check_offline(self):
        """Unmount, run all offline checks, mount again. Returns a list of problems."""
        problems = []
        os.sync()                       # write back delayed allocations first
        runs_before = {n: self.runs(n) for n in self.expected}
        fd = self.fd_root()
        try:
            fsmap = I.getfsmap(fd)
        except OSError as e:
            if e.errno != 25:           # ENOTTY: kernel without GETFSMAP (control runs)
                raise
            fsmap = None
        finally:
            os.close(fd)
        self.umount()
        r = run([NTFSCK, "-n", self.img], check=False)
        if r.returncode != 0:
            problems.append(f"ntfsck -n rc={r.returncode}: {(r.stdout + r.stderr)[-1500:]}")
        problems += self.check_with_prototype(runs_before, fsmap)
        self.mount()
        I.drop_caches()
        problems += self.verify_contents("after remount")
        return problems

    def check_with_prototype(self, runs_before, fsmap):
        """Independent parser: on-disk runlists == FIEMAP, $Bitmap == GETFSMAP."""
        problems = []
        vol = proto.Volume(self.img)
        try:
            vol.scan()
            by_name = {}
            for (num, typ, name), st in vol.streams.items():
                if typ == proto.AT_DATA and name == "":
                    by_name[vol.path_of(num).lstrip("/")] = st
            for name, runs in runs_before.items():
                if not runs:
                    continue                    # resident
                st = by_name.get(name)
                if st is None:
                    problems.append(f"{name}: not found by the prototype parser")
                    continue
                try:                            # through the attribute list, as a driver reads it
                    strict.stream_runs(vol, st.base)
                except strict.Corrupt as e:
                    problems.append(f"{name}: {e}")
                # FIEMAP stops at the end of the file, the runlist at the allocation
                end = max((v + n for v, _l, n in runs), default=0)
                disk = [(r.vcn, r.lcn, min(r.length, end - r.vcn)) for r in st.runs
                        if r.lcn is not None and r.lcn >= 0 and r.vcn < end]
                if merge(disk) != merge(runs):
                    problems.append(f"{name}: on-disk runlist {merge(disk)[:6]} != FIEMAP {merge(runs)[:6]}")
            bm = vol.bitmap
            nclu = vol.total_clusters
            for phys, ln, owner, _fl in fsmap or ():
                a, n = phys // self.cluster, ln // self.cluster
                used = owner != I.FMR_OWN_FREE
                for lcn in (a, a + n - 1):
                    if lcn < nclu and bool(bm[lcn >> 3] >> (lcn & 7) & 1) != used:
                        problems.append(f"GETFSMAP says LCN {lcn} {'used' if used else 'free'}, $Bitmap disagrees")
                        break
            total = sum(ln for _p, ln, _o, _f in fsmap or ())
            if fsmap is not None and total != nclu * self.cluster:
                problems.append(f"GETFSMAP covers {total} bytes, volume has {nclu * self.cluster}")
        finally:
            vol.close()
        ch = run([sys.executable, "-I", os.path.join(PROTO_DIR, "ntfsdefrag.py"), "check", self.img], check=False)
        if ch.returncode != 0:
            problems.append(f"prototype check rc={ch.returncode}: {(ch.stdout + ch.stderr)[-800:]}")
        return problems

    def destroy(self):
        if self.loop:
            run(["umount", MNT], check=False)
            run(["losetup", "-d", self.loop], check=False)
        os.unlink(self.img)


def merge(runs):
    out = []
    for v, l, n in sorted(runs):
        if out and out[-1][0] + out[-1][2] == v and out[-1][1] + out[-1][2] == l:
            out[-1] = (out[-1][0], out[-1][1], out[-1][2] + n)
        else:
            out.append((v, l, n))
    return out


def write_file(path, size, seed, chunk=None, sync_each=False):
    rnd = random.Random(seed)
    with open(path, "wb") as f:
        left = size
        while left:
            n = min(left, chunk or (1 << 20))
            f.write(rnd.randbytes(n))
            left -= n
            if sync_each:
                f.flush()
                os.fsync(f.fileno())


def make_attr_list_file(vol, name, seed, min_extents=3):
    """A file whose $DATA needs an attribute list and min_extents extents: its
    pieces of 1 cluster (some of 3) alternate on the disk with those of a
    spacer file, which is deleted afterwards. Returns its MFT record number."""
    rnd = random.Random(seed)
    a = open(vol.path(name), "wb")
    b = open(vol.path(name + ".spacer"), "wb")
    num = os.fstat(a.fileno()).st_ino
    rounds = n = 0
    while n < min_extents and rounds < 3000:
        for _ in range(100):
            a.write(rnd.randbytes(vol.cluster * (3 if rnd.random() < 0.15 else 1)))
            a.flush()
            os.fsync(a.fileno())
            b.write(bytes(vol.cluster))
            b.flush()
            os.fsync(b.fileno())
            rounds += 1
        I.drop_caches()
        n = strict.data_extents(vol.loop, num)
    a.close()
    b.close()
    os.unlink(vol.path(name + ".spacer"))
    os.sync()
    log(f"{name}: {rounds} rounds, {n} extents")
    if n < min_extents:
        raise RuntimeError(f"{name} has {n} extents after {rounds} rounds")
    return num


def fragment_volume(vol, fill=0.7, big=("big1", "big2"), big_size=None, seed=1):
    """Fill with small files, delete every other one, then write big files into the holes."""
    rnd = random.Random(seed)
    os.makedirs(vol.path("small"), exist_ok=True)
    piece = max(vol.cluster * 4, 16384)
    n = int(vol.size * fill / piece)
    for i in range(n):
        try:
            write_file(vol.path(f"small/s{i:05d}"), piece, seed * 100000 + i)
        except OSError:
            break
    os.sync()
    for i in range(0, n, 2):
        try:
            os.unlink(vol.path(f"small/s{i:05d}"))
        except FileNotFoundError:
            pass
    os.sync()
    for i in range(1, n, 2):
        if os.path.exists(vol.path(f"small/s{i:05d}")) and rnd.random() < 0.1:
            vol.record(f"small/s{i:05d}")
    # the big files are appended to in turns, one piece at a time with an
    # fsync in between, so that their extents interleave
    size = big_size or int(vol.size * 0.06)
    files = [open(vol.path(name), "wb") for name in big]
    rnds = [random.Random(seed * 7 + k) for k in range(len(big))]
    left = size
    while left > 0 and files:
        n = min(left, piece * rnd.randrange(1, 4))
        for f, r in zip(files, rnds):
            f.write(r.randbytes(n))
            f.flush()
            os.fsync(f.fileno())
        left -= n
    for f, name in zip(files, big):
        f.close()
        vol.record(name)
    os.sync()


# ---------------------------------------------------------------------------


class Base(unittest.TestCase):
    cluster = 4096
    size_mb = 128

    def setUp(self):
        if not os.path.ismount(TMPFS):
            run(["mount", "-t", "tmpfs", "-o", "size=1500m", "tmpfs", TMPFS])
        os.makedirs(TMP, exist_ok=True)
        dmesg_mark()
        self.vol = Volume(self.cluster, self.size_mb)

    def tearDown(self):
        self.doCleanups()               # close the test's file descriptors first
        try:
            problems = []
            if self.vol.loop:
                problems += self.vol.check_offline()
            bad = [l for l in dmesg_since_mark() if DMESG_BAD.search(l)]
            if bad:
                problems.append("dmesg: " + " | ".join(bad[:8]))
            if problems:
                log(f"{self.id()}: offline checks: {problems}")
            if problems or getattr(self, "_failed", False):
                keep = os.path.join(WORK, f"{self.id().split('.')[-2]}.{self._testMethodName}.img")
                if self.vol.loop:
                    self.vol.umount()
                shutil.copyfile(self.vol.img, keep)
                log(f"image kept: {keep}")
            if problems and not getattr(self, "_failed", False):
                self.fail("; ".join(problems))
        finally:
            self.vol.destroy()

    def open(self, name, flags=os.O_RDONLY):
        fd = os.open(self.vol.path(name), flags)
        self.addCleanup(os.close, fd)
        return fd

    def mapping_fits(self, num, vcn, n, lcn):
        """Whether moving [vcn, vcn + n) of record num's $DATA to lcn leaves
        mapping pairs that fit in the MFT record of the extent mapping vcn
        (the range must lie in that extent), computed from the disk."""
        I.drop_caches()
        info = strict.extents_info(self.vol.loop, num)
        e = next(e for e in info if e["lowest"] <= vcn <= e["highest"])
        self.assertLessEqual(vcn + n - 1, e["highest"], "the range spans extents")
        new = strict.replace_runs([(r.vcn, r.lcn, r.length) for r in e["runs"]], vcn, n, lcn)
        need = (e["mp_offset"] + strict.mapping_pairs_size(new) + 7) & ~7
        return need - e["length"] <= e["free"]

    def largest_free(self, need=1):
        free = sorted(self.vol.free(), key=lambda e: -e[1])
        self.assertTrue(free and free[0][1] >= need, f"no free extent of {need} clusters: {free[:3]}")
        return free[0]


class GetFsMapTests(Base):
    def test_matches_statfs_and_bitmap(self):
        fragment_volume(self.vol)
        os.sync()
        fd = self.vol.fd_root()
        recs = I.getfsmap(fd)
        os.close(fd)
        self.assertTrue(recs[-1][3] & I.FMR_OF_LAST)
        pos = 0
        for phys, ln, owner, fl in recs:
            self.assertEqual(phys, pos, "records must be contiguous")
            self.assertGreater(ln, 0)
            self.assertIn(owner, (I.FMR_OWN_FREE, I.FMR_OWN_UNKNOWN))
            self.assertTrue(fl & I.FMR_OF_SPECIAL_OWNER)
            pos += ln
        for a, b in zip(recs, recs[1:]):
            self.assertNotEqual(a[2], b[2], "adjacent records must differ in owner")
        free = sum(ln for _p, ln, o, _f in recs if o == I.FMR_OWN_FREE)
        st = os.statvfs(MNT)
        log(f"c{self.cluster}: fsmap free {free}, statfs free {st.f_bfree * st.f_frsize}")
        self.assertEqual(free, st.f_bfree * st.f_frsize)
        # bitmap comparison happens in tearDown (check_with_prototype)

    def test_pagination_and_keys(self):
        fragment_volume(self.vol)
        fd = self.vol.fd_root()
        self.addCleanup(os.close, fd)
        whole = I.getfsmap(fd, batch=100000)
        dev = I.getfsmap_raw(fd, count=1)[2][0][0]
        for batch in (1, 2, 3, 7):
            self.assertEqual(I.getfsmap(fd, batch=batch), whole, f"batch {batch}")
        # count-only query
        _of, entries, recs = I.getfsmap_raw(fd, count=0)
        self.assertEqual(entries, len(whole))
        self.assertEqual(recs, [])
        # a window in the middle: records are clipped to it
        mid = whole[len(whole) // 2]
        lo = mid[0] + self.cluster // 2 if mid[1] > self.cluster else mid[0]
        hi = mid[0] + mid[1] + 3 * self.cluster
        _of, _n, recs = I.getfsmap_raw(fd, low=(dev, lo, 0, 0, 0), high=(dev, hi, 0, 0, 0))
        self.assertTrue(recs)
        self.assertEqual(recs[0][2], lo, "the first record is clipped to the low key")
        for r in recs:
            self.assertGreaterEqual(r[2], lo)
            self.assertLessEqual(r[2], hi)
        # the low key is the previous record: continue after it
        _of, _n, recs2 = I.getfsmap_raw(fd, low=(dev, whole[0][0], 0, 0, whole[0][1]), count=2)
        self.assertEqual(recs2[0][2], whole[1][0])
        # a low key on an earlier device (0 = any) starts at the beginning
        _of, _n, recs3 = I.getfsmap_raw(fd, low=(0, whole[1][0], 0, 0, 0), count=1)
        self.assertEqual(recs3[0][2], 0)
        # a high key on an earlier device, a low key on a later one: nothing
        _of, n, _r = I.getfsmap_raw(fd, high=(dev - 1, 1 << 62, 0, 0, 0))
        self.assertEqual(n, 0)
        _of, n, _r = I.getfsmap_raw(fd, low=(dev + 1, 0, 0, 0, 0))
        self.assertEqual(n, 0)
        # beyond the end of the volume: nothing
        _of, n, _r = I.getfsmap_raw(fd, low=(dev, 1 << 60, 0, 0, 0))
        self.assertEqual(n, 0)

    def test_invalid_arguments(self):
        fd = self.vol.fd_root()
        self.addCleanup(os.close, fd)
        for kw in ({"iflags": 1}, {"reserved": 1}, {"key_reserved": 1}):
            with self.assertRaises(OSError) as cm:
                I.getfsmap_raw(fd, **kw)
            self.assertEqual(cm.exception.errno, 22, kw)
        with self.assertRaises(OSError):
            I.getfsmap_raw(fd, low=(0, 0, 0, 1, 0))            # file offset in the low key
        with self.assertRaises(OSError):
            I.getfsmap_raw(fd, low=(0, 1 << 20, 0, 0, 0), high=(0, 4096, 0, 0, 0))
        # also works on a regular file descriptor and for an unprivileged user
        fdf = os.open(MNT, os.O_RDONLY)
        os.close(fdf)
        pid = os.fork()
        if pid == 0:
            try:
                os.setgid(65534)
                os.setuid(65534)
                fd2 = os.open(MNT, os.O_RDONLY)
                I.getfsmap(fd2)
                os._exit(0)
            except Exception:
                os._exit(1)
        self.assertEqual(os.waitpid(pid, 0)[1], 0)


class MoveTests(Base):
    def test_move_whole_file(self):
        fragment_volume(self.vol, fill=0.5, big_size=int(self.vol.size * 0.02))
        for name in ("big1", "big2"):
            runs = self.vol.runs(name)
            self.assertGreater(len(merge(runs)), 1, f"{name} should be fragmented")
            total = sum(n for _v, _l, n in runs)
            lcn, n = self.largest_free(total)
            fd = self.open(name)
            moved = 0
            # move it piece by piece into the largest free extent
            for v, l, k in merge(runs):
                if moved >= n:
                    break
                k = min(k, n - moved)
                self.assertEqual(I.move_clusters(fd, v, lcn + moved, k), k)
                moved += k
            after = merge(self.vol.runs(name))
            log(f"c{self.cluster} {name}: {len(merge(runs))} -> {len(after)} runs, total {total}")
            self.assertEqual(after, [(0, lcn, total)])
            I.drop_caches()
            self.assertEqual(sha(self.vol.path(name)), self.vol.expected[name])

    def test_partial_and_merge(self):
        fragment_volume(self.vol)
        name = "big1"
        fd = self.open(name)
        num = os.fstat(fd).st_ino
        runs = merge(self.vol.runs(name))
        lcn, n = self.largest_free(4)
        cands = sorted((r for r in runs if r[2] > 4), key=lambda r: -r[2])
        self.assertTrue(cands)
        pick = next((r for r in cands if self.mapping_fits(num, r[0] + 1, 2, lcn)), None)
        if pick is None:
            # every record holding such a run is full: the split cannot be
            # written and must change nothing
            v = cands[0][0]
            self.assertEqual(I.move_errno(fd, v + 1, lcn, 2), -errno.ENOSPC)
            self.assertEqual(merge(self.vol.runs(name)), runs)
        else:
            v, l, k = pick
            # the middle of an extent: it splits in three
            self.assertEqual(I.move_clusters(fd, v + 1, lcn, 2), 2)
            after = merge(self.vol.runs(name))
            self.assertIn((v + 1, lcn, 2), after)
            self.assertEqual(len(after), len(runs) + 2)
            # and back: merges again
            self.assertEqual(I.move_clusters(fd, v + 1, l + 1, 2), 2)
            self.assertEqual(merge(self.vol.runs(name)), runs)
        # a range across two extents onto free space right behind the first
        # part, so that it merges with it
        runs = merge(self.vol.runs(name))
        for i in range(len(runs) - 1):
            a, b = runs[i], runs[i + 1]
            span = a[2] + min(b[2], 3)
            if any(f[0] <= a[1] + a[2] and f[0] + f[1] >= a[1] + span for f in self.vol.free()):
                if not self.mapping_fits(num, b[0], span - a[2], a[1] + a[2]):
                    continue
                self.assertEqual(I.move_clusters(fd, b[0], a[1] + a[2], span - a[2]), span - a[2])
                self.assertIn((a[0], a[1], span), merge(self.vol.runs(name)))
                break
        I.drop_caches()
        self.assertEqual(sha(self.vol.path(name)), self.vol.expected[name])

    def test_errors(self):
        fragment_volume(self.vol, big=("big1",))
        name = "big1"
        fd = self.open(name)
        runs = merge(self.vol.runs(name))
        v, l, k = runs[0]
        lcn, n = self.largest_free(2)
        nclu = self.vol.size // self.cluster
        other = next(n for n in sorted(os.listdir(self.vol.path("small"))))
        busy = merge(self.vol.runs("small/" + other))[0][1]
        cases = [
            ("destination in use", (v, busy, 1), {}, -16),
            ("destination is the file itself", (v, l, 1), {}, 1),
            ("beyond the volume", (v, nclu, 1), {}, -22),
            ("crossing the end", (v, nclu - 1, 2), {}, -22),
            ("zero length", (v, lcn, 0), {}, -22),
            ("flags", (v, lcn, 1), {"flags": 1}, -22),
            ("reserved", (v, lcn, 1), {"reserved": 1}, -22),
            ("beyond the allocation", (sum(r[2] for r in runs) + 5, lcn, 1), {}, -22),
            ("huge vcn", ((1 << 63) - 1, lcn, 2), {}, -22),
        ]
        for what, args, kw, want in cases:
            self.assertEqual(I.move_errno(fd, *args, **kw), want, what)
        # a hole cannot be moved
        with open(self.vol.path("sparse"), "wb") as f:
            f.truncate(64 * self.cluster)
            f.seek(10 * self.cluster)
            f.write(b"x" * self.cluster)
        self.vol.record("sparse")
        sfd = self.open("sparse")
        os.fsync(sfd)
        self.assertEqual(I.move_errno(sfd, 0, lcn, 1), -22, "hole")
        self.assertEqual(I.move_errno(sfd, 9, lcn, 2), -22, "hole + data")
        r = [x for x in self.vol.runs("sparse")]
        self.assertTrue(r)
        self.assertEqual(I.move_errno(sfd, r[0][0], lcn, 1), 1, "data of a sparse file")
        # resident file
        with open(self.vol.path("tiny"), "wb") as f:
            f.write(b"tiny")
        self.vol.record("tiny")
        self.assertEqual(I.move_errno(self.open("tiny"), 0, lcn, 1), -95, "resident")
        # directory
        dfd = os.open(self.vol.path("small"), os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, dfd)
        self.assertEqual(I.move_errno(dfd, 0, lcn, 1), -22, "directory")
        # unprivileged
        pid = os.fork()
        if pid == 0:
            os.setgid(65534)
            os.setuid(65534)
            os._exit(0 if I.move_errno(fd, v, lcn, 1) == -1 else 1)
        self.assertEqual(os.waitpid(pid, 0)[1], 0, "EPERM for an unprivileged user")
        # immutable
        run(["chattr", "+i", self.vol.path(name)], check=False)
        if "i" in run(["lsattr", "-d", self.vol.path(name)], check=False).stdout.split()[0]:
            self.assertEqual(I.move_errno(fd, v, lcn, 1), -1, "immutable")
            run(["chattr", "-i", self.vol.path(name)])
        # read-only mount
        self.doCleanups()
        self.vol.umount()
        self.vol.mount(ro=True)
        fd = os.open(self.vol.path(name), os.O_RDONLY)
        self.assertEqual(I.move_errno(fd, v, lcn, 1), -30, "read-only mount")
        os.close(fd)
        self.vol.umount()
        self.vol.mount()
        # nothing changed by the failures
        self.assertEqual(merge(self.vol.runs(name)), runs)

    def test_metadata_files_refused(self):
        """$MFT, $Bitmap, ... opened through show_sys_files cannot be moved."""
        lcn, n = self.largest_free(4)
        self.vol.umount()
        self.vol.mount_opts = ["-o", "show_sys_files"]
        self.vol.mount()
        tried = 0
        for name in ("$MFT", "$MFTMirr", "$LogFile", "$Bitmap", "$Boot", "$BadClus", "$UpCase"):
            try:
                fd = os.open(self.vol.path(name), os.O_RDONLY)
            except OSError:
                continue
            try:
                try:
                    runs = merge(I.file_runs(fd, self.cluster))
                except OSError:
                    runs = []           # no FIEMAP for metadata files
                vcn = runs[0][0] if runs else 0
                # EPERM from the move, or ENOTTY where the system file has
                # no ioctl at all: refused either way
                self.assertIn(I.move_errno(fd, vcn, lcn, 1), (-1, -25), f"{name} must not move")
                tried += 1
            finally:
                os.close(fd)
        if not tried:
            self.skipTest("system files not visible with show_sys_files")
        self.vol.umount()
        self.vol.mount_opts = []
        self.vol.mount()

    def test_dirty_pagecache_and_delalloc(self):
        """Data still in the page cache (incl. delayed allocations) moves correctly."""
        fragment_volume(self.vol, big=())
        name = "fresh"
        data = random.Random(5).randbytes(48 * self.cluster + 123)
        with open(self.vol.path(name), "wb") as f:
            f.write(data)                   # no fsync: delayed allocation
            f.flush()
            fd = os.open(self.vol.path(name), os.O_RDWR)
            self.addCleanup(os.close, fd)
            runs = merge(I.file_runs(fd, self.cluster))       # FIEMAP_FLAG_SYNC allocates
            os.pwrite(fd, b"Z" * 100, 5 * self.cluster)       # dirty again, not written back
            data = data[:5 * self.cluster] + b"Z" * 100 + data[5 * self.cluster + 100:]
            lcn, n = self.largest_free(sum(r[2] for r in runs))
            pos = 0
            for v, _l, k in runs:
                self.assertEqual(I.move_clusters(fd, v, lcn + pos, k), k)
                pos += k
        self.assertEqual(len(merge(self.vol.runs(name))), 1)
        with open(self.vol.path(name), "rb") as f:
            self.assertEqual(f.read(), data)
        I.drop_caches()
        with open(self.vol.path(name), "rb") as f:
            self.assertEqual(f.read(), data)
        self.vol.record(name)

    def test_initialized_size_tail(self):
        """Allocated but uninitialized clusters (fallocate, seek past EOF) move and read as zeros."""
        fragment_volume(self.vol, big=())
        fd = self.open("prealloc", os.O_RDWR | os.O_CREAT)
        os.pwrite(fd, b"A" * (3 * self.cluster), 0)
        os.posix_fallocate(fd, 0, 40 * self.cluster)
        os.fsync(fd)
        runs = merge(I.file_runs(fd, self.cluster))
        lcn, n = self.largest_free(40)
        pos = 0
        for v, _l, k in runs:
            self.assertEqual(I.move_clusters(fd, v, lcn + pos, k), k)
            pos += k
        os.pwrite(fd, b"B" * 10, 20 * self.cluster)
        os.fsync(fd)
        I.drop_caches()
        with open(self.vol.path("prealloc"), "rb") as f:
            got = f.read()
        want = b"A" * (3 * self.cluster) + b"\0" * (17 * self.cluster) + b"B" * 10
        want += b"\0" * (40 * self.cluster - len(want))
        self.assertEqual(got, want)
        self.vol.record("prealloc")

    def test_past_eof_prealloc(self):
        """Clusters preallocated past EOF (FALLOC_FL_KEEP_SIZE) move: nothing is
        copied, the size stays, and the clusters read as zeros once the file grows
        over them. (The move must still flush $Bitmap before the MFT record points
        to the new clusters; the crash suite's "eof" workload checks that order.)"""
        fragment_volume(self.vol, big=())
        fd = self.open("keep", os.O_RDWR | os.O_CREAT)
        data = b"K" * (2 * self.cluster + 100)
        os.pwrite(fd, data, 0)
        fallocate(fd, 0x01, 0, 30 * self.cluster)              # KEEP_SIZE
        os.fsync(fd)
        self.assertEqual(os.fstat(fd).st_size, len(data))
        first = 3                                               # first cluster wholly past EOF
        lcn, n = self.largest_free(30)
        moved = I.move_clusters(fd, first, lcn, 30 - first)
        self.assertEqual(moved, 30 - first)
        self.assertEqual(I.move_clusters(fd, first, lcn, 30 - first), 30 - first, "already there")
        self.assertEqual(os.fstat(fd).st_size, len(data))
        I.drop_caches()
        with open(self.vol.path("keep"), "rb") as f:
            self.assertEqual(f.read(), data)
        os.pwrite(fd, b"Z" * 10, 20 * self.cluster)
        os.fsync(fd)
        I.drop_caches()
        with open(self.vol.path("keep"), "rb") as f:
            got = f.read()
        self.assertEqual(got, data + b"\0" * (20 * self.cluster - len(data)) + b"Z" * 10)
        self.vol.record("keep")

    def test_attribute_list(self):
        """A file whose $DATA spans the base record and several extent records:
        a move changes only the mapping pairs of the extents it touches, never
        which records hold the extents nor their VCN ranges. A move that grows
        the mapping pairs of an extent past its record fails with ENOSPC and
        changes nothing; whether it fits is computed independently from the
        on-disk records. Moves across an extent boundary and of the whole file
        in one call work chunk by chunk."""
        num = make_attr_list_file(self.vol, "alist", seed=5)
        fd = self.open("alist")
        dev = self.vol.loop

        def extents():
            I.drop_caches()
            return strict.extents_info(dev, num)

        def layout(info):
            return [(e["rec"], e["lowest"], e["highest"]) for e in info]

        info0 = extents()
        self.assertGreaterEqual(len(info0), 3, layout(info0))
        rnd = random.Random(self.cluster)
        outcome = {"fits": 0, "ENOSPC": 0}
        for _ in range(3):
            for k, e in enumerate(extents()):
                runs = [(r.vcn, r.lcn, r.length) for r in e["runs"]]
                long = [r for r in runs if r[1] is not None and r[2] >= 3]
                if not long:
                    continue
                v, _l, n = rnd.choice(long)
                v += rnd.randrange(1, n - 1)
                free = [f for f in self.vol.free() if f[1] >= 1]
                dst = rnd.choice(free)[0]
                new = strict.replace_runs(runs, v, 1, dst)
                need = (e["mp_offset"] + strict.mapping_pairs_size(new) + 7) & ~7
                fits = need - e["length"] <= e["free"]
                before = I.file_runs(fd, self.cluster)
                r = I.move_errno(fd, v, dst, 1)
                if fits:
                    self.assertEqual(r, 1, f"extent {k}: grows by {need - e['length']} bytes, "
                                           f"{e['free']} free: {I.errname(r)}")
                else:
                    self.assertEqual(r, -errno.ENOSPC, f"extent {k}: needs {need - e['length']} "
                                                       f"bytes, {e['free']} free")
                    self.assertEqual(I.file_runs(fd, self.cluster), before)
                    self.assertTrue(any(f[0] <= dst < f[0] + f[1] for f in self.vol.free()),
                                    "the destination of a failed move must be free again")
                outcome["fits" if fits else "ENOSPC"] += 1
        log(f"attribute list grow moves: {outcome}")
        self.assertTrue(outcome["fits"] and outcome["ENOSPC"], outcome)
        # several runs on both sides of the first extent boundary into one place
        runs = merge(I.file_runs(fd, self.cluster))
        b = info0[1]["lowest"]
        i = max(k for k, r in enumerate(runs) if r[0] <= b)
        v0, v1 = runs[max(i - 3, 0)][0], runs[min(i + 3, len(runs) - 1)][0]
        lcn, _n = self.largest_free(v1 - v0)
        self.assertEqual(I.move_clusters(fd, v0, lcn, v1 - v0), v1 - v0)
        self.assertIn((v0, lcn, v1 - v0), merge(I.file_runs(fd, self.cluster)))
        # the whole file in one call
        total = sum(r[2] for r in runs)
        lcn, _n = self.largest_free(total)
        self.assertEqual(I.move_clusters(fd, 0, lcn, total), total)
        self.assertEqual(merge(I.file_runs(fd, self.cluster)), [(0, lcn, total)])
        self.assertEqual(layout(extents()), layout(info0), "the extents must stay where they are")
        self.vol.record("alist")

    def test_mapping_write_error(self):
        """An I/O error while the MFT record with the new mapping is written:
        the ioctl fails with EIO, the data stays readable, the old clusters
        stay allocated (the old mapping may still be the one on the disk),
        and the volume is marked as having errors, so it is dirty on the disk
        after the unmount and a check reclaims the leaked clusters."""
        fragment_volume(self.vol, big=("big1",))
        name = "big1"
        num = os.stat(self.vol.path(name)).st_ino
        runs = merge(self.vol.runs(name))
        self.doCleanups()
        self.vol.umount()
        pv = proto.Volume(self.vol.img)
        try:
            pieces = pv.record_pieces(num)
        finally:
            pv.close()
        sectors = self.vol.size // 512
        loop = run(["losetup", "-f", "--show", self.vol.img]).stdout.strip()
        dm = "/dev/mapper/mvfail"

        def table(bad):
            out, pos = [], 0
            for off, ln in sorted(bad):
                a, b = off // 512, -(-(off + ln) // 512)
                if a > pos:
                    out.append(f"{pos} {a - pos} linear {loop} {pos}")
                out.append(f"{a} {b - a} error")
                pos = b
            out.append(f"{pos} {sectors - pos} linear {loop} {pos}")
            return "\n".join(out)

        def load(bad):
            run(["dmsetup", "load", "mvfail", "--table", table(bad)])
            run(["dmsetup", "suspend", "--noudevsync", "--nolockfs", "mvfail"])
            run(["dmsetup", "resume", "--noudevsync", "mvfail"])

        run(["dmsetup", "create", "--noudevsync", "mvfail", "--table", table([])])
        run(["dmsetup", "mknodes", "mvfail"])
        mounted = False
        try:
            run(["mount", "-i", "-t", "ntfs", dm, MNT])
            mounted = True
            fd = os.open(self.vol.path(name), os.O_RDONLY)
            try:
                v, _l, k = max(runs, key=lambda r: r[2])
                lcn, _n = self.largest_free(k)
                load(pieces)
                self.assertEqual(I.move_errno(fd, v, lcn, k), -errno.EIO)
                self.assertEqual(sha(self.vol.path(name)), self.vol.expected[name])
                load([])
            finally:
                os.close(fd)
            run(["umount", MNT])
            mounted = False
        finally:
            if mounted:
                run(["umount", MNT], check=False)
            run(["dmsetup", "remove", "--noudevsync", "mvfail"], check=False)
            run(["losetup", "-d", loop], check=False)
        pv = proto.Volume(self.vol.img)
        try:
            pv.scan()
            flags = strict.volume_flags(pv)
            bad, leaked = strict.bitmap_problems(pv)
            got = pv.read_stream_bytes(*strict.stream_runs(pv, num))
        finally:
            pv.close()
        self.assertEqual(hashlib.sha256(got).hexdigest(), self.vol.expected[name], "on disk")
        self.assertEqual(bad, [])
        self.assertGreaterEqual(leaked, k)
        self.assertTrue(flags & 1, f"volume flags {flags:#x}: not dirty")
        r = run([NTFSCK, "-a", self.vol.img], check=False)
        log(f"ntfsck -a: rc {r.returncode}: {(r.stdout + r.stderr)[-300:]}")
        expected_msgs = re.compile(r"I/O error|critical .*error|Buffer I/O|"
                                   r"ntfs.*(mft record|new mapping|chkdsk|Failed)", re.I)
        unexpected = [ln for ln in dmesg_since_mark() if DMESG_BAD.search(ln) and not expected_msgs.search(ln)]
        self.assertEqual(unexpected, [])
        dmesg_mark()
        self.vol.mount()            # tearDown: ntfsck -n must now be clean

    def test_mft_zone_destination(self):
        """The MFT zone (where the driver prefers not to put data while
        there is space elsewhere) is an allocation policy, not a reservation:
        a destination inside it is accepted."""
        fragment_volume(self.vol, big=("big1",))
        vol = proto.Volume(self.vol.loop, allow_mounted=True)
        try:
            zone = (vol.mft_lcn, vol.mft_lcn + vol.total_clusters // 8)
        finally:
            vol.close()
        free = [(max(l, zone[0]), min(l + n, zone[1]) - max(l, zone[0])) for l, n in self.vol.free()
                if l < zone[1] and l + n > zone[0]]
        free = [f for f in free if f[1] > 0]
        self.assertTrue(free, f"no free cluster in the MFT zone {zone}")
        fd = self.open("big1")
        v, _l, n = merge(self.vol.runs("big1"))[0]
        n = min(n, free[0][1])
        self.assertEqual(I.move_clusters(fd, v, free[0][0], n), n)
        self.assertIn(free[0][0], [l for _v, l, _n in merge(self.vol.runs("big1"))])

    def test_unlinked_open_file(self):
        fragment_volume(self.vol, big=("big1",))
        fd = self.open("big1")
        runs = merge(self.vol.runs("big1"))
        os.unlink(self.vol.path("big1"))
        del self.vol.expected["big1"]
        lcn, n = self.largest_free(runs[0][2])
        self.assertEqual(I.move_clusters(fd, runs[0][0], lcn, runs[0][2]), runs[0][2])
        # clusters go back to the free space when the last reference goes

    def test_named_stream(self):
        """A named stream opened through its path (if the driver supports it) can be moved."""
        fragment_volume(self.vol, big=("big1",))
        self.doCleanups()
        self.vol.umount()
        self.vol.mount_opts = ["-o", "streams_interface=windows"]
        self.vol.mount()
        base = self.vol.path("big1")
        data = random.Random(9).randbytes(30 * self.cluster)
        spelling = base + ":ads"
        with open(spelling, "wb") as f:
            f.write(data)
        self.assertNotIn("big1:ads", os.listdir(MNT), "a named stream, not a file")
        fd = self.open(spelling)
        os.fsync(fd)
        runs = merge(I.file_runs(fd, self.cluster))
        if not runs:
            self.skipTest("FIEMAP does not report named streams")
        lcn, n = self.largest_free(sum(r[2] for r in runs))
        pos = 0
        for v, _l, k in runs:
            self.assertEqual(I.move_clusters(fd, v, lcn + pos, k), k)
            pos += k
        I.drop_caches()
        with open(spelling, "rb") as f:
            self.assertEqual(f.read(), data)

    def test_fuzz_moves(self):
        """Single-threaded: random file operations, each followed by a random
        move of the same file, contents checked after every step; the first
        bad step and the steps before it are logged."""
        fragment_volume(self.vol, fill=0.6, big=())
        size = 96 * max(self.cluster, 4096)
        seed = CFG.get("fuzz_seed", 1)
        rnd = random.Random(seed)
        name = "fz"
        path = self.vol.path(name)
        m = bytearray(random.Random(seed).randbytes(size))
        with open(path, "wb") as f:
            f.write(m)
        history = []
        steps = CFG.get("fuzz_steps", 4000)
        weights = "wwwwmmttppv"
        for k in range(steps):
            op = make_op(rnd, rnd.choice(weights), len(m), size, self.cluster)
            if op:
                bad = apply_op(path, m, op)
                history.append(op)
                if bad:
                    break
            if rnd.random() < 0.6:
                fd = os.open(path, os.O_RDONLY)
                try:
                    runs = merge(I.file_runs(fd, self.cluster))
                    if runs:
                        v, _l, n = rnd.choice(runs)
                        off = rnd.randrange(n)
                        n = rnd.randrange(1, n - off + 1)
                        free = [f for f in self.vol.free() if f[1] >= n]
                        if free:
                            f0 = rnd.choice(free)
                            dst = f0[0] + rnd.randrange(f0[1] - n + 1)
                            r = I.move_errno(fd, v + off, dst, n)
                            history.append({"op": "move", "vcn": v + off, "n": n, "lcn": dst, "r": r,
                                            "runs": runs[:8]})
                finally:
                    os.close(fd)
            if rnd.random() < 0.05:
                I.drop_caches()
                history.append({"op": "drop"})
            bad = apply_op(path, m, {"op": "v"})
            if bad:
                break
        else:
            bad = None
        if bad:
            log(f"c{self.cluster} fuzz seed {seed}: step {k}: {bad}")
            for h in history[-30:]:
                log(f"    {h}")
            json.dump({"cluster": self.cluster, "seed": seed, "history": history},
                      open(os.path.join(WORK, f"fuzz-c{self.cluster}-s{seed}.json"), "w"))
        self.assertIsNone(bad, f"fuzz seed {seed} step {k}")
        self.vol.record(name)

    def test_stress(self):
        """Random moves racing with writes, reads, mmap writes, truncates and hole punching."""
        fragment_volume(self.vol, fill=0.6, big=())
        seconds = CFG.get("stress_seconds", 60)
        nfiles = 6
        size = 96 * max(self.cluster, 4096)
        model = {}
        locks = {}
        for i in range(nfiles):
            name = f"st{i}"
            data = bytearray(random.Random(i).randbytes(size))
            with open(self.vol.path(name), "wb") as f:
                f.write(data)
            model[name] = data
            locks[name] = threading.Lock()
        stop = time.time() + seconds
        errors = []
        trace = {f"st{i}": [] for i in range(nfiles)}     # op dicts, see make_op()
        stats = {"moves": 0, "moved": 0, "busy": 0, "einval": 0, "enospc": 0}

        ops = CFG.get("ops", "wmtpv")       # write, mmap, truncate, punch, verify
        weights = [("w", 0.45), ("m", 0.15), ("t", 0.10), ("p", 0.08), ("v", 0.22)]
        weights = [(o, w) for o, w in weights if o in ops]

        def pick(rnd):
            x = rnd.random() * sum(w for _o, w in weights)
            for o, w in weights:
                if x < w:
                    return o
                x -= w
            return weights[-1][0]

        # which files writers and movers use (default: all of them)
        wfiles = CFG.get("writer_files") or list(range(nfiles))
        mfiles = CFG.get("mover_files") or list(range(nfiles))

        def writer(seed):
            rnd = random.Random(seed)
            while time.time() < stop and not errors:
                name = f"st{rnd.choice(wfiles)}"
                with locks[name]:
                    m = model[name]
                    op = make_op(rnd, pick(rnd), len(m), size, self.cluster)
                    if op is None:
                        continue
                    try:
                        bad = apply_op(self.vol.path(name), m, op)
                        trace[name].append(op)
                        stats[op["op"]] = stats.get(op["op"], 0) + 1
                        if bad:
                            errors.append(f"{name}: {bad}")
                            dump = os.path.join(WORK, f"fail-{name}-c{self.cluster}.json")
                            json.dump({"cluster": self.cluster, "size": size, "seed": int(name[2:]),
                                       "ops": trace[name]}, open(dump, "w"))
                            log(f"{name}: {bad}; {len(trace[name])} ops dumped to {dump}")
                    except Exception as e:
                        errors.append(f"writer {name}: {e!r}")

        def free_watch():
            while time.time() < stop and not errors:
                st = os.statvfs(MNT)
                stats.setdefault("free_mb", []).append(st.f_bfree * st.f_frsize >> 20)
                time.sleep(5)

        def mover(seed):
            rnd = random.Random(seed)
            while time.time() < stop and not errors:
                name = f"st{rnd.choice(mfiles)}"
                try:
                    fd = os.open(self.vol.path(name), os.O_RDONLY)
                except FileNotFoundError:
                    continue
                try:
                    mode = CFG.get("mover_mode", "move")
                    if mode == "nosync":        # FIEMAP without writeback
                        runs = merge(I.file_runs(fd, self.cluster, sync=False))
                    else:
                        runs = merge(I.file_runs(fd, self.cluster))
                    if not runs or mode == "fiemap":   # writeback only, no move
                        continue
                    v, _l, k = rnd.choice(runs)
                    off = rnd.randrange(k)
                    n = rnd.randrange(1, k - off + 1)
                    free = [f for f in self.vol.free() if f[1] >= n]
                    if not free:
                        continue
                    f0 = rnd.choice(free)
                    dst = f0[0] + rnd.randrange(f0[1] - n + 1)
                    r = I.move_errno(fd, v + off, dst, n)
                    with locks[name]:
                        trace[name].append({"op": "move", "vcn": v + off, "n": n, "lcn": dst, "r": r})
                    if r > 0:
                        stats["moves"] += 1
                        stats["moved"] += r
                    elif r == -16:
                        stats["busy"] += 1
                    elif r == -22:
                        stats["einval"] += 1          # truncated / punched meanwhile
                    elif r == -28:
                        stats["enospc"] += 1          # mapping pairs do not fit the record
                    else:
                        errors.append(f"move {name} {v + off}+{n}->{dst}: {I.errname(r)}")
                except Exception as e:
                    errors.append(f"mover {name}: {e!r}")
                finally:
                    os.close(fd)

        threads = [threading.Thread(target=writer, args=(s,)) for s in (1, 2)[:CFG.get("writers", 2)]]
        threads.append(threading.Thread(target=free_watch))
        threads += [threading.Thread(target=mover, args=(s,)) for s in (11, 12, 13)[:CFG.get("movers", 3)]]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log(f"c{self.cluster} stress: {stats}, errors {errors[:3]}")
        self.assertFalse(errors, errors[:5])
        if CFG.get("movers", 3) and CFG.get("mover_mode", "move") == "move":
            self.assertGreater(stats["moves"], 10, stats)
        for name, m in model.items():
            with open(self.vol.path(name), "rb") as f:
                self.assertEqual(f.read(), bytes(m), name)
            I.drop_caches()
            with open(self.vol.path(name), "rb") as f:
                self.assertEqual(f.read(), bytes(m), name + " after drop_caches")
            self.vol.record(name)


class ReplayTests(Base):
    """Replay operation traces dumped by test_stress, single-threaded, checking after every step."""

    def test_replay(self):
        for path in CFG.get("replay", []):
            tr = json.load(open(path))
            if tr["cluster"] != self.cluster:
                continue
            fragment_volume(self.vol, fill=0.6, big=())
            name = "replay"
            m = bytearray(random.Random(tr["seed"]).randbytes(tr["size"]))
            with open(self.vol.path(name), "wb") as f:
                f.write(m)
            fd = os.open(self.vol.path(name), os.O_RDONLY)
            first_bad = None
            for k, op in enumerate(tr["ops"]):
                if op["op"] == "move":
                    if CFG.get("replay_moves", True) and op["r"] > 0:
                        I.move_errno(fd, op["vcn"], op["lcn"], op["n"])
                    continue
                bad = apply_op(self.vol.path(name), m, op) or apply_op(self.vol.path(name), m, {"op": "v"})
                if bad:
                    first_bad = (k, op, bad, tr["ops"][max(0, k - 12):k])
                    break
            os.close(fd)
            log(f"replay {path}: {len(tr['ops'])} ops, first failure: {first_bad}")
            self.assertIsNone(first_bad, f"{path}: step {first_bad and first_bad[0]}: {first_bad and first_bad[2]}")
            self.vol.record(name)


# --- reproducible file operations (stress test and replay) -------------------


def make_op(rnd, kind, length, size, cluster):
    """A random operation as a dict with everything needed to replay it."""
    if kind == "w":
        return {"op": "w", "off": rnd.randrange(0, length + 1), "n": rnd.randrange(1, 3 * cluster),
                "seed": rnd.getrandbits(32), "fsync": rnd.random() < 0.2}
    if kind == "m" and length >= 4096:
        return {"op": "m", "off": rnd.randrange(0, length - 64), "seed": rnd.getrandbits(32),
                "msync": rnd.random() < 0.3}
    if kind == "t":
        return {"op": "t", "size": rnd.randrange(size // 2, size + size // 2)}
    if kind == "p" and length > 8 * cluster:
        return {"op": "p", "off": rnd.randrange(0, length - 4 * cluster), "n": rnd.randrange(1, 4 * cluster)}
    if kind == "v":
        return {"op": "v"}
    return None


def apply_op(path, m, op):
    """Apply @op to the file and to its model @m; returns a problem string or None."""
    kind = op["op"]
    if kind == "w":
        b = random.Random(op["seed"]).randbytes(op["n"])
        fd = os.open(path, os.O_WRONLY)
        try:
            done = os.pwrite(fd, b, op["off"])
            if op["fsync"]:
                os.fsync(fd)
        finally:
            os.close(fd)
        if op["off"] > len(m):
            m.extend(b"\0" * (op["off"] - len(m)))
        m[op["off"]:op["off"] + op["n"]] = b
        if done != op["n"]:
            # a short write is no data loss of the file system: report it
            # as what it is (the model above assumed the whole write)
            return f"short write: {done} of {op['n']} bytes at {op['off']}"
    elif kind == "m":
        b = random.Random(op["seed"]).randbytes(64)
        fd = os.open(path, os.O_RDWR)
        try:
            mm = mmap.mmap(fd, len(m))
            mm[op["off"]:op["off"] + 64] = b
            if op["msync"]:
                mm.flush()
            mm.close()
        finally:
            os.close(fd)
        m[op["off"]:op["off"] + 64] = b
    elif kind == "t":
        os.truncate(path, op["size"])
        if op["size"] < len(m):
            del m[op["size"]:]
        else:
            m.extend(b"\0" * (op["size"] - len(m)))
    elif kind == "p":
        fd = os.open(path, os.O_RDWR)
        try:
            fallocate_punch(fd, op["off"], op["n"])
            m[op["off"]:op["off"] + op["n"]] = b"\0" * op["n"]
        except OSError as e:
            if e.errno != 95:
                raise
        finally:
            os.close(fd)
    elif kind == "v":
        with open(path, "rb") as f:
            got = f.read()
        if got != bytes(m):
            return describe_diff(got, m)
    return None


def describe_diff(got, m):
    if len(got) != len(m):
        return f"size {len(got)} != {len(m)}"
    i = next(i for i in range(len(m)) if got[i] != m[i])
    j = i
    while j < len(m) and got[j] != m[j]:
        j += 1
    return f"contents differ at {i}..{j}: got {got[i:i + 16].hex()} want {bytes(m[i:i + 16]).hex()}"


def fallocate(fd, mode, off, n):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
    if libc.fallocate(fd, mode, off, n):
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def fallocate_punch(fd, off, n):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
    if libc.fallocate(fd, 0x01 | 0x02, off, n):            # KEEP_SIZE | PUNCH_HOLE
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def load_tests():
    suite = unittest.TestSuite()
    only = re.compile(CFG.get("only", "."))
    for cluster in CFG.get("clusters", [512, 4096, 65536]):
        for base in (GetFsMapTests, MoveTests) + ((ReplayTests,) if CFG.get("replay") else ()):
            cls = type(f"{base.__name__}_c{cluster}", (base,),
                       {"cluster": cluster, "size_mb": 256 if cluster >= 65536 else 128})
            for name in unittest.defaultTestLoader.getTestCaseNames(cls):
                if only.search(f"{cls.__name__}.{name}"):
                    suite.addTest(cls(name))
    return suite


class Result(unittest.TextTestResult):
    def addFailure(self, test, err):
        test._failed = True
        super().addFailure(test, err)

    def addError(self, test, err):
        test._failed = True
        super().addError(test, err)


def main():
    t0 = time.time()
    runner = unittest.TextTestRunner(stream=LOG, verbosity=2, resultclass=Result)
    res = runner.run(load_tests())
    out = {"tests": res.testsRun, "failures": [(str(t), tb) for t, tb in res.failures],
           "errors": [(str(t), tb) for t, tb in res.errors],
           "skipped": [(str(t), why) for t, why in res.skipped], "seconds": round(time.time() - t0)}
    json.dump(out, open(os.path.join(WORK, "results.json"), "w"), indent=1)
    log(f"done: {res.testsRun} tests, {len(res.failures)} failures, {len(res.errors)} errors")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log(traceback.format_exc())
        raise
