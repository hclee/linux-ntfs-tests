#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
In-VM tests of online defragmentation: ntfsdefrag (ntfsprogs-plus) run on a
volume mounted with the in-kernel ntfs driver.

Runs INSIDE the test VM as root (run_kernel_tests.sh with SUITE=online):

    python3 test_online_defrag.py WORKDIR

Uses the volume helpers and offline checks of test_ntfs_move.py (ntfsck,
independent on-disk parser, contents after remount, dmesg). WORKDIR/config.json
additionally needs "ntfsdefrag": path of the binary.
"""
import errno
import os
import random
import signal
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_ntfs_move as T  # noqa: E402
from test_ntfs_move import CFG, I, MNT, log, merge, run, sha  # noqa: E402

DEFRAG = CFG.get("ntfsdefrag")
# built with -DENABLE_FAULT_INJECTION, put next to it by hand (optional)
FAULT = os.path.join(os.path.dirname(DEFRAG or "/"), "ntfsdefrag-fault-injection")


def frag_count(vol, names):
    return {n: len(merge(vol.runs(n))) for n in names}


def layout(vol, names):
    """Everything a no-op run must leave alone: file runs and the free space."""
    return {n: merge(vol.runs(n)) for n in names}, vol.free()


def defrag(*args, check=True, timeout=1800, nocap=False):
    cmd = [DEFRAG, *args]
    if nocap:       # root without CAP_SYS_ADMIN
        cmd = ["setpriv", "--inh-caps=-sys_admin", "--bounding-set=-sys_admin", *cmd]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    log(f"$ {' '.join(cmd)} -> {r.returncode}\n{r.stdout[-3000:]}{r.stderr[-2000:]}")
    if check and r.returncode:
        raise AssertionError(f"ntfsdefrag {args} failed ({r.returncode}): {r.stderr[-1000:]}")
    return r


def make_fragmented(vol, nbig=6, seed=3):
    """Interleaved big files plus small ones; returns the names of the big files."""
    names = [f"big{i}" for i in range(nbig)]
    T.fragment_volume(vol, fill=0.55, big=tuple(names), big_size=int(vol.size * 0.025), seed=seed)
    return names


class OnlineTests(T.Base):
    def setUp(self):
        if not DEFRAG or not os.access(DEFRAG, os.X_OK):
            self.skipTest("no ntfsdefrag binary configured")
        super().setUp()

    def test_defragment(self):
        names = make_fragmented(self.vol)
        before = frag_count(self.vol, names)
        self.assertGreater(sum(before.values()), 2 * len(names), before)
        defrag("-v", MNT)
        after = frag_count(self.vol, names)
        log(f"c{self.cluster}: fragments {before} -> {after}")
        self.assertLess(sum(after.values()), sum(before.values()))
        self.assertEqual(sum(1 for v in after.values() if v > 1), 0, after)
        self.assertEqual(self.vol.verify_contents("after online defrag"), [])
        # a second run has nothing left to do and changes nothing
        snap = layout(self.vol, names)
        r = defrag(MNT)
        self.assertIn("Relocated 0", r.stdout)
        self.assertEqual(layout(self.vol, names), snap)

    def test_compact(self):
        names = make_fragmented(self.vol)
        free_before = self.vol.free()
        defrag("-c", MNT)
        free_after = self.vol.free()
        log(f"c{self.cluster}: free extents {len(free_before)} -> {len(free_after)}, "
            f"largest {max(f[1] for f in free_before)} -> {max(f[1] for f in free_after)}")
        self.assertLess(len(free_after), len(free_before))
        self.assertGreater(max(f[1] for f in free_after), max(f[1] for f in free_before))
        self.assertEqual(self.vol.verify_contents("after online -c"), [])

    def test_analyze_and_simulate_change_nothing(self):
        names = make_fragmented(self.vol)
        snap = layout(self.vol, names)
        r = defrag("-a", MNT)
        self.assertIn("fragmented:", r.stdout)
        r = defrag("-n", MNT)
        self.assertIn("After (simulated)", r.stdout)
        r = defrag("-n", "-c", MNT)
        self.assertEqual(layout(self.vol, names), snap)
        # -a works without CAP_SYS_ADMIN (GETFSMAP and FIEMAP need no
        # privilege), a real run does not
        r = defrag("-a", MNT, check=False, nocap=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = defrag(MNT, check=False, nocap=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CAP_SYS_ADMIN", r.stderr)
        self.assertEqual(layout(self.vol, names), snap)

    def test_subdirectory_refused(self):
        """A directory inside the volume is not the volume: refused, with the mount point named."""
        make_fragmented(self.vol, nbig=2)
        r = defrag(os.path.join(MNT, "small"), check=False)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("not a mount point", r.stderr)
        self.assertIn(MNT, r.stderr)

    def test_device_argument(self):
        names = make_fragmented(self.vol, nbig=3)
        r = defrag(self.vol.loop)
        self.assertIn("(mounted)", r.stdout)
        self.assertTrue(all(v == 1 for v in frag_count(self.vol, names).values()))

    def test_refuses_other_drivers(self):
        names = make_fragmented(self.vol, nbig=2)
        self.doCleanups()
        self.vol.umount()
        loop = run(["losetup", "-f", "--show", self.vol.img]).stdout.strip()
        try:
            r = run(["mount", "-t", "ntfs3", loop, MNT], check=False)
            if r.returncode:
                self.skipTest(f"ntfs3 not available: {r.stderr}")
            try:
                r = defrag(loop, check=False)
                self.assertEqual(r.returncode, 1)
                self.assertIn("ntfs3", r.stderr)
                r = defrag(MNT, check=False)
                self.assertEqual(r.returncode, 1)
                self.assertIn("in-kernel ntfs driver", r.stderr)
            finally:
                run(["umount", MNT])
        finally:
            run(["losetup", "-d", loop])
            time.sleep(0.2)
        self.vol.mount()
        self.assertTrue(all(v > 1 for v in frag_count(self.vol, names).values()))

    def test_interrupt(self):
        names = make_fragmented(self.vol, nbig=8)
        p = subprocess.Popen([DEFRAG, "-c", MNT], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.3)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=600)
        log(f"interrupted run: {p.returncode}\n{out[-1500:]}{err[-500:]}")
        self.assertIn(p.returncode, (0, 2))
        self.assertEqual(self.vol.verify_contents("after SIGINT"), [])
        defrag(MNT)
        self.assertTrue(all(v == 1 for v in frag_count(self.vol, names).values()))

    def test_bind_mount_of_a_directory_refused(self):
        """A bind mount of a directory of the volume is not the volume."""
        make_fragmented(self.vol, nbig=2)
        other = "/mnt/bind-test"
        os.makedirs(other, exist_ok=True)
        run(["mount", "--bind", os.path.join(MNT, "small"), other])
        try:
            r = defrag(other, check=False)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("whole volume", r.stderr)
            self.assertIn(MNT, r.stderr)
            # the device still leads to the mount of the whole volume
            r = defrag("-a", self.vol.loop)
            self.assertIn(f"NTFS volume {MNT} (mounted)", r.stdout)
        finally:
            run(["umount", other])

    def test_read_only_mount_refused(self):
        """A read-only mount is refused up front, -a still works."""
        names = make_fragmented(self.vol, nbig=2)
        self.vol.umount()
        self.vol.mount(ro=True)
        try:
            r = defrag(MNT, check=False)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("read-only", r.stderr)
            self.assertNotIn("Relocated", r.stdout)
            defrag("-a", MNT)
        finally:
            self.vol.umount()
            self.vol.mount()
        self.assertTrue(all(v > 1 for v in frag_count(self.vol, names).values()))

    def test_immutable_file_left_alone(self):
        """Files the driver will not move (immutable, append-only) are
        left alone up front instead of failing every move."""
        names = make_fragmented(self.vol, nbig=4)
        before = frag_count(self.vol, names)
        pinned = names[:2]
        run(["chattr", "+i", self.vol.path(pinned[0])])
        run(["chattr", "+a", self.vol.path(pinned[1])])
        try:
            r = defrag(MNT)
        finally:
            run(["chattr", "-i", self.vol.path(pinned[0])])
            run(["chattr", "-a", self.vol.path(pinned[1])])
        # (no move of them was even tried)
        self.assertNotRegex(r.stdout, r"moves (failed|were refused)")
        after = frag_count(self.vol, names)
        self.assertEqual({n: after[n] for n in pinned}, {n: before[n] for n in pinned})
        self.assertTrue(all(after[n] == 1 for n in names[2:]), after)
        self.assertEqual(self.vol.verify_contents("after pinned files"), [])

    def _refused(self, err, hit):
        """The driver moves half of a piece, then fails with @err."""
        if not os.access(FAULT, os.X_OK):
            self.skipTest(f"no {FAULT}")
        names = make_fragmented(self.vol)
        env = dict(os.environ, NTFSDEFRAG_FAIL_AT=f"move_ioctl:{hit}",
                   NTFSDEFRAG_FAIL_ERRNO=str(err))
        r = subprocess.run([FAULT, "-v", MNT], capture_output=True, text=True,
                           timeout=1800, env=env)
        log(f"$ {FAULT} -v {MNT} [{err}@{hit}] -> {r.returncode}\n"
            f"{r.stdout[-3000:]}{r.stderr[-2000:]}")
        self.assertIn("[test] simulated failure", r.stderr)
        self.assertNotIn("BUG", r.stdout + r.stderr)
        self.assertEqual(self.vol.verify_contents(f"after errno {err}"), [])
        return names, r

    def _refused_then_finished(self, err, hit):
        """The refused move is settled with the kernel's free space and the
        run goes on; a second run finishes the job."""
        names, r = self._refused(err, hit)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("moves failed", r.stdout)
        defrag(MNT)
        self.assertTrue(all(v == 1 for v in frag_count(self.vol, names).values()))
        self.assertEqual(self.vol.verify_contents("after the second run"), [])

    def test_refused_move_enospc(self):
        """The new runlist does not fit into the MFT records."""
        self._refused_then_finished(errno.ENOSPC, 1)

    def test_refused_move_einval(self):
        """The file changed between the check and the move."""
        self._refused_then_finished(errno.EINVAL, 2)

    def test_refused_move_eperm(self):
        self._refused_then_finished(errno.EPERM, 3)

    def test_refused_move_ebusy(self):
        """The destination was taken meanwhile."""
        self._refused_then_finished(errno.EBUSY, 1)

    def test_fatal_move_error(self):
        """An I/O error from the driver stops the run with status 1."""
        _names, r = self._refused(errno.EIO, 2)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("Stopped after an error from the ntfs driver", r.stderr)

    def test_attribute_list_file(self):
        """A file of some 600 runs spread over extent records (attribute
        list) ends contiguous: its runs move to one place in one call, so
        no MFT record has to hold more mapping pairs than before."""
        T.make_attr_list_file(self.vol, "alist", seed=11, min_extents=3)
        before = len(merge(self.vol.runs("alist")))
        self.assertGreater(before, 300)
        want = sha(self.vol.path("alist"))
        r = defrag("-v", MNT)
        self.assertNotIn("moves failed", r.stdout)
        self.assertEqual(len(merge(self.vol.runs("alist"))), 1)
        T.I.drop_caches()
        self.assertEqual(sha(self.vol.path("alist")), want)
        self.vol.record("alist")
        self.assertEqual(self.vol.verify_contents("after the attribute list file"), [])

    def test_mft_zone_kept_free(self):
        """The driver accepts destinations in its MFT zone; ntfsdefrag keeps
        the zone behind $MFT (-z) free itself: no file gains clusters
        there, also with -c."""
        make_fragmented(self.vol)
        with open(self.vol.loop, "rb") as f:
            boot = f.read(512)
        mft = int.from_bytes(boot[48:56], "little")
        start = min(lcn for lcn, _n in self.vol.free() if lcn > mft)
        zone = range(start, start + (16 << 20) // self.vol.cluster)
        log(f"$MFT at {mft}, zone {zone.start}..{zone.stop}")

        def in_zone():
            got = {}
            for top, _dirs, files in os.walk(MNT):
                for name in files:
                    rel = os.path.relpath(os.path.join(top, name), MNT)
                    got[rel] = {lcn + k for _v, lcn, n in self.vol.runs(rel)
                                if lcn >= 0 for k in range(n)
                                if lcn + k in zone}
            return got

        before = in_zone()
        defrag("-v", "-z", "16", MNT)
        defrag("-v", "-c", "-z", "16", MNT)
        after = in_zone()
        grown = {n: sorted(after[n] - before.get(n, set()))[:4]
                 for n in after if after[n] - before.get(n, set())}
        self.assertEqual(grown, {})
        self.assertEqual(self.vol.verify_contents("after -z"), [])

    def test_named_streams(self):
        """Named streams are moved on a streams_interface=windows mount, left alone otherwise."""
        names = make_fragmented(self.vol, nbig=2)
        self.doCleanups()
        self.vol.umount()
        self.vol.mount_opts = ["-o", "streams_interface=windows"]
        self.vol.mount()
        rnd = random.Random(7)
        ads = []
        piece = max(8 * self.vol.cluster, 32768)
        for i in range(6):        # fragmented named streams: interleave their growth
            for n in names:
                p = f"{n}:s{i % 2}"
                with open(self.vol.path(p), "ab") as f:
                    f.write(rnd.randbytes(piece))
                    f.flush()
                    os.fsync(f.fileno())
                if p not in ads:
                    ads.append(p)
        self.assertFalse(any(":" in e for e in os.listdir(MNT)), "streams must not be plain files")
        want = {p: sha(self.vol.path(p)) for p in ads}   # checked here, not offline
        before = frag_count(self.vol, ads)
        self.assertGreater(sum(before.values()), len(ads))
        defrag(MNT)
        after = frag_count(self.vol, ads)
        log(f"named streams: {before} -> {after}")
        self.assertTrue(all(v == 1 for v in after.values()), after)
        T.I.drop_caches()
        self.assertEqual({p: sha(self.vol.path(p)) for p in ads}, want)

    def test_under_load(self):
        """Online defragmentation while files are created, appended, rewritten and deleted."""
        self._under_load(defragment=True)

    def test_under_load_control(self):
        """The same load without defragmentation (tells driver bugs from ours)."""
        self._under_load(defragment=False)

    def _under_load(self, defragment):
        names = make_fragmented(self.vol, nbig=8)
        stop = threading.Event()
        errors = []
        model = {}
        lock = threading.Lock()

        # the load stays well below the free space: an ENOSPC would leave
        # files partly written and the model wrong
        budget = sum(n for _l, n in self.vol.free()) * self.vol.cluster // 3

        def total():
            return sum(len(v) for v in model.values())

        def worker(seed):
            rnd = random.Random(seed)
            k = 0
            while not stop.is_set() and not errors:
                k += 1
                name = f"load{seed}_{rnd.randrange(12)}"
                path = self.vol.path(name)
                try:
                    with lock:
                        m = model.get(name)
                        op = rnd.random()
                        if m is not None and op < 0.5 and total() > budget:
                            op = 0.75                # shrink instead of grow
                        if m is None and total() > budget:
                            continue
                        if m is None or op < 0.2:
                            m = bytearray(rnd.randbytes(rnd.randrange(1, 40) * self.vol.cluster))
                            with open(path, "wb") as f:
                                f.write(m)
                            model[name] = m
                        elif op < 0.5:
                            b = rnd.randbytes(rnd.randrange(1, 4 * self.vol.cluster))
                            with open(path, "ab") as f:
                                f.write(b)
                            m.extend(b)
                        elif op < 0.7 and len(m):
                            off = rnd.randrange(len(m))
                            b = rnd.randbytes(min(len(m) - off, 3000))
                            fd = os.open(path, os.O_WRONLY)
                            try:
                                n = os.pwrite(fd, b, off)   # may be short
                            finally:
                                os.close(fd)
                            m[off:off + n] = b[:n]
                        elif op < 0.8:
                            os.unlink(path)
                            del model[name]
                        else:
                            with open(path, "rb") as f:
                                got = f.read()
                            if got != bytes(m):
                                errors.append(f"{name}: " + T.describe_diff(got, m))
                except Exception as e:
                    if not isinstance(e, OSError):
                        errors.append(f"{name}: {e!r}")
                    elif e.errno == 28 and name in model:
                        # out of space anyway: take what the file holds now
                        with open(path, "rb") as f:
                            model[name] = bytearray(f.read())
                        log(f"{name}: ENOSPC (total {total()}, budget {budget})")
                    elif e.errno != 28:
                        errors.append(f"{name}: {e!r}")

        threads = [threading.Thread(target=worker, args=(s,)) for s in (1, 2, 3)]
        for t in threads:
            t.start()
        try:
            if defragment:
                for args in ([], ["-c"], []):
                    r = defrag(*args, MNT, check=False)
                    self.assertIn(r.returncode, (0,), r.stderr)
            else:
                time.sleep(CFG.get("load_seconds", 20))
        finally:
            stop.set()
            for t in threads:
                t.join()
        self.assertFalse(errors, errors[:5])
        for name, m in model.items():
            with open(self.vol.path(name), "rb") as f:
                self.assertEqual(f.read(), bytes(m), name)
            self.vol.expected[name] = sha(self.vol.path(name))
        self.assertEqual(self.vol.verify_contents("after load"), [])


def load_tests():
    import re
    suite = unittest.TestSuite()
    only = re.compile(CFG.get("only", "."))
    for cluster in CFG.get("clusters", [512, 4096, 65536]):
        cls = type(f"OnlineTests_c{cluster}", (OnlineTests,),
                   {"cluster": cluster, "size_mb": 256 if cluster >= 65536 else 128})
        for name in unittest.defaultTestLoader.getTestCaseNames(cls):
            if only.search(f"{cls.__name__}.{name}"):
                suite.addTest(cls(name))
    return suite


if __name__ == "__main__":
    T.load_tests = load_tests
    T.main()
