#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Crash-consistency test of online defragmentation (NTFS_IOC_MOVE_CLUSTERS)
with dm-log-writes, the way xfstests generic/482 does it.

Runs INSIDE the test VM as root (run_kernel_tests.sh with SUITE=crash):

    python3 test_crash_logwrites.py WORKDIR

The volume sits on a dm-log-writes target that records every write together
with its FLUSH/FUA flags. Files are written and synced, the log is marked,
then the volume is defragmented online (ntfsdefrag, or random move ioctls).
Afterwards the log is replayed onto a scratch device up to every flush and
FUA point after the mark - each one a state the disk could be in after a
power cut - and every state is checked:
  - ntfsck -n may only report clusters marked in use that nothing owns
    (and the dirty flag): moves can leak clusters, never lose data,
  - every file, read straight from the image by an independent parser
    (ntfsdefrag.py of this repo) through its attribute list the way a
    driver reads it (ntfs_strict.py), has exactly its original contents,
  - no cluster a file uses is free in $Bitmap, none is used twice, and if
    clusters leaked, the volume is marked dirty on disk (the volume is
    unmounted and mounted again before the mark, so it starts clean).

The checks run in parallel: at each check point replay-log only runs a short
shell script that copies the replay device to a numbered sparse image (and
waits while 2 x crash_jobs images are pending), and a pool of crash_jobs
checkers (default: the VM's CPUs) checks the images as they appear. A failed
check no longer stops the replay, so every bad point is reported.

WORKDIR/config.json: ntfsck, prototype, ntfsdefrag, replay_log, clusters,
crash_workloads (["defrag", "defrag-c", "moves", "eof", "alist",
"alist-defrag"]), crash_jobs, crash_every_write (workloads also checked after
every single write, as on a device that keeps the order of writes; default
moves, eof, alist, alist-defrag).

The "alist" workloads use a file whose $DATA needs an attribute list and
three extents (base record and two extent records): "alist" makes random
moves on it that shrink its mapping (several runs into one place), grow it
(one cluster out of the middle of a run) and one that puts half of the file
in one place; "alist-defrag" runs ntfsdefrag on that volume.

The "eof" workload moves clusters preallocated past the end of a file
(FALLOC_FL_KEEP_SIZE). Nothing is copied then, so besides the usual checks the
log itself is checked: a FLUSH must come between the $Bitmap write that marks
the new clusters in use and the MFT record write that points to them (a
device may otherwise write the record first, and a power cut leaves clusters
in use that $Bitmap calls free).
Results: WORKDIR/results.json, WORKDIR/test.log.
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ntfs_ioctls as I  # noqa: E402
import ntfs_strict as strict  # noqa: E402

WORK = os.path.abspath(sys.argv[1])
CFG = json.load(open(os.path.join(WORK, "config.json")))
LOG = open(os.path.join(WORK, "test.log"), "a", buffering=1)
TMP = "/mnt/crash"
MNT = TMP + "/mnt"


def log(*a):
    print(*a, file=LOG)


def run(cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{cmd} -> {r.returncode}: {r.stdout[-1500:]} {r.stderr[-1500:]}")
    return r


def losetup(path):
    return run(["losetup", "-f", "--show", path]).stdout.strip()


def make_files(cluster, size):
    """Fragmented big files plus small ones; returns {relative path: sha256}."""
    rnd = random.Random(cluster)
    os.makedirs(f"{MNT}/small", exist_ok=True)
    piece = max(4 * cluster, 16384)
    names = []
    for i in range(int(size * 0.45 / piece)):
        p = f"small/s{i:05d}"
        try:
            with open(f"{MNT}/{p}", "wb") as f:
                f.write(rnd.randbytes(piece))
        except OSError:
            break
        names.append(p)
    os.sync()
    for p in names[::2]:
        os.unlink(f"{MNT}/{p}")
    os.sync()
    big = [f"big{i}" for i in range(4)]
    files = [open(f"{MNT}/{b}", "wb") for b in big]
    for _ in range(int(size * 0.03 / piece)):
        for f in files:
            f.write(rnd.randbytes(piece * rnd.randrange(1, 3)))
            f.flush()
            os.fsync(f.fileno())
    for f in files:
        f.close()
    os.sync()
    expected = {}
    for p in big + names[1::2][::7]:
        with open(f"{MNT}/{p}", "rb") as f:
            expected[p] = hashlib.sha256(f.read()).hexdigest()
    return expected


def random_moves(cluster, count, seed):
    rnd = random.Random(seed)
    names = [n for n in os.listdir(MNT) if n.startswith("big")]
    done = 0
    root = os.open(MNT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(count * 4):
            if done >= count:
                break
            fd = os.open(f"{MNT}/{rnd.choice(names)}", os.O_RDONLY)
            try:
                runs = I.file_runs(fd, cluster)
                if not runs:
                    continue
                v, _l, n = rnd.choice(runs)
                off = rnd.randrange(n)
                n = rnd.randrange(1, n - off + 1)
                free = [f for f in I.free_extents(root, cluster) if f[1] >= n]
                if not free:
                    continue
                f0 = rnd.choice(free)
                if I.move_errno(fd, v + off, f0[0] + rnd.randrange(f0[1] - n + 1), n) > 0:
                    done += 1
            finally:
                os.close(fd)
    finally:
        os.close(root)
    return done


def eof_prepare(cluster, expected):
    """A file with clusters preallocated past its end; returns its MFT number."""
    path = f"{MNT}/keep"
    data = b"K" * (2 * cluster + 100)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        os.pwrite(fd, data, 0)
        fallocate(fd, 0x01, 0, 30 * cluster)          # KEEP_SIZE
        os.fsync(fd)
    finally:
        os.close(fd)
    expected["keep"] = hashlib.sha256(data).hexdigest()
    return os.stat(path).st_ino


def eof_move(cluster):
    """Move clusters 3..29 of keep (all past EOF); returns (lcn, moved)."""
    root = os.open(MNT, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(f"{MNT}/keep", os.O_RDWR)
    try:
        free = [f for f in I.free_extents(root, cluster) if f[1] >= 27]
        lcn = free[-1][0] + free[-1][1] - 27
        return lcn, I.move_clusters(fd, 3, lcn, 27)
    finally:
        os.close(fd)
        os.close(root)


def alist_prepare(cluster, dev, expected):
    """A file whose $DATA needs an attribute list and at least 3 extents
    (base record plus 2 extent records): its pieces of 1 cluster (some of 3)
    are interleaved with those of a spacer file of zeros, which is deleted
    afterwards, so the gaps are free and read as zeros in the images."""
    rnd = random.Random(cluster * 3)
    a = open(f"{MNT}/alist", "wb")
    b = open(f"{MNT}/spacer", "wb")
    num = os.fstat(a.fileno()).st_ino
    rounds = 0
    while True:
        for _ in range(100):
            a.write(rnd.randbytes(cluster * (3 if rnd.random() < 0.15 else 1)))
            a.flush()
            os.fsync(a.fileno())
            b.write(bytes(cluster))
            b.flush()
            os.fsync(b.fileno())
            rounds += 1
        I.drop_caches()
        n = strict.data_extents(dev, num)
        if n >= 3 or rounds >= 3000:
            break
    a.close()
    b.close()
    os.unlink(f"{MNT}/spacer")
    os.sync()
    with open(f"{MNT}/alist", "rb") as f:
        expected["alist"] = hashlib.sha256(f.read()).hexdigest()
    log(f"alist: {rounds} rounds, {n} extents of $DATA")
    if n < 3:
        raise RuntimeError(f"alist has only {n} extents after {rounds} rounds")


def alist_moves(cluster, seed):
    """Moves on the attribute list file that shrink its mapping (several runs
    into one), grow it (a cluster out of the middle of a run) and one that
    consolidates half of the file. Returns (moved, failed by errno)."""
    rnd = random.Random(seed)
    root = os.open(MNT, os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open(f"{MNT}/alist", os.O_RDONLY)
    done, failed = 0, {}

    def move(v, n):
        nonlocal done
        free = [f for f in I.free_extents(root, cluster) if f[1] >= n]
        if not free:
            failed["nofree"] = failed.get("nofree", 0) + 1
            return
        f0 = max(free, key=lambda f: f[1]) if n > 16 else rnd.choice(free)
        r = I.move_errno(fd, v, f0[0] + rnd.randrange(f0[1] - n + 1), n)
        if r > 0:
            done += 1
        else:
            name = I.errname(r)
            failed[name] = failed.get(name, 0) + 1

    try:
        for i in range(30):
            runs = I.file_runs(fd, cluster)
            kind = ("grow", "shrink")[i % 2]
            if i == 20:                 # half of the file into one run
                k = len(runs) // 2
                s0 = rnd.randrange(len(runs) - k)
                move(runs[s0][0], runs[s0 + k][0] - runs[s0][0])
            elif kind == "grow":
                long = [r for r in runs if r[2] >= 3]
                if long:
                    v, _l, n = rnd.choice(long)
                    move(v + rnd.randrange(1, n - 1), 1)
            else:
                k = rnd.randrange(2, 9)
                s0 = rnd.randrange(len(runs) - k)
                move(runs[s0][0], runs[s0 + k][0] - runs[s0][0])
    finally:
        os.close(fd)
        os.close(root)
    return done, failed


def fallocate(fd, mode, off, n):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
    if libc.fallocate(fd, mode, off, n):
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def eof_order(logdev, replay, ino, lcn, n):
    """Problems with the write order of the eof move: a FLUSH must separate
    the $Bitmap write for [lcn, lcn+n) from the next write of MFT record ino.
    Replays the log from the mark (verbose) to see every entry."""
    import re
    sys.path.insert(0, os.path.dirname(os.path.abspath(CFG["prototype"])))
    import ntfsdefrag as proto
    hdr = run([CFG["replay_log"], "--log", logdev]).stdout
    ssz = int(re.search(r"sectorsize=(\d+)", hdr).group(1))
    run([CFG["replay_log"], "--log", logdev, "--replay", replay, "--end-mark", "start"])
    out = run([CFG["replay_log"], "-v", "--log", logdev, "--replay", replay, "--start-mark", "start"]).stdout
    entries = []
    for m in re.finditer(r"replaying (\d+)@\d+: sector (\d+), size (\d+), flags 0x[0-9a-f]+\(([^)]*)\)", out):
        entries.append((int(m.group(1)), int(m.group(2)) * ssz, int(m.group(3)), m.group(4)))
    vol = proto.Volume(replay, allow_mounted=True)
    try:
        vol.scan()
        bm = []                                      # disk ranges of the $Bitmap bytes
        for byte in range(lcn >> 3, ((lcn + n - 1) >> 3) + 1):
            vcn, within = divmod(byte, vol.cluster)
            blcn, _ = vol.vcn_to_lcn(vol.bitmap_runs, vcn)
            bm.append((blcn * vol.cluster + within, 1))
        rec = vol.record_pieces(ino)
    finally:
        vol.close()

    def hits(e, ranges):
        return e[2] and any(e[1] < o + ln and o < e[1] + e[2] for o, ln in ranges)
    first_bm = next((i for i, e in enumerate(entries) if hits(e, bm)), None)
    if first_bm is None:
        return [f"eof order: no $Bitmap write for clusters {lcn}+{n} in {len(entries)} entries"]
    m = next((i for i in range(first_bm + 1, len(entries)) if hits(entries[i], rec)), None)
    if m is None:
        return [f"eof order: no write of MFT record {ino} after the $Bitmap write"]
    b = max(i for i in range(first_bm, m) if hits(entries[i], bm))
    if not any("FLUSH" in entries[i][3] for i in range(b + 1, m + 1)):
        return [f"eof order: no FLUSH between the $Bitmap write (entry {entries[b][0]}) and "
                f"the MFT record write (entry {entries[m][0]}, flags {entries[m][3] or 'none'})"]
    log(f"eof order ok: $Bitmap entry {entries[b][0]}, MFT entry {entries[m][0]}")
    return []


def write_checker(expected, cluster, path=None):
    """The check of one image (argv: image, label); exit 0 = consistent."""
    path = path or f"{TMP}/check.py"
    with open(path, "w") as f:
        f.write(f'''
import hashlib, json, subprocess, sys
sys.path.insert(0, {os.path.dirname(os.path.abspath(CFG["prototype"]))!r})
sys.path.insert(0, {HERE!r})
import ntfsdefrag as proto
import ntfs_strict as strict
dev, n = sys.argv[1], sys.argv[2]
expected = {expected!r}
problems = []
r = subprocess.run([{CFG["ntfsck"]!r}, "-n", dev], capture_output=True, text=True)
out = r.stdout + r.stderr
# leaked clusters, the dirty flag, and (after single writes) a record of
# $MFT 0-3 whose mirror copy was written but not the record itself yet: the
# driver writes the mirror first, so every update of $Volume passes that state
ok_words = ("bitmap", "dirty", "$mft/$mftmirr records do not match")
if r.returncode:
    bad = [l for l in out.splitlines() if ("Fix it?" in l or "rror" in l) and "errors:" not in l
           and not any(w in l.lower() for w in ok_words)]
    if bad or not any(w in l.lower() for l in out.splitlines() for w in ok_words):
        problems.append("ntfsck: " + " | ".join((bad or out.splitlines())[:6]))
try:
    vol = proto.Volume(dev, allow_mounted=True)
    vol.scan()
    by_name = {{}}
    for (num, typ, name), st in vol.streams.items():
        if typ == proto.AT_DATA and name == "":
            by_name[vol.path_of(num).lstrip("/")] = num
    for p, digest in expected.items():
        num = by_name.get(p)
        if num is None:
            problems.append(p + ": missing")
            continue
        try:
            runs, size = strict.stream_runs(vol, num)
        except strict.Corrupt as e:
            problems.append(p + ": " + str(e))
            continue
        data = vol.read_stream_bytes(runs, size)
        if hashlib.sha256(data).hexdigest() != digest:
            problems.append(p + ": contents differ")
    bad, leaked = strict.bitmap_problems(vol)
    problems += bad
    flags = strict.volume_flags(vol)
    if leaked and not flags & 1:
        problems.append(f"{{leaked}} clusters leaked on a volume that is clean on disk (flags {{flags:#x}})")
    vol.close()
except Exception as e:
    problems.append("parser: " + repr(e))
if problems:
    print("\\n".join(problems), file=sys.stderr)
    with open({TMP + "/problems"!r}, "a") as f:
        f.write(f"check {{n}}: " + "; ".join(problems) + "\\n")
    sys.exit(1)
''')
    return path


def summarize(lines):
    """Problems grouped by kind (numbers stripped): a count and the first
    one of each, so that a frequent kind does not hide a rarer one."""
    import re
    kinds = {}
    for ln in lines:
        where, sep, rest = ln.partition(": ")
        parts = rest.split("; ") if ln.startswith("check ") and sep else [ln]
        for part in parts:
            k = re.sub(r"\d+", "N", part)
            kinds.setdefault(k, []).append(f"{where}: {part}" if len(parts) > 1 or part != ln else ln)
    return [f"{len(v)}x {v[0]}" for v in kinds.values()]


def problem(text):
    with open(f"{TMP}/problems", "a") as f:
        f.write(text + "\n")


def check_image(checker, path, label):
    """Run the checker on one image and delete it. A checker that fails
    without saying why (crash, missing tool) is a problem too: nothing may
    turn into a pass silently."""
    try:
        r = subprocess.run([sys.executable, "-I", checker, path, label], capture_output=True, text=True)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    if r.returncode and r.returncode != 1:
        problem(f"check {label}: checker exited {r.returncode}: {r.stderr.strip()[-300:]}")
    elif r.returncode and not r.stderr.strip():
        problem(f"check {label}: checker failed without output")
    return r.returncode == 0


def replay_checked(logdev, replay, mode, checker):
    """Replay the log from the mark, checking every `mode` point in parallel.

    replay-log calls snap.sh at each point; it copies the replay device to
    SNAP/<n>.img (sparse, renamed when complete) and waits while too many
    images are pending. Checker processes take the images in order and
    delete them. Returns (replay-log exit code, number of points checked).
    """
    jobs = CFG.get("crash_jobs") or os.cpu_count() or 1
    snap = f"{TMP}/snap"
    os.makedirs(snap, exist_ok=True)
    for f in os.listdir(snap):
        os.unlink(os.path.join(snap, f))
    script = f"{TMP}/snap.sh"
    with open(script, "w") as f:
        f.write(f"""#!/bin/sh
d={snap}
n=$(( $(cat $d/counter) + 1 )); echo $n > $d/counter
while :; do
    set -- $d/*.img
    if [ ! -e "$1" ] || [ $# -lt {2 * jobs} ]; then break; fi
    sleep 0.02
done
cp --sparse=always "{replay}" $d/$n.tmp && mv $d/$n.tmp $d/$n.img
""")
    os.chmod(script, 0o755)
    open(f"{snap}/counter", "w").write("0")
    errf = open(f"{TMP}/replay-{mode}.err", "w+")     # a file: a full pipe would stall replay-log
    proc = subprocess.Popen([CFG["replay_log"], "--log", logdev, "--replay", replay, "--start-mark", "start",
                             "--check", mode, "--fsck", script],
                            stdout=subprocess.DEVNULL, stderr=errf, text=True)
    failed = []
    lock = threading.Lock()

    def check(path, n):
        if not check_image(checker, path, f"{mode} {n}"):
            with lock:
                failed.append(n)

    taken = set()
    futures = []
    with ThreadPoolExecutor(jobs) as pool:
        while True:
            done = proc.poll() is not None
            imgs = sorted((int(f[:-4]) for f in os.listdir(snap) if f.endswith(".img")))
            for n in imgs:
                if n not in taken:
                    taken.add(n)
                    futures.append(pool.submit(check, f"{snap}/{n}.img", n))
            if done:
                break
            time.sleep(0.02)
        for fu in futures:
            fu.result()
    errf.seek(0)
    err = errf.read()
    errf.close()
    if proc.returncode:
        log(f"replay-log {mode}: rc {proc.returncode}: {err[-500:]}")
    raw = open(f"{snap}/counter").read().strip()
    total = int(raw) if raw.isdigit() else -1
    if len(taken) != total:      # a copy failed: count it as a problem
        problem(f"{mode}: {total} points, {len(taken)} images")
    log(f"{mode}: {total} points checked with {jobs} jobs, {len(failed)} bad")
    return proc.returncode, total


def one_case(cluster, workload):
    size = CFG.get("crash_size_mb", 48) << 20
    if workload.startswith("alist"):     # about 600 pieces of 1-3 clusters, half freed
        size = max(size, 1400 * 2 * cluster)
    for p in ("data", "log", "replay"):
        if os.path.exists(f"{TMP}/{p}.img"):
            os.unlink(f"{TMP}/{p}.img")
    for p, sz in (("data", size), ("replay", size), ("log", 1200 << 20)):
        with open(f"{TMP}/{p}.img", "wb") as f:
            f.truncate(sz)
    data, logdev, replay = (losetup(f"{TMP}/{p}.img") for p in ("data", "log", "replay"))
    sectors = size // 512
    # no udev in the test VM: do not wait for it, make the node ourselves
    run(["dmsetup", "create", "--noudevsync", "lw", "--table",
         f"0 {sectors} log-writes {data} {logdev}"])
    run(["dmsetup", "mknodes", "lw"])
    dev = "/dev/mapper/lw"
    result = {"cluster": cluster, "workload": workload}
    try:
        run(["mkntfs", "-q", "-F", "-Q", "-c", str(cluster), dev])
        os.makedirs(MNT, exist_ok=True)
        run(["mount", "-i", "-t", "ntfs", dev, MNT])
        if workload.startswith("alist"):
            expected = {}
            alist_prepare(cluster, dev, expected)
        else:
            expected = make_files(cluster, size)
        if workload == "eof":
            ino = eof_prepare(cluster, expected)
        # a clean unmount clears the dirty flag: the moves start from a
        # volume that is clean on disk, so a leak must set the flag itself
        run(["umount", MNT])
        run(["mount", "-i", "-t", "ntfs", dev, MNT])
        os.sync()
        run(["dmsetup", "message", "lw", "0", "mark", "start"])
        t0 = time.time()
        if workload == "eof":
            eof_lcn, result["moves"] = eof_move(cluster)
        elif workload == "alist":
            result["moves"], result["move_errors"] = alist_moves(cluster, cluster)
        elif workload == "moves":
            result["moves"] = random_moves(cluster, CFG.get("crash_moves", 40), cluster)
        else:
            args = ["-c"] if workload == "defrag-c" else []
            r = run([CFG["ntfsdefrag"], *args, MNT], check=False)
            result["ntfsdefrag_rc"] = r.returncode
            result["ntfsdefrag"] = r.stdout.strip().splitlines()[-1:] + r.stderr.strip().splitlines()[-3:]
        result["workload_s"] = round(time.time() - t0, 1)
        os.sync()
        run(["umount", MNT])
        run(["dmsetup", "message", "lw", "0", "mark", "end"])
        run(["dmsetup", "remove", "--noudevsync", "lw"])
        # the state at the mark, then every flush / FUA point after it
        run([CFG["replay_log"], "--log", logdev, "--replay", replay, "--end-mark", "start"])
        checker = write_checker(expected, cluster)
        if os.path.exists(f"{TMP}/problems"):
            os.unlink(f"{TMP}/problems")
        t0 = time.time()
        checks = 0
        modes = list(CFG.get("crash_check", ["flush", "fua"]))
        # the state after every single write too (a device that keeps the
        # order of writes): orderings within one flush interval show there
        if workload in CFG.get("crash_every_write", ["moves", "eof", "alist", "alist-defrag"]):
            modes.append("1")
        for mode in modes:
            run([CFG["replay_log"], "--log", logdev, "--replay", replay, "--end-mark", "start"])
            rc, n = replay_checked(logdev, replay, mode, checker)
            result[f"replay_{mode}_rc"] = rc
            checks += n
        result["checks"] = checks
        result["check_s"] = round(time.time() - t0, 1)
        # the checker itself must catch a wrong file: a checker that passes
        # everything would make this whole test vacuous
        some = sorted(expected)[0]
        bad = write_checker({**expected, some: "0" * 64}, cluster, f"{TMP}/check-bad.py")
        run(["cp", "--sparse=always", replay, f"{TMP}/selfcheck.img"])
        if check_image(bad, f"{TMP}/selfcheck.img", "selfcheck"):
            problem("selfcheck: the checker accepted a wrong digest of " + some)
        else:       # the expected rejection is not a problem of this case
            lines = open(f"{TMP}/problems").read().splitlines()
            keep = [ln for ln in lines if "check selfcheck:" not in ln]
            if len(keep) != len(lines) - 1:
                problem(f"selfcheck: expected one rejection line, got {lines[-3:]}")
            else:
                open(f"{TMP}/problems", "w").write("".join(k + "\n" for k in keep))
        result["problems"] = summarize(open(f"{TMP}/problems").read().splitlines()
                                       if os.path.exists(f"{TMP}/problems") else [])
        if workload == "eof":
            result["problems"] += eof_order(logdev, replay, ino, eof_lcn, 27)
            if result["moves"] != 27:
                result["problems"].append(f"eof: moved {result['moves']} of 27 clusters")
        # and the final state, fully replayed, must be clean
        r = run([CFG["ntfsck"], "-n", replay], check=False)
        result["final_ntfsck_rc"] = r.returncode
    finally:
        run(["umount", MNT], check=False)
        run(["dmsetup", "remove", "--noudevsync", "lw"], check=False)
        for d in (data, logdev, replay):
            run(["losetup", "-d", d], check=False)
    ok = (not result["problems"] and result.get("replay_flush_rc") == 0 and
          result.get("replay_fua_rc") == 0 and result.get("replay_1_rc", 0) == 0 and
          result["checks"] > 0 and
          result.get("ntfsdefrag_rc", 0) == 0)
    result["ok"] = ok
    log(json.dumps(result))
    return result


def main():
    if not os.path.ismount("/mnt"):
        run(["mount", "-t", "tmpfs", "-o", "size=2600m", "tmpfs", "/mnt"])
    os.makedirs(TMP, exist_ok=True)
    out = {"cases": []}
    for cluster in CFG.get("clusters", [4096]):
        for wl in CFG.get("crash_workloads", ["moves", "defrag", "defrag-c", "eof"]):
            try:
                out["cases"].append(one_case(cluster, wl))
            except Exception:
                log(traceback.format_exc())
                out["cases"].append({"cluster": cluster, "workload": wl, "ok": False,
                                     "error": traceback.format_exc()[-800:]})
    dm = run(["dmesg"], check=False).stdout
    out["dmesg_bad"] = [l for l in dm.splitlines()
                        if any(k in l for k in ("BUG:", "WARNING:", "KASAN:", "UBSAN:", "possible circular",
                                                "inconsistent lock state", "INFO: task"))][:10]
    tests = len(out["cases"])
    failures = [(f"{c['workload']} c{c['cluster']}", json.dumps(c)[:1500]) for c in out["cases"] if not c["ok"]]
    if out["dmesg_bad"]:
        failures.append(("dmesg", "\n".join(out["dmesg_bad"])))
    json.dump({"tests": tests, "failures": failures, "errors": [], "skipped": [],
               "seconds": 0, "cases": out["cases"]}, open(os.path.join(WORK, "results.json"), "w"), indent=1)
    log(f"done: {tests} cases, {len(failures)} failures")


if __name__ == "__main__":
    main()
