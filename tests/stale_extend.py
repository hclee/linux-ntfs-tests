#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Stale data after extending a file past its initialized size (fs/ntfs).

Runs in the test VM as root:  python3 stale_extend.py WORKDIR [cluster...]

Free clusters are first filled with a marker (a file written and deleted),
then a file is extended in ways that allocate new clusters past its
initialized size: a write past EOF, truncate up then write, truncate up then
mmap write, fallocate then write. Everything between the old end and the
new data must read back as zeros, from the page cache and after dropping it.
Prints one line per case and exits non-zero on stale data.
"""
import mmap, os, subprocess, sys

MARK = b"\xa5"
work = sys.argv[1]
clusters = [int(c) for c in sys.argv[2:]] or [512, 4096, 65536]


def sh(*cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def drop():
    os.sync()
    open("/proc/sys/vm/drop_caches", "w").write("3\n")


def check(path, start, end, what, results):
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(end - start)
    bad = [i for i, b in enumerate(data) if b != 0]
    results.append((what, len(bad)))
    if bad:
        print(f"  STALE {what}: {len(bad)} bytes, first at {start + bad[0]}: {data[bad[0]:bad[0] + 8].hex()}")


def case(cs, mnt, name, how, results):
    path = f"{mnt}/{name}"
    with open(path, "wb") as f:
        f.write(b"x" * 100)
        f.flush()
        os.fsync(f.fileno())
    far = 3 * cs + 1000
    fd = os.open(path, os.O_RDWR)
    if how == "write":
        os.pwrite(fd, b"y" * 100, far)
    elif how == "truncate":
        os.ftruncate(fd, far + 4 * cs)
        os.pwrite(fd, b"y" * 100, far)
    elif how == "mmap":
        os.ftruncate(fd, far + 4 * cs)
        mm = mmap.mmap(fd, far + 4 * cs)
        mm[far:far + 100] = b"y" * 100
        mm.close()
    elif how == "fallocate":
        os.posix_fallocate(fd, 0, far + 4 * cs)
        os.pwrite(fd, b"y" * 100, far)
    os.close(fd)
    check(path, 100, far, f"c{cs} {how} (cached)", results)
    drop()
    check(path, 100, far, f"c{cs} {how} (from disk)", results)


def main():
    if not os.path.ismount("/mnt"):      # /mnt exists on the read-only host root
        sh("mount", "-t", "tmpfs", "-o", "size=600m", "tmpfs", "/mnt")
    os.makedirs("/mnt/st", exist_ok=True)
    results = []
    for cs in clusters:
        img = f"/mnt/st/v{cs}.img"
        with open(img, "wb") as f:
            f.truncate(64 << 20)
        sh("mkntfs", "-q", "-F", "-Q", "-c", str(cs), img)
        loop = subprocess.run(["losetup", "-f", "--show", img], capture_output=True, text=True, check=True).stdout.strip()
        mnt = f"/mnt/st/m{cs}"
        os.makedirs(mnt, exist_ok=True)
        sh("mount", "-i", "-t", "ntfs", loop, mnt)
        # put the marker into every free cluster, then free them again
        with open(f"{mnt}/marker", "wb") as f:
            try:
                while True:
                    f.write(MARK * (1 << 20))
            except OSError:
                pass
        os.sync()
        os.unlink(f"{mnt}/marker")
        os.sync()
        for n, how in enumerate(("write", "truncate", "mmap", "fallocate")):
            case(cs, mnt, f"f{n}", how, results)
        sh("umount", mnt)
        sh("losetup", "-d", loop)
    for what, bad in results:
        print(f"{'FAIL' if bad else 'ok  '} {what}")
    open(os.path.join(work, "stale.out"), "w").write("\n".join(f"{w} {b}" for w, b in results))
    sys.exit(1 if any(b for _w, b in results) else 0)


main()
