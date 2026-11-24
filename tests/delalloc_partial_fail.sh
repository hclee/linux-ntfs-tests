# SPDX-License-Identifier: GPL-2.0-or-later
# Guest script (run with run_guest_script.sh): what a failed buffered write
# into a hole at an offset that is not cluster aligned leaves allocated.
#
# ->iomap_begin() zeroes the parts of the first and last new cluster that the
# write does not cover, in the page cache, before anything is copied.  When
# the copy then fails (EFAULT here), the delalloc release keeps every cluster
# with a dirty folio, so those zeroed edge clusters stay delalloc and
# writeback allocates them: a sparse file gets up to two clusters of zeroes
# where it had holes.  Writeback also converts a whole delalloc run when it
# writes back part of it (sync_file_range() of the first page here).
# A short copy into a hole whose folio is in the page cache leaves that folio
# with dirty blocks followed by clean ones.  iomap releases the clean blocks
# of a dirty folio one block (512 bytes) at a time, and a delalloc
# reservation is a whole cluster, so with 1 KiB and 2 KiB clusters the
# clusters of that folio that the write did not reach stay reserved unless
# they are released as one range.  The volume first holds a deleted file of
# 0xee, so that a cluster allocated without being written shows old data.
# Checked for each of $CLUSTERS plus 1024 and 2048:
#   - the file reads back as zeroes (or the data written), from the page
#     cache, after dropping it, and after a remount (correctness, FAIL)
#   - at most the two zeroed edge clusters stay allocated (FAIL)
#   - a short copy of 512 bytes into a cached hole allocates one cluster
#     (FAIL)
#   - ntfsck -n is clean.
. "$HARNESS/guest_lib.sh"
mountpoint -q /mnt || mount -t tmpfs -o size=1g tmpfs /mnt
IMG=/mnt/partial-fail.img
efault() {	# efault FILE OFFSET LENGTH: pwrite() from an unmapped buffer
	python3 - "$@" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.pwrite.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long]
fd = os.open(sys.argv[1], os.O_WRONLY)
r = libc.pwrite(fd, 4096, int(sys.argv[3]), int(sys.argv[2]))
print("pwrite from a bad buffer:", r, os.strerror(ctypes.get_errno()))
PY
}
shortcopy() {	# shortcopy FILE OFFSET LENGTH: pwrite() whose source faults after 512 bytes
	python3 - "$@" <<'PY'
import ctypes, mmap, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.pwrite.restype = ctypes.c_ssize_t
libc.pwrite.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long]
pg = mmap.PAGESIZE
buf = libc.mmap(None, 2 * pg, mmap.PROT_READ | mmap.PROT_WRITE,
                mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
libc.munmap(buf + pg, pg)
src = buf + pg - 512
ctypes.memset(src, 0xab, 512)
off, n = int(sys.argv[2]), int(sys.argv[3])
fd = os.open(sys.argv[1], os.O_RDWR)
os.pread(fd, n, off)	# the hole's folios become uptodate, so a short copy counts
r = libc.pwrite(fd, src, n, off)
print("pwrite whose source faults after 512 bytes:", r)
sys.exit(r != 512)
PY
}
zeroes() {	# zeroes FILE SIZE [OFF LEN BYTE]: contents check
	python3 - "$@" <<'PY'
import sys
d = open(sys.argv[1], "rb").read()
exp = bytearray(int(sys.argv[2]))
if len(sys.argv) > 3:
    o, n, b = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5], 0)
    exp[o:o + n] = bytes([b]) * n
if bytes(exp) != d:
    i = next((i for i in range(min(len(d), len(exp))) if d[i] != exp[i]), -1)
    sys.exit("differs at %d (size %d)" % (i, len(d)))
PY
}
for cs in $(printf '%s\n' $CLUSTERS 1024 2048 | sort -nu); do
	rm -f $IMG; truncate -s 64M $IMG
	mkntfs -F -Q -q -c $cs $IMG >/dev/null 2>&1 || { fail "mkntfs c$cs"; continue; }
	mount -i -t ntfs -o loop $IMG $M || { fail "mount c$cs"; continue; }
	python3 -c "import sys; sys.stdout.buffer.write(b'\xee' * (16 << 20))" > $M/old
	sync; rm $M/old; sync
	unit=$((cs > 4096 ? cs : 4096))
	size=$((64 * unit))
	for init in 0 full; do
		tag="failed unaligned write init=$init c$cs"; mark "$tag"
		f=$M/f-$init
		xfs_io -f -c "truncate $size" $f
		[ $init = full ] && xfs_io -c "pwrite -q $((size - 512)) 512" $f
		xfs_io -c fsync $f; sync
		free0=$(stat -f -c %f $M)
		efault $f $((8 * unit + 512)) $((8 * unit))
		sync
		free1=$(stat -f -c %f $M)
		exp=""; [ $init = full ] && exp="$((size - 512)) 512 0xcd"
		zeroes $f $size $exp && echo "PASS: $tag contents (cache)" || fail "$tag contents (cache)"
		echo 3 > /proc/sys/vm/drop_caches
		zeroes $f $size $exp && echo "PASS: $tag contents (disk)" || fail "$tag contents (disk)"
		echo "$tag: $((free0 - free1)) clusters allocated by the failed write"
		[ $((free0 - free1)) -le 2 ] &&
			echo "PASS: $tag allocates at most the zeroed edge clusters" ||
			fail "$tag: $((free0 - free1)) clusters allocated, at most 2 expected"
	done
	tag="short copy into a cached hole c$cs"; mark "$tag"
	f=$M/short
	xfs_io -f -c "truncate $size" $f -c fsync; sync
	free0=$(stat -f -c %f $M)
	shortcopy $f 0 $((8 * unit)) || fail "$tag: the write was not 512 bytes"
	sync
	free1=$(stat -f -c %f $M)
	zeroes $f $size 0 512 0xab && echo "PASS: $tag contents (cache)" || fail "$tag contents (cache)"
	echo 3 > /proc/sys/vm/drop_caches
	zeroes $f $size 0 512 0xab && echo "PASS: $tag contents (disk)" || fail "$tag contents (disk)"
	echo "$tag: $((free0 - free1)) clusters allocated by the short write"
	[ $((free0 - free1)) -le 1 ] &&
		echo "PASS: $tag allocates only the cluster written" ||
		fail "$tag: $((free0 - free1)) clusters allocated, 1 expected"
	tag="partial writeback c$cs"; mark "$tag"
	f=$M/run
	xfs_io -f -c "pwrite -q -S 0x42 0 $((16 * unit))" $f
	b0=$(stat -c %b $f)
	xfs_io -c "sync_range -b -w -a 0 4096" $f
	echo "$tag: st_blocks $b0 -> $(stat -c %b $f); extents after writeback of the first page:"
	xfs_io -c "fiemap -v" $f | sed -n '3,6p'
	umount $M
	mount -i -t ntfs -o loop $IMG $M || { fail "remount c$cs"; continue; }
	zeroes $M/f-0 $size && zeroes $M/f-full $size $((size - 512)) 512 0xcd &&
		echo "PASS: contents after remount c$cs" || fail "contents after remount c$cs"
	python3 -c "import sys; d=open(sys.argv[1],'rb').read(); sys.exit(d != b'\x42'*len(d))" $f &&
		echo "PASS: $tag contents" || fail "$tag contents"
	umount $M
	run_ntfsck $IMG "partial-c$cs"
done
rm -f $IMG
dmesg_check
echo "### done"
