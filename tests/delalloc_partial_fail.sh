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
# Checked for each of $CLUSTERS:
#   - the file reads back as zeroes (or the data written), from the page
#     cache, after dropping it, and after a remount (correctness, FAIL)
#   - how many clusters stayed allocated (space, reported only)
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
for cs in $CLUSTERS; do
	rm -f $IMG; truncate -s 64M $IMG
	mkntfs -F -Q -q -c $cs $IMG >/dev/null 2>&1 || { fail "mkntfs c$cs"; continue; }
	mount -i -t ntfs -o loop $IMG $M || { fail "mount c$cs"; continue; }
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
	done
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
