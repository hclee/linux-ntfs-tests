# SPDX-License-Identifier: GPL-2.0-or-later
# Debug only (branch delalloc-v2-debug, never merged): trace the ranges ntfs
# punches after a 512 byte short copy into a cached hole, at 1 KiB and 2 KiB
# clusters, with kprobes on ntfs_write_delalloc_punch() and
# ntfs_attr_punch_delalloc(), and print the free cluster count right after
# the write and after sync.
. "$HARNESS/guest_lib.sh"
mountpoint -q /mnt || mount -t tmpfs -o size=1g tmpfs /mnt
T=/sys/kernel/tracing
mountpoint -q $T || mount -t tracefs nodev $T || echo "no tracefs"
probe() { echo "$1" >> $T/kprobe_events && echo "probe ok: $1" || echo "probe FAILED: $1"; }
: > $T/kprobe_events 2>/dev/null || echo "no kprobe_events"
probe 'p:ntpunch ntfs_write_delalloc_punch off=%si:s64 len=%dx:s64'
probe 'p:ntpunchrl ntfs_attr_punch_delalloc vcn=%si:s64 cnt=%dx:s64'
probe 'p:ntrelease iomap_write_delalloc_release start=%si:s64 end=%dx:s64'
probe 'p:scan iomap_write_delalloc_scan start=%dx:s64 end=%cx:s64'
probe 'p:dpunch iomap_write_delalloc_punch start=%cx:s64 end=%r8:s64'
probe 'p:ifspunch iomap_write_delalloc_ifs_punch start=%dx:s64 end=%cx:s64'
probe 'p:seek mapping_seek_hole_data start=%si:s64 end=%dx:s64 whence=%cx:s32'
probe 'r:seekret mapping_seek_hole_data ret=$retval:s64'
probe 'p:tail ntfs_dirty_cluster_tail start=%si:s64 end=%dx:s64'
probe 'p:wbpages ntfs_writepages'
probe 'p:zero ntfs_zero_range_unkillable pos=%si:s64 len=%dx:s64'
echo 1 > $T/events/kprobes/enable 2>/dev/null
shortcopy() {
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
if len(sys.argv) > 5:	# fault on the first byte
    src = buf + pg
if sys.argv[4] == "read":
    os.pread(fd, n, off)
r = libc.pwrite(fd, src, n, off)
print("pwrite:", r)
PY
}
IMG=/mnt/trace.img
for cs in 1024 2048; do
	for pre in read noread efault; do
		rm -f $IMG; truncate -s 64M $IMG
		mkntfs -F -Q -q -c $cs $IMG >/dev/null 2>&1
		mount -i -t ntfs -o loop $IMG $M || { fail "mount"; continue; }
		f=$M/short
		xfs_io -f -c "truncate $((64 * 4096))" -c fsync $f; sync
		free0=$(stat -f -c %f $M)
		echo > $T/trace
		echo "### c$cs $pre"
		if [ $pre = efault ]; then
			shortcopy $f $((8 * 4096 + 512)) 32768 noread efault
		else
			shortcopy $f 0 32768 $pre
		fi
		echo "free after write: $((free0 - $(stat -f -c %f $M))) clusters used"
		grep -v '^#' $T/trace | sed 's/^.*: //'
		xfs_io -c "fiemap -v" $f | sed -n '2,8p'
		sync
		echo "free after sync: $((free0 - $(stat -f -c %f $M))) clusters used"
		xfs_io -c "fiemap -v" $f | sed -n '2,8p'
		umount $M
	done
done
echo 0 > $T/events/kprobes/enable 2>/dev/null; : > $T/kprobe_events 2>/dev/null
echo "PASS: trace done"
dmesg_check
echo "### done"
