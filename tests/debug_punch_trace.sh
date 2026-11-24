# SPDX-License-Identifier: GPL-2.0-or-later
# Debug only (branch delalloc-v2-debug, never merged): trace the ranges ntfs
# punches after a short or failed copy into a cached hole, at 1 KiB and 2 KiB
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
probe 'p:seek mapping_seek_hole_data start=%si:s64 end=%dx:s64 whence=%cx:s32'
probe 'r:seekret mapping_seek_hole_data ret=$retval:s64'
probe 'p:wbpages ntfs_writepages'
probe 'p:zero ntfs_zero_range_unkillable pos=%si:s64 len=%dx:s64'
echo 1 > $T/events/kprobes/enable 2>/dev/null
shortcopy() {	# shortcopy FILE OFFSET LENGTH VALID: pwrite() whose source faults after VALID bytes
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
off, n, valid = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
buf = libc.mmap(None, 2 * pg, mmap.PROT_READ | mmap.PROT_WRITE,
                mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
libc.munmap(buf + pg, pg)
src = buf + pg - valid
ctypes.memset(src, 0xab, valid)
fd = os.open(sys.argv[1], os.O_RDWR)
r = libc.pwrite(fd, src, n, off)
print("pwrite:", r, os.strerror(ctypes.get_errno()) if r < 0 else "")
PY
}
used() { echo "$1: $((free0 - $(stat -f -c %f $M))) clusters used"; }
IMG=/mnt/trace.img
# Every case writes into a hole of a file whose initialized size is its
# size: a write that ends above the initialized size drops the page cache
# first (__ntfs_extend_initialized_size()), so no clean folio survives it.
#   short512     read 32K, then a copy that faults after 512 bytes
#   shortcs      read 32K, then a copy that faults after one cluster
#   shortcs-nr   the same without the read (control)
#   dirty        read 32K, write the last cluster of page 0, then a write
#                of the clusters before it that faults on its first byte
#   dirty-nr     the same without the read (control)
for cs in 1024 2048; do
	for c in short512 shortcs shortcs-nr dirty dirty-nr; do
		rm -f $IMG; truncate -s 64M $IMG
		mkntfs -F -Q -q -c $cs $IMG >/dev/null 2>&1
		mount -i -t ntfs -o loop $IMG $M || { fail "mount"; continue; }
		f=$M/short
		xfs_io -f -c "truncate $((64 * 4096))" -c "pwrite -q $((64 * 4096 - 512)) 512" -c fsync $f
		sync
		free0=$(stat -f -c %f $M)
		echo "### c$cs $c"
		case $c in *-nr) ;; *) xfs_io -c "pread -q 0 32768" $f ;; esac
		case $c in dirty*)
			xfs_io -c "pwrite -q -S 0xcd $((4096 - cs)) $cs" $f
			used "after the write of the last cluster of page 0" ;;
		esac
		echo > $T/trace
		case $c in
		short512)	shortcopy $f 0 32768 512 ;;
		shortcs*)	shortcopy $f 0 32768 $cs ;;
		dirty*)		shortcopy $f 0 $((4096 - cs)) 0 ;;
		esac
		used "after the faulting write"
		grep -v '^#' $T/trace | sed 's/^.*: //'
		xfs_io -c "fiemap -v" $f | sed -n '2,8p'
		sync
		used "after sync"
		xfs_io -c "fiemap -v" $f | sed -n '2,8p'
		sync; echo 3 > /proc/sys/vm/drop_caches
		used "after sync and drop_caches"
		umount $M
		mount -i -t ntfs -o loop $IMG $M || { fail "remount"; continue; }
		used "after remount"
		umount $M
	done
done
echo 0 > $T/events/kprobes/enable 2>/dev/null; : > $T/kprobe_events 2>/dev/null
echo "PASS: trace done"
dmesg_check
echo "### done"
