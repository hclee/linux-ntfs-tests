# SPDX-License-Identifier: GPL-2.0-or-later
# Guest script (run with run_guest_script.sh): fstests with FSTYP=ntfs on
# the kernel driver, by default the tests of fstests/patches (generic/816,
# 817 and 818), in one section per cluster size (512, 4096 and 65536), then
# a dmesg check. Prints one PASS or FAIL line per test and section; a test
# that fstests did not run ("not run") is a FAIL too.
# Environment: FSTESTS (an xfstests tree built with fstests/patches
# applied), FSTESTS_TESTS (the tests to run, default "generic/816
# generic/817 generic/818"), FSTESTS_SECTIONS (section:cluster-size pairs),
# and FSTESTS_ALLOW_NOTRUN (1 to report unsupported tests as SKIP).
# The directory of NTFSCK (ntfsprogs-plus's sbin)
# goes first in PATH: fstests runs mkfs.ntfs and fsck.ntfs from PATH, and
# ntfs-3g's mkfs.ntfs must not take over.
# Results: $W/fstests-results/<section>/ (check.log, result.xml and
# <test>.full and <test>.out.bad of every test).
. "$HARNESS/guest_lib.sh"
TESTS=${FSTESTS_TESTS:-generic/816 generic/817 generic/818}
SECTIONS=${FSTESTS_SECTIONS:-"ntfs_512:512 ntfs_4k:4096 ntfs_64k:65536"}
if ! [ -x "${FSTESTS:-}/check" ]; then
	fail "no fstests tree at '${FSTESTS:-}' (build xfstests with fstests/patches and set FSTESTS)"
	echo "### done"
	exit 0
fi
sbin=$(dirname "$(command -v "$NTFSCK")")
export PATH=$sbin:$PATH
for p in mkfs.ntfs fsck.ntfs; do
	case $(command -v $p) in
	$sbin/*) echo "$p: $(command -v $p)" ;;
	*) fail "$p is '$(command -v $p)', not the one in $sbin" ;;
	esac
done
# The host's udev socket cannot handle device events from this VM.
if ! mount -t tmpfs -o mode=0755 tmpfs /run ||
   ! timeout 10 /usr/lib/systemd/systemd-udevd --daemon ||
   ! udevadm control --timeout=10 --ping; then
	fail "could not start guest udev"
	echo "### done"
	exit 0
fi
if ! ip link set lo up; then
	fail "could not enable guest loopback"
	echo "### done"
	exit 0
fi
mountpoint -q /mnt || mount -t tmpfs -o size=2500m tmpfs /mnt
# check and the tests keep their temporary files in /tmp, which is the
# host's, read-only (TMPDIR does not reach the guest scripts)
mountpoint -q /tmp || mount -t tmpfs -o size=256m tmpfs /tmp
if ! [ -d /dev/fd ]; then
	ln -s /proc/self/fd /dev/fd || {
		fail "could not create /dev/fd"
		echo "### done"
		exit 0
	}
fi
# Some fstests invoke mount directly, without the configured -i option.
mount_prog=$(command -v mount)
mkdir -p /tmp/fstests-bin
printf '#!/bin/sh\nexec "%s" -i "$@"\n' "$mount_prog" > /tmp/fstests-bin/mount
chmod +x /tmp/fstests-bin/mount
export PATH=/tmp/fstests-bin:$PATH
# check and the tests write next to the tree; the host's root is read-only
mkdir -p /mnt/xfstests
tar -C "$FSTESTS" --exclude=.git -cf - . | tar -C /mnt/xfstests -xf -
if [ "${FSTESTS_VIRTIO_DISKS:-0}" = 1 ]; then
	tdev=/dev/vda
	sdev=/dev/vdb
	if ! [ -b "$tdev" ] || ! [ -b "$sdev" ]; then
		fail "fstests virtio disks are missing"
		echo "### done"
		exit 0
	fi
	echo "fstests disk sizes: $(blockdev --getsize64 "$tdev") $(blockdev --getsize64 "$sdev")"
else
	# generic/816 fills a 512 MiB volume.
	truncate -s 512M /mnt/test.img
	truncate -s 1G /mnt/scratch.img
	tdev=$(losetup -f --show /mnt/test.img)
	sdev=$(losetup -f --show /mnt/scratch.img)
fi
mkdir -p /mnt/fstests/test /mnt/fstests/scratch
mkfs.ntfs -Q -F -q "$tdev" > /dev/null
# every section sets every option: check carries options over from the
# section before only in some cases
for s in $SECTIONS; do
	cat <<EOF
[${s%%:*}]
FSTYP=ntfs
TEST_DEV=$tdev
TEST_DIR=/mnt/fstests/test
SCRATCH_DEV=$sdev
SCRATCH_MNT=/mnt/fstests/scratch
MOUNT_OPTIONS="-i"
TEST_FS_MOUNT_OPTS="-i"
MKFS_OPTIONS="-c ${s#*:}"
RECREATE_TEST_DEV=true
RESULT_BASE=$W/fstests-results

EOF
done > /mnt/xfstests/local.config
cat /mnt/xfstests/local.config
mark "fstests $TESTS"
(cd /mnt/xfstests && ./check -R xunit $TESTS) > $W/check.out 2>&1
echo "check exit status $?"
cat $W/check.out
# one line per test and section, from the xunit report of each section
for s in $SECTIONS; do
	s=${s%%:*}
	python3 - "$W/fstests-results/$s/result.xml" "$s" "${FSTESTS_ALLOW_NOTRUN:-0}" $TESTS <<'EOF'
import sys
import xml.etree.ElementTree as ET
path, section, allow_notrun, tests = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4:]
try:
    cases = {c.get("name"): c for c in ET.parse(path).getroot().iter("testcase")}
except (OSError, ET.ParseError) as e:
    cases = {}
    print(f"FAIL: fstests {section}: no report ({e})")
skipped = 0
for t in tests:
    c = cases.get(t)
    if c is None:
        print(f"FAIL: {t} {section}: did not run")
    elif c.find("skipped") is not None:
        skipped += 1
        status = "SKIP" if allow_notrun else "FAIL"
        print(f"{status}: {t} {section}: not run: {c.find('skipped').get('message', '')}")
    elif c.find("failure") is not None or c.find("error") is not None:
        e = c.find("failure") if c.find("failure") is not None else c.find("error")
        print(f"FAIL: {t} {section}: {e.get('message', '')}")
    else:
        print(f"PASS: {t} {section}")
if allow_notrun and skipped == len(tests):
    print(f"FAIL: fstests {section}: all tests were skipped")
EOF
	for f in "$W"/fstests-results/$s/generic/*.out.bad; do
		[ -f "$f" ] || continue
		t=${f##*/}; t=${t%.out.bad}
		echo "--- $s generic/$t: diff of the expected output"
		diff -u /mnt/xfstests/tests/generic/$t.out "$f" | head -30
	done
done
[ "${FSTESTS_VIRTIO_DISKS:-0}" = 1 ] || losetup -d "$tdev" "$sdev"
dmesg_check
echo "### done"
