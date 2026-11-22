#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run driver reproducers (guest scripts for run_guest_script.sh) one after
# another on one kernel and print one line per script: PASS/FAIL counts and
# the first FAIL line.
#
#   tests/run_reproducers.sh KERNEL_BUILD_DIR WORKDIR [SCRIPT...]
#
# SCRIPT defaults to every fs/ntfs reproducer in this directory (not the
# ntfs3_* ones, which need a kernel with the fs/ntfs3 series, and not the
# measurement scripts). Each run gets WORKDIR/<script name>/ (shell.log,
# console.log). The C helpers are built first (make -C tests).
# Environment: CLUSTERS, MEM, SMP and TIMEOUT pass through to the VM.
# Exit status 1 if any script reported a FAIL or did not finish.
#
# Example:
#   tests/run_reproducers.sh ../build-ntfs /var/tmp/repro short_copy_stale.sh
set -uo pipefail
case "${1:-}" in -h|--help|"") sed -n '3,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0;; esac
here=$(cd "$(dirname "$0")" && pwd)
build=$1; work=$(realpath -m "$2"); shift 2
if [ $# = 0 ]; then
	set -- $(cd "$here" && ls delalloc_*.sh hole_fill_stale.sh short_copy_stale.sh \
		short_write_size.sh stale_wb_race.sh slab_cache_names.sh sparse_cu_*.sh \
		ntfs_compressed_*.sh fsx_parallel.sh killed_short_write.sh killed_write_mmap.sh \
		keep_size_short_write.sh 2>/dev/null)
fi
mkdir -p "$work"
make -s -C "$here" || exit 2	# the C helpers
fail=0
for s in "$@"; do
	name=${s%.sh}; name=${name##*/}
	script=$here/${s##*/}
	"$here/run_guest_script.sh" "$build" "$work/$name" "$script" > "$work/$name.log" 2>&1
	log=$work/$name/shell.log
	p=$(grep -c '^PASS' "$log" 2>/dev/null); f=$(grep -c '^FAIL' "$log" 2>/dev/null)
	done_=$(grep -c '^### done' "$log" 2>/dev/null)
	first=$(grep -m1 '^FAIL' "$log" 2>/dev/null)
	[ "${f:-0}" = 0 ] && [ "${done_:-0}" -gt 0 ] || fail=1
	[ "${done_:-0}" -gt 0 ] || first="did not finish (see $work/$name.log)"
	printf '%-32s pass %3s fail %3s %s\n' "$name" "${p:-0}" "${f:-0}" "$first"
done
exit $fail
