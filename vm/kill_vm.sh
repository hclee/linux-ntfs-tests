#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Stop the test VM(s) started with run_vm.sh for WORKDIR:
#
#   vm/kill_vm.sh WORKDIR
#
# Only qemu-system-x86_64 processes whose command line names WORKDIR are
# signalled (pkill -f would also match the shell that runs this).
#
# Example:
#   vm/kill_vm.sh /var/tmp/repro/short_write_size
set -euo pipefail
case "${1:-}" in -h|--help|"") sed -n '3,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0;; esac
work=$(realpath -m "$1")
found=0
for pid in $(pgrep -x qemu-system-x86 || true); do
	if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "ntfsvm.work=$work "; then
		kill "$pid" && found=1 && echo "stopped $pid"
	fi
done
[ "$found" = 1 ] || echo "no VM for $work"
