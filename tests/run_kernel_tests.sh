#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run the fs/ntfs ioctl tests (test_ntfs_move.py) in QEMU on a self-built
# kernel (see vm/build_kernel.sh).
#
#   tests/run_kernel_tests.sh KERNEL_BUILD_DIR WORKDIR [ONLY_REGEX]
#
# Environment: SUITE (move: the ioctl tests, online: ntfsdefrag on a mounted
# volume, crash: dm-log-writes replay of online moves; needs REPLAY_LOG, the
# replay-log tool of xfstests: $XFSTESTS/src/log-writes/replay-log or replay-log in PATH), NTFSCK and NTFSDEFRAG (default: found in PATH),
# NTFSDEFRAG_FI (ntfsdefrag built with -DENABLE_FAULT_INJECTION, default: ntfsdefrag-fault-injection next to NTFSDEFRAG),
# CRASH_WORKLOADS (default "moves defrag defrag-c eof alist alist-defrag"), CRASH_SIZE_MB (48),
# CRASH_MOVES (40), CRASH_CHECK ("flush fua"), CRASH_JOBS (parallel checks, default: VM CPUs), CLUSTERS (default "512 4096 65536"), STRESS_SECONDS (default 60), MOVERS
# (mover threads in the stress test, default 3; 0 = control run without moves),
# OPS (stress operations: w=write m=mmap t=truncate p=punch v=verify, default wmtpv),
# WRITERS (writer threads, default 2), WRITER_FILES / MOVER_FILES (indexes
# of the stress files each side uses, e.g. "0 1 2" and "3 4 5"), REPLAY (trace files fail-*.json written by a
# failed stress run: replayed single-threaded by ReplayTests), REPLAY_MOVES (0/1),
# MEM / SMP / TIMEOUT (passed to run_vm.sh).
# Exit status 0 only if every test passed; details in WORKDIR/test.log.
# The move, online and crash suites need a kernel with the fs/ntfs online
# defragmentation series (NTFS_IOC_MOVE_CLUSTERS, FS_IOC_GETFSMAP).
#
# Example:
#   SUITE=move tests/run_kernel_tests.sh ../build-ntfs /var/tmp/move
set -euo pipefail
case "${1:-}" in -h|--help|"") sed -n '3,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0;; esac
here=$(cd "$(dirname "$0")" && pwd)
vm=$(cd "$here/../vm" && pwd)
build=$(realpath "$1"); work=$(realpath -m "$2"); only=${3:-.}
ntfsck=${NTFSCK:-$(command -v ntfsck)} || { echo "ntfsck not found: install ntfsprogs-plus or set NTFSCK" >&2; exit 2; }
ntfsdefrag=${NTFSDEFRAG:-$(command -v ntfsdefrag || echo /nonexistent/ntfsdefrag)}
ntfsdefrag_fi=${NTFSDEFRAG_FI:-$(dirname "$ntfsdefrag")/ntfsdefrag-fault-injection}
case ${SUITE:-move} in
	move) suite=$here/test_ntfs_move.py ;;
	online) suite=$here/test_online_defrag.py ;;
	crash) suite=$here/test_crash_logwrites.py ;;
	*) echo "SUITE must be move, online or crash" >&2; exit 2 ;;
esac
# the modules of this kernel; older releases may sit next to them
mods="$build/modroot/lib/modules/$(cat "$build/include/config/kernel.release")"
mkdir -p "$work"
# private copies: rebuilding the tools while the VM runs must not break it
mkdir -p "$work/bin"
cp "$ntfsck" "$work/bin/ntfsck" && ntfsck=$work/bin/ntfsck
if [ -x "$ntfsdefrag" ]; then cp "$ntfsdefrag" "$work/bin/ntfsdefrag" && ntfsdefrag=$work/bin/ntfsdefrag; fi
# the online suite looks for it next to ntfsdefrag
if [ -x "$ntfsdefrag_fi" ]; then
	cp "$ntfsdefrag_fi" "$work/bin/ntfsdefrag-fault-injection"
elif [ "${SUITE:-move}" = online ]; then
	echo "note: no $ntfsdefrag_fi (set NTFSDEFRAG_FI); the fault-injection tests will be skipped" >&2
fi
rm -f "$work/results.json" "$work/test.log"
replay_log=${REPLAY_LOG:-${XFSTESTS:+$XFSTESTS/src/log-writes/replay-log}}
replay_log=${replay_log:-$(command -v replay-log || echo /nonexistent/replay-log)}
python3 - "$work" "$ntfsck" "$here/ntfsdefrag.py" "$only" "$ntfsdefrag" "$replay_log" <<'PY'
import json, os, sys
work, ntfsck, proto, only, ntfsdefrag, replay_log = sys.argv[1:7]
clusters = [int(c) for c in os.environ.get("CLUSTERS", "512 4096 65536").split()]
json.dump({"ntfsck": ntfsck, "prototype": proto, "only": only, "clusters": clusters,
           "ntfsdefrag": ntfsdefrag, "replay_log": replay_log,
           "crash_workloads": os.environ.get("CRASH_WORKLOADS", "moves defrag defrag-c eof alist alist-defrag").split(),
           "crash_size_mb": int(os.environ.get("CRASH_SIZE_MB", "48")),
           "crash_moves": int(os.environ.get("CRASH_MOVES", "40")),
           "crash_check": os.environ.get("CRASH_CHECK", "flush fua").split(),
           "crash_jobs": int(os.environ.get("CRASH_JOBS", "0")),
           "stress_seconds": int(os.environ.get("STRESS_SECONDS", "60")),
           "movers": int(os.environ.get("MOVERS", "3")),
           "ops": os.environ.get("OPS", "wmtpv"),
           "writers": int(os.environ.get("WRITERS", "2")),
           "replay": [os.path.abspath(p) for p in os.environ.get("REPLAY", "").split()],
           "replay_moves": os.environ.get("REPLAY_MOVES", "1") == "1",
           "writer_files": [int(x) for x in os.environ.get("WRITER_FILES", "").split()],
           "mover_files": [int(x) for x in os.environ.get("MOVER_FILES", "").split()],
           "mover_mode": os.environ.get("MOVER_MODE", "move"),
           "fuzz_seed": int(os.environ.get("FUZZ_SEED", "1")),
           "fuzz_steps": int(os.environ.get("FUZZ_STEPS", "4000"))},
          open(os.path.join(work, "config.json"), "w"))
PY
KERNEL="$build/arch/x86/boot/bzImage" MODULES="$mods" SCRIPT="$suite" \
	MEM=${MEM:-4G} SMP=${SMP:-4} TIMEOUT=${TIMEOUT:-3600} \
	"$vm/run_vm.sh" "$work" || true
tail -n 30 "$work/test.log" 2>/dev/null || true
python3 - "$work/results.json" <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except FileNotFoundError:
    sys.exit("no results.json: the VM did not finish (see console.log)")
print(f"{r['tests']} tests, {len(r['failures'])} failures, {len(r['errors'])} errors, "
      f"{len(r['skipped'])} skipped, {r['seconds']} s")
sys.exit(1 if r["failures"] or r["errors"] else 0)
PY
