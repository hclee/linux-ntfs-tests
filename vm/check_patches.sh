#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Check every commit of a kernel patch series the way maintainers and the
# kernel test robot do, and report only what the series adds:
#
#   vm/check_patches.sh TREE BASE TIP DIR [DIR...]
#
# TREE is any checkout of the repository (it is not touched: the commits are
# checked out in a private worktree, $CHECK_WORK/tree). For BASE and then for
# each commit of BASE..TIP, the directories DIR (e.g. fs/ntfs) are compiled
# with W=1 by gcc and by clang (LLVM=1) and checked by sparse (C=2); the
# warnings of each commit are compared with those of the commit before it,
# so pre-existing warnings do not count. checkpatch --strict runs on each
# commit too (CamelCase notes on existing macros and the missing
# Signed-off-by are left out: the author adds Signed-off-by before sending).
#
# Needs a configured kernel .config with the DIRs enabled: $CHECK_CONFIG
# (required: e.g. the .config of a vm/build_kernel.sh build). sparse is taken
# from $SPARSE (default: sparse in PATH).
# Work dirs: $CHECK_WORK (default ./check-work).
# Output: one line per commit; details in $CHECK_WORK/<commit>.<tool>.new.
# Exit status 1 if any commit adds a warning or a checkpatch error/warning.
#
# Example:
#   CHECK_CONFIG=../build-ntfs/.config vm/check_patches.sh ../linux ntfs-next my-series fs/ntfs
set -euo pipefail
case "${1:-}" in -h|--help|"") sed -n '3,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0;; esac
tree=$(realpath "$1"); base=$2; tip=$3; shift 3; dirs=("$@")
work=$(realpath -m "${CHECK_WORK:-check-work}")
config=${CHECK_CONFIG:?set CHECK_CONFIG to a kernel .config}
sparse=${SPARSE:-$(command -v sparse || echo sparse)}
jobs=${JOBS:-$(nproc)}
mkdir -p "$work"
wt=$work/tree
if [ ! -d "$wt" ]; then git -C "$tree" worktree add -q --detach "$wt" "$base"; fi
for o in gcc clang; do
	mkdir -p "$work/$o"
	[ -f "$config" ] || { echo "no kernel config: $config" >&2; exit 2; }
	[ -f "$work/$o/.config" ] || cp "$config" "$work/$o/.config"
done
llvm=(LLVM=1)

# warnings of one tool for the checked-out commit, normalised (no line
# numbers) so that moved code does not count as new
build() {	# tool -> stdout: sorted warning lines
	local tool=$1 d
	case $tool in
	gcc)	for d in "${dirs[@]}"; do touch_dir "$d"; done
		make -s -C "$wt" O="$work/gcc" -j"$jobs" W=1 "${dirs[@]/%//}" 2>&1 >/dev/null || true;;
	clang)	for d in "${dirs[@]}"; do touch_dir "$d"; done
		make -s -C "$wt" O="$work/clang" -j"$jobs" "${llvm[@]}" W=1 "${dirs[@]/%//}" 2>&1 >/dev/null || true;;
	sparse)	make -s -C "$wt" O="$work/gcc" -j"$jobs" C=2 CHECK="$sparse" "${dirs[@]/%//}" 2>&1 >/dev/null || true;;
	esac | grep -E 'warning:|error:' | grep -E "($(IFS='|'; echo "${dirs[*]}"))/" |
		sed -E 's/:[0-9]+:[0-9]+:/:/; s/:[0-9]+:/:/' | sort || true
}
touch_dir() { find "$wt/$1" -name '*.c' -exec touch {} +; }

for o in gcc clang; do	# configs for the base tree
	if [ $o = clang ]; then make -s -C "$wt" O="$work/$o" "${llvm[@]}" olddefconfig >/dev/null
	else make -s -C "$wt" O="$work/$o" olddefconfig >/dev/null; fi
done
git -C "$wt" checkout -q --detach "$base"
for t in gcc clang sparse; do build $t > "$work/base.$t"; done
for o in gcc clang; do	# a build that compiled nothing would look clean
	ls "$work/$o/${dirs[0]}"/*.o >/dev/null 2>&1 || { echo "$o: nothing compiled in ${dirs[0]}" >&2; exit 2; }
done
prev=base
fail=0
for c in $(git -C "$tree" rev-list --reverse "$base..$tip"); do
	git -C "$wt" checkout -q --detach "$c"
	h=$(git -C "$wt" log -1 --format=%h)
	line="$h"
	for t in gcc clang sparse; do
		build $t > "$work/$h.$t"
		comm -13 "$work/$prev.$t" "$work/$h.$t" > "$work/$h.$t.new"
		n=$(grep -c . "$work/$h.$t.new" || true)
		line="$line $t+$n"
		[ "$n" = 0 ] || fail=1
	done
	# from inside the tree: checkpatch looks up cited commit ids with git
	git -C "$wt" format-patch -1 --stdout "$c" | (cd "$wt" && ./scripts/checkpatch.pl --strict --terse --no-summary - 2>/dev/null) |
		grep -v -e 'Avoid CamelCase' -e 'Missing Signed-off-by' -e 'does MAINTAINERS need updating' > "$work/$h.checkpatch.new" || true
	n=$(grep -c . "$work/$h.checkpatch.new" || true)
	[ "$n" = 0 ] || { grep -qE 'ERROR|WARNING' "$work/$h.checkpatch.new" && fail=1; }
	echo "$line checkpatch:$n  $(git -C "$wt" log -1 --format=%s | cut -c1-70)"
	prev=$h
done
exit $fail
