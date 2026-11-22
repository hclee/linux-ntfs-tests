#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compare the summary of tests/run_reproducers.sh with a file of expected
results and exit 1 when any test changed: an unexpected failure (a
regression) or an unexpected pass (a fix landed; update the expected file).
A test missing from the summary counts as changed too.

    compare_results.py EXPECTED SUMMARY

EXPECTED has lines "name pass|fail" (# starts a comment); SUMMARY is the
output of run_reproducers.sh ("name pass N fail M [first FAIL line]").
Example: compare_results.py tests/expected/ntfs-next.txt /var/tmp/repro.txt
"""
import sys

if len(sys.argv) != 3 or sys.argv[1] in ("-h", "--help"):
    print(__doc__.strip())
    sys.exit(0 if len(sys.argv) == 2 else 2)
expected = {}
for line in open(sys.argv[1]):
    line = line.split("#", 1)[0].split()
    if line:
        expected[line[0]] = line[1]
got = {}
for line in open(sys.argv[2]):
    f = line.split()
    if len(f) >= 5 and f[1] == "pass" and f[3] == "fail":
        got[f[0]] = "fail" if int(f[4]) or "did not finish" in line else "pass"
changed = 0
for name, want in sorted(expected.items()):
    have = got.get(name, "missing")
    if have != want:
        changed += 1
        kind = "unexpected failure" if have == "fail" else (
            "unexpected pass" if have == "pass" else "did not run")
        print(f"{name}: expected {want}, got {have} ({kind})")
for name in sorted(set(got) - set(expected)):
    print(f"{name}: {got[name]} (not in {sys.argv[1]})")
print(f"{len(expected) - changed} of {len(expected)} as expected")
sys.exit(1 if changed else 0)
