#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Runs INSIDE the test VM: executes <work>/cmds.sh with bash, output to <work>/shell.log."""
import subprocess, sys, os
work = sys.argv[1]
with open(os.path.join(work, "shell.log"), "w") as log:
    subprocess.run(["/usr/bin/bash", "-x", os.path.join(work, "cmds.sh")], stdout=log,
                   stderr=subprocess.STDOUT, cwd=work)
