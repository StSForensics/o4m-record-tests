#!/usr/bin/env python3
# Copyright 2026 Gareth Wong
# SPDX-License-Identifier: Apache-2.0
#
# Checks the exit-3 paths of verify.py. These paths give no verdict, so they cannot be test vectors
# (a vector pins a verdict text). Run from the package root:
#   python check_exit_codes.py
# Exit code 0 if every case behaves as stated, otherwise 1. Prints one line per case.
#
# Not covered: an internal error that cannot be triggered from outside (verify.py catches every
# exception and exits 3). That path is reviewed by reading, not run.

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(ROOT, "verify.py")
GOOD = os.path.join(ROOT, "vectors", "T3", "t3-001", "input.json")

# (name, arguments, expected exit code, must stdout hold a verdict line)
CASES = [
    ("control: valid input gives PASS", ["T3", GOOD], 0, True),
    ("missing file", ["T3", os.path.join(ROOT, "no-such-file.json")], 3, False),
    ("a folder instead of a file", ["T3", ROOT], 3, False),
    ("no arguments", [], 3, False),
    ("unknown test name", ["T9", GOOD], 3, False),
    ("alternative reading given for T3", ["T3", GOOD, "--reading", "B"], 3, False),
    ("unknown reading letter", ["T14a", GOOD, "--reading", "Z"], 3, False),
]


def main():
    bad = 0
    for name, args, want, verdict in CASES:
        p = subprocess.run([sys.executable, "-I", VERIFY] + args, capture_output=True)
        out = p.stdout.decode("utf-8", "replace")
        has_verdict = any(l.startswith("Result: ") for l in out.splitlines())
        ok = p.returncode == want and has_verdict == verdict
        if not ok:
            bad += 1
        print("%s | %s | exit %d (want %d), verdict line %s (want %s)"
              % ("OK  " if ok else "FAIL", name, p.returncode, want,
                 "present" if has_verdict else "absent", "present" if verdict else "absent"))
    print("%d cases, %d failed" % (len(CASES), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
