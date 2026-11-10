#!/usr/bin/env python3
# Copyright 2026 Gareth Wong
# SPDX-License-Identifier: Apache-2.0
#
# Mutation-kill harness for verify.py. Each mutant is one exact text substitution in a copy of
# verify.py. Every vector (including alternative readings) is run against the mutant; a vector
# kills the mutant if its stdout or exit code differs from expected.txt or expected_exit.txt.
# expected.txt files are never edited here.
#
#   python mutation/mutate.py            (run from the package root)
# Writes mutation/MUTATION_RECORD.txt. Exit code 0 if the unmutated verifier matches every
# vector, otherwise 1.

import datetime
import hashlib
import os
import platform
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (id, description, old text, new text). old text must occur exactly once in verify.py.
MUTANTS = [
    ("M-T3-01", "T3 always PASS (all T3 checks skipped)",
     "def run_t3(top, decl, v):\n", "def run_t3(top, decl, v):\n    return\n"),
    ("M-T3-02", "T3 always FAIL",
     "def run_t3(top, decl, v):\n", "def run_t3(top, decl, v):\n    v.add(\"T3-HASH\", \"mutant\")\n    return\n"),
    ("M-T3-03", "skip the hash recomputation",
     'if record_hash(r) != r["hash"]:', "if False:"),
    ("M-T3-04", "skip the genesis (zero prev_hash) check",
     'if r["prev_hash"] != ZERO_HASH:', "if False:"),
    ("M-T3-05", "accept first seq 0",
     "if lowest != 1:", "if lowest not in (0, 1):"),
    ("M-T3-06", "off-by-one in the gap test: highest seq left out of the scan (equivalent mutant, see note)",
     "range(1, highest + 1)", "range(1, highest)"),
    ("M-T3-06b", "off-by-one in the gap test: seq 1 left out of the scan",
     "range(1, highest + 1)", "range(2, highest + 1)"),
    ("M-T3-06c", "off-by-one in the gap test: scan runs one past the highest seq",
     "range(1, highest + 1)", "range(1, highest + 2)"),
    ("M-T3-20", "link compared only with seq minus one (a missing predecessor is never a link failure)",
     "pred = seqs[idx - 1]", "pred = s - 1\n        if pred not in by_seq:\n            continue"),
    ("M-T3-07", "skip the link check",
     'if r["prev_hash"] not in pred_hashes:', "if False:"),
    ("M-T3-08", "skip the fork check",
     "if len(by_seq[s]) > 1:", "if False:"),
    ("M-T3-09", "ignore teardown last_seq",
     'elif td["last_seq"] != max_event or td["seq"] != td["last_seq"] + 1:', "elif False:"),
    ("M-T3-10", "treat an open stream as PASS",
     'v.add("T3-OPEN"', 'None and v.add("T3-OPEN"'),
    ("M-T3-11", "report only the first reason code",
     "codes = sorted({c for c, _ in v.findings})", "codes = sorted({c for c, _ in v.findings})[:1]"),
    ("M-T3-12", "walk in file order instead of seq order",
     "seqs = sorted(by_seq)", "seqs = list(by_seq)"),
    ("M-T3-13", "accept more than one teardown",
     "if len(tds) > 1:", "if False:"),
    ("M-T3-14", "accept records after the teardown",
     'if td["seq"] != highest or any(e["seq"] > td["seq"] for e in events):', "if False:"),
    ("M-T3-15", "treat an empty input as PASS",
     'v.add("T3-EMPTY"', 'None and v.add("T3-EMPTY"'),
    ("M-T3-16", "accept uppercase hex",
     'HEX = set("0123456789abcdef")', 'HEX = set("0123456789abcdefABCDEF")'),
    ("M-T3-17", "declared-gap range ignored (declared seqs still counted as undeclared)",
     "und = [s for s in missing if s not in declared_seqs]", "und = missing"),
    ("M-T3-18", "declared gap reported without the DECLARED-GAP hold (declared scope can PASS)",
     'v.add("DECLARED-GAP", "stream', 'None and v.add("DECLARED-GAP", "stream'),
    ("M-T3-19", "missing seqs not listed as UNDECLARED GAP",
     'v.undeclared.append("stream', 'None and v.undeclared.append("stream'),
    ("M-IN-01", "booleans accepted as integers",
     "return type(v) is int and", "return isinstance(v, int) and"),
    ("M-IN-02", "duplicate keys accepted (last one wins)",
     "if k in obj:", "if False:"),
    ("M-IN-03", "NFC check removed",
     'elif unicodedata.normalize("NFC", s) != s:', "elif False:"),
    ("M-IN-04", "evidence hash over the input with newlines removed instead of the file bytes",
     "evidence_hash = hashlib.sha256(raw).hexdigest()", 'evidence_hash = hashlib.sha256(raw.replace(b"\\n", b"")).hexdigest()'),
    ("M-IN-05", "integer bound raised to 2^64",
     "MAX_INT = 2 ** 53 - 1", "MAX_INT = 2 ** 64"),
    ("M-OUT-01", "profile line dropped",
     '           "Profile: F (vector profile v0 assumes sequence numbers assigned at the source)",\n', ""),
    ("M-OUT-02", "V2.4 unsigned-result sentence dropped",
     "out.append(V24)", "pass"),
    ("M-OUT-03", "exit code always 0",
     'return {"PASS": 0, "FAIL": 1, "HOLD": 2}[res]', "return 0"),
    ("M-OUT-04", "FAIL and HOLD precedence swapped",
     'if codes & FAIL_CODES:\n            return "FAIL"\n        if codes & HOLD_CODES:\n            return "HOLD"',
     'if codes & HOLD_CODES:\n            return "HOLD"\n        if codes & FAIL_CODES:\n            return "FAIL"'),
    ("M-T14-01", "T14a always PASS (all T14a checks skipped)",
     "def run_t14a(top, decl, v, reading):\n", "def run_t14a(top, decl, v, reading):\n    return\n"),
    ("M-T14-02", "T14a always FAIL",
     "def run_t14a(top, decl, v, reading):\n",
     "def run_t14a(top, decl, v, reading):\n    v.add(\"T14A-IMBALANCE\", \"mutant\")\n    return\n"),
    ("M-T14-03", "ignore dropped",
     "diff = r - (a + d)", "diff = r - a"),
    ("M-T14-04", "accept accepted plus dropped greater than or equal to received",
     "if diff != 0:", "if diff > 0:"),
    ("M-T14-05", "check only the first checkpoint",
     "for c in good:\n        cid = c[\"checkpoint_id\"]", "for c in good[:1]:\n        cid = c[\"checkpoint_id\"]"),
    ("M-T14-06", "tolerate an imbalance of 1",
     "if diff != 0:", "if abs(diff) > 1:"),
    ("M-T14-07", "ignore the fail-open declared-gap line",
     'v.declared.append("DECLARED GAP: drops', 'None and v.declared.append("DECLARED GAP: drops'),
    ("M-T14-08", "drop the SOURCE-LOCAL line",
     'if test == "T14a" and res == "PASS":', "if False:"),
    ("M-T14-09", "checkpoint policy ignored",
     'if fail_mode and c["policy"] != fail_mode:', "if False:"),
    ("M-T14-10", "UNVERIFIED provenance ignored",
     'if prov == "UNVERIFIED":', "if False:"),
    ("M-T14-11", "negative counters accepted",
     'all(is_nonneg_int(c[k]) for k in ("received", "accepted", "dropped"))',
     'all(is_int(c[k]) for k in ("received", "accepted", "dropped"))'),
    ("M-T14-12", "duplicate checkpoint ids accepted",
     "if ok and cid in seen:", "if False:"),
    ("M-T14-13", "claimed INDEPENDENTLY-RECONCILED label printed as if checked",
     'label = prov if prov != "INDEPENDENTLY-RECONCILED" else', 'label = prov if True else'),
    ("M-T14-14", "no checkpoints treated as PASS",
     'v.add("T14A-NONE"', 'None and v.add("T14A-NONE"'),
    ("M-T14-15", "T14b-not-run line dropped",
     "v.notes.append(", "None and v.notes.append("),
    ("M-T14-16", "fail-open drops listed as declared gap even when the declaration says fail-closed",
     'c["policy"] == "fail-open" and fail_mode == "fail-open" and diff == 0',
     'c["policy"] == "fail-open" and diff == 0'),
    ("M-ALT-B", "Reading B regression check disabled",
     "if cur[k] < prev[k]:", "if False:"),
    ("M-ALT-C", "Reading C chain-count check disabled",
     'if n != c["accepted"]:', "if False:"),
    ("M-ALT-D", "Reading D hold disabled",
     'if reading == "D":', "if False:"),
    ("M-IN-06", "nesting depth check removed",
     "if nesting_depth(raw) > MAX_DEPTH:", "if False:"),
    ("M-IN-07", "nesting limit off by one, too high (17)",
     "MAX_DEPTH = 16", "MAX_DEPTH = 17"),
    ("M-IN-08", "nesting limit off by one, too low (15)",
     "MAX_DEPTH = 16", "MAX_DEPTH = 15"),
]


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def vectors():
    out = []
    base = os.path.join(ROOT, "vectors")
    for group in sorted(os.listdir(base)):
        for vid in sorted(os.listdir(os.path.join(base, group))):
            d = os.path.join(base, group, vid)
            with open(os.path.join(d, "intent.txt"), encoding="utf-8") as f:
                cmd = f.readline().split(": ", 1)[1].split()
            # cmd: python verify.py TEST path [--reading X]
            out.append((vid, cmd[2], os.path.join(ROOT, cmd[3]), cmd[4:], d))
    return out


def run_all(verifier, vecs):
    disagree = []
    for vid, test, path, extra, d in vecs:
        p = subprocess.run([sys.executable, "-I", verifier, test, path] + extra, capture_output=True)
        with open(os.path.join(d, "expected.txt"), "rb") as f:
            exp = f.read()
        with open(os.path.join(d, "expected_exit.txt"), encoding="utf-8") as f:
            exp_exit = int(f.read().strip())
        if p.stdout != exp or p.returncode != exp_exit:
            disagree.append(vid)
    return disagree


def main():
    src_path = os.path.join(ROOT, "verify.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    vecs = vectors()
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    base_disagree = run_all(src_path, vecs)
    lines = []
    killed = survived = 0
    with tempfile.TemporaryDirectory() as tmp:
        for mid, desc, old, new in MUTANTS:
            n = src.count(old)
            if n != 1:
                lines.append("%s | %s | NOT APPLIED (target text found %d times)" % (mid, desc, n))
                continue
            mpath = os.path.join(tmp, "verify_%s.py" % mid.replace("-", "_"))
            with open(mpath, "w", encoding="utf-8", newline="\n") as f:
                f.write(src.replace(old, new))
            dis = run_all(mpath, vecs)
            if dis:
                killed += 1
                lines.append("%s | %s | killed by %s" % (mid, desc, ", ".join(dis)))
            else:
                survived += 1
                lines.append("%s | %s | SURVIVED" % (mid, desc))
    me = os.path.abspath(__file__)
    rec = [
        "MUTATION RECORD, O4M Record Tests 2026 v1.0, T3 and T14a, vector profile v0",
        "Self-run by the author of the verifier. Not reproduced by anyone else. Finer mutants beyond this list have not been run.",
        "",
        "Run started: %s" % started,
        "Python: %s (%s)" % (platform.python_version(), platform.platform(terse=True)),
        "SHA-256 verify.py: %s" % sha(src_path),
        "SHA-256 gen_vectors.py: %s" % sha(os.path.join(ROOT, "gen_vectors.py")),
        "SHA-256 mutation/mutate.py: %s" % sha(me),
        "Commands (from the package root):",
        "  python gen_vectors.py . --expected",
        "  python mutation/mutate.py",
        "Vectors run per mutant: %d (T3, T14a and alternative readings; a vector kills a mutant if stdout or exit code differs from expected)" % len(vecs),
        "Unmutated verifier against every vector: %s" % ("all match" if not base_disagree else "MISMATCH: " + ", ".join(base_disagree)),
        "",
        "One line per mutant: id | description | result",
    ] + lines + [
        "",
        "Mutants: %d. Killed: %d. Survived: %d." % (len(MUTANTS), killed, survived),
        "",
        "On survivors and history",
        "First run on 7 Nov 2026: 47 mutants, 44 killed, 3 survived (M-T3-04 skip the genesis check, M-T3-06, "
        "M-T14-06 tolerate an imbalance of 1). Two survivors showed missing vectors, not equivalent code. Vectors "
        "t3-028 (valid first record with a non-zero prev_hash) and t14a-019 (imbalance of exactly 1) were added, "
        "every expected.txt was regenerated from the unchanged verifier, and both mutants are now killed. Mutants "
        "M-T3-06b, M-T3-06c and M-T3-20 were added at the same time. No expected.txt was edited to kill a mutant.",
        "M-T3-06 survives and is an equivalent mutant: the highest seq in a stream is present by construction (it is "
        "taken from the records), so leaving it out of the missing-seq scan cannot change any output. No vector can "
        "kill it. The sharper off-by-one mutants M-T3-06b and M-T3-06c are killed.",
        "Limits of this record: mutants are hand-written text substitutions chosen by the same author who wrote the "
        "verifier, so they reflect that author's idea of likely mistakes. A kill shows that a vector disagrees with the "
        "mutant; it does not show that the expected outputs are right. Agreement with RT-1 or with a second reader has "
        "not been checked.",
    ]
    with open(os.path.join(ROOT, "mutation", "MUTATION_RECORD.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(rec) + "\n")
    sys.stdout.write("\n".join(lines[-0:]) + "\nkilled %d survived %d base %s\n" % (killed, survived, base_disagree or "ok"))
    return 0 if not base_disagree else 1


if __name__ == "__main__":
    sys.exit(main())
