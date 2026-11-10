#!/usr/bin/env python3
# Copyright 2026 Gareth Wong
# SPDX-License-Identifier: Apache-2.0
#
# Deterministic generator for the T3 and T14a vectors (vector profile v0).
# No randomness, no network, no clock. Running it twice gives identical bytes.
#
#   python gen_vectors.py OUTDIR              writes input.json, about.txt, intent.txt
#   python gen_vectors.py OUTDIR --expected   also runs verify.py and writes expected.txt and
#                                             expected_exit.txt, and stops if any result or
#                                             reason-code set differs from the stated intent.

import hashlib
import json
import os
import subprocess
import sys

ZERO = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rehash(r):
    body = {k: v for k, v in r.items() if k != "hash"}
    r["hash"] = hashlib.sha256(canonical(body)).hexdigest()
    return r


def rec(sid, seq, prev, data, kind="event", last_seq=None):
    r = {"stream_id": sid, "seq": seq, "prev_hash": prev, "type": kind, "data": data}
    if kind == "teardown":
        r["last_seq"] = last_seq
    return rehash(r)


def stream(sid, n=5, start=1, prefix=None):
    prefix = prefix or sid
    out, prev = [], ZERO
    for i in range(n):
        r = rec(sid, start + i, prev, "%s event %d" % (prefix, start + i))
        out.append(r)
        prev = r["hash"]
    last = start + n - 1
    out.append(rec(sid, last + 1, prev, "%s teardown" % prefix, "teardown", last))
    return out


def relink(rs, from_index):
    # recompute prev_hash and hash from from_index onwards, in list order
    for i in range(from_index, len(rs)):
        rs[i]["prev_hash"] = rs[i - 1]["hash"] if i > 0 else ZERO
        rehash(rs[i])
    return rs


def decl(fail_mode="fail-closed", gaps=None):
    return {
        "consequential_action_types": ["payment"],
        "tolerances": {"max_gap": 0, "max_clock_skew_s": 5, "max_unsealed_window_s": 60},
        "fail_mode": fail_mode,
        "monitors": [],
        "declared_gaps": gaps or [],
    }


def cp(cid, r, a, d, policy="fail-closed", **extra):
    c = {"checkpoint_id": cid, "received": r, "accepted": a, "dropped": d, "policy": policy}
    c.update(extra)
    return c


V = []  # (folder, test, reading, input object or raw text, result, codes, about)


def add(folder, test, obj, result, codes, about, reading=None):
    V.append((folder, test, reading, obj, result, sorted(codes), about))


# T3 vectors

s = stream("s1")
add("T3/t3-001", "T3", {"declaration": decl(), "records": s}, "PASS", [],
    "Valid single stream: five events (seq 1 to 5) and a teardown at seq 6 carrying last_seq 5, every hash and link "
    "recomputed. Models the untampered case. Expected PASS with no reason codes.")

a, b = stream("s1"), stream("s2")
inter = [x for pair in zip(a, b) for x in pair]
add("T3/t3-002", "T3", {"declaration": decl(), "records": inter}, "PASS", [],
    "Two valid streams whose records alternate in file order. Models normal interleaved capture. The verifier walks "
    "each stream by seq, so interleaving does not matter. Expected PASS.")

s = stream("s1"); del s[2]
add("T3/t3-003", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-GAP", "T3-LINK"],
    "Deletion attack: the event at seq 3 is removed and nothing is recomputed. Seq 3 is missing (T3-GAP, also listed "
    "as an UNDECLARED GAP) and seq 4 still points at the deleted record, so it does not link to seq 2 (T3-LINK). Expected FAIL.")

s = stream("s1"); del s[0]
add("T3/t3-004", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-GAP", "T3-START"],
    "Deletion of the first event. The lowest seq is now 2 (T3-START) and seq 1 is missing (T3-GAP, listed as an "
    "UNDECLARED GAP). No link failure is reported for seq 2 because it has no predecessor left to compare with; T3-START "
    "carries that finding. Expected FAIL.")

s = stream("s1"); del s[4]
add("T3/t3-005", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-GAP", "T3-LINK", "T3-TAIL"],
    "Deletion of the last event before the teardown (seq 5). Three codes fire: T3-GAP (seq 5 missing), T3-LINK (the "
    "teardown at seq 6 points at the deleted record, not at seq 4) and T3-TAIL (the teardown says last_seq 5 but the "
    "highest event present is 4). The teardown carrying last_seq is what makes this tail deletion visible. Expected FAIL.")

s = stream("s1")[:-1]
add("T3/t3-006", "T3", {"declaration": decl(), "records": s}, "HOLD", ["T3-OPEN"],
    "The teardown is removed, leaving an open stream of five valid events. T3 cannot tell whether events after seq 5 "
    "existed, so it returns HOLD with T3-OPEN rather than PASS. Known limit: deleting the tail of a stream that has no "
    "teardown cannot be seen by T3 alone; it needs C13 (teardown on a never-shed lane) or counters and checkpoints (C14, C6). Expected HOLD.")

s = stream("s1"); s[2]["seq"], s[3]["seq"] = 4, 3
add("T3/t3-007", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-HASH", "T3-LINK"],
    "Reorder attack: the seq values of events 3 and 4 are swapped without recomputing anything. Both moved records "
    "fail hash recomputation (T3-HASH, seq is inside the hash) and the links at seq 3, 4 and 5 no longer match their "
    "predecessors (T3-LINK). Expected FAIL.")

s = stream("s1"); s.insert(3, rec("s1", 3, s[1]["hash"], "s1 inserted record"))
add("T3/t3-008", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-FORK"],
    "Insertion attack: an extra record reuses seq 3 with different data, a valid hash and a valid link to seq 2. Two "
    "records now share seq 3 (T3-FORK). Seq 4 still links to one of them, so no link failure fires. Expected FAIL.")

s = stream("s1")
alt4 = rec("s1", 4, s[2]["hash"], "s1 branch event 4")
alt5 = rec("s1", 5, alt4["hash"], "s1 branch event 5")
alt6 = rec("s1", 6, alt5["hash"], "s1 branch teardown", "teardown", 5)
add("T3/t3-009", "T3", {"declaration": decl(), "records": s + [alt4, alt5, alt6]}, "FAIL", ["T3-FORK", "T3-TAIL"],
    "Fork: a second branch starts at seq 4 linking to seq 3 and runs to its own teardown, so seq 4, 5 and 6 each hold "
    "two records (T3-FORK) and the stream has two teardowns (T3-TAIL). Each branch is internally valid, which is why "
    "only the fork and tail checks catch it. Expected FAIL.")

s = stream("s1"); s[2]["data"] = "s1 event 3 altered"
add("T3/t3-010", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-HASH"],
    "Tampering with the data of event 3 while leaving its stored hash unchanged. Recomputation does not match "
    "(T3-HASH). Links still match the stored hashes, so only T3-HASH fires. Expected FAIL.")

s = stream("s1"); s[2]["data"] = "s1 event 3 altered"; rehash(s[2])
add("T3/t3-011", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-LINK"],
    "Tampering with event 3 and recomputing that record's hash, but not the records after it. Event 3 now verifies on "
    "its own, but seq 4 points at the old hash (T3-LINK). Expected FAIL.")

s = stream("s1"); s[2]["data"] = "s1 event 3 altered"; relink(s, 2)
add("T3/t3-012", "T3", {"declaration": decl(), "records": s}, "PASS", [],
    "Known limit vector. Event 3 is altered and every record from seq 3 onwards is recomputed consistently, including "
    "the teardown. The chain walk returns PASS because the rewritten chain is internally perfect. A chain walk alone "
    "cannot detect a full rewrite from the point of tampering; that needs external commitments made before the rewrite "
    "(checkpoints with independent time-stamps and witnesses, C6 and T6a). This vector must stay in the package. Expected PASS.")

add("T3/t3-013", "T3", {"declaration": decl(), "records": []}, "HOLD", ["T3-EMPTY"],
    "Zero streams: the records list is empty. Nothing can be walked, so the result is HOLD with T3-EMPTY, never PASS. Expected HOLD.")

s = stream("s1", n=5, start=0)
add("T3/t3-014", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-START"],
    "Zero-based stream: seq runs 0 to 4 and the teardown is at 5, all hashes and links valid. Vector profile v0 chose "
    "one-based numbering, so this fails T3-START. It documents the choice; if the editor picks zero-based numbering, "
    "this vector and t3-001 swap results. Expected FAIL.")

s = stream("s1"); order = [3, 0, 5, 1, 4, 2]
add("T3/t3-015", "T3", {"declaration": decl(), "records": [s[i] for i in order]}, "PASS", [],
    "The records of t3-001 in a fixed shuffled file order (4, 1, teardown, 2, 5, 3). Content is valid; the verifier "
    "walks by seq, so file order does not matter. Expected PASS.")

a, b, c = stream("s1"), stream("s2"), stream("s3"); b[1]["data"] = "s2 event 2 altered"
add("T3/t3-016", "T3", {"declaration": decl(), "records": a + b + c}, "FAIL", ["T3-HASH"],
    "Three streams; stream s2 has event 2 altered with its stored hash unchanged. Only s2 is named in the detail "
    "lines; s1 and s3 raise nothing. Expected FAIL.")

s = stream("s1"); s[5]["last_seq"] = 7; rehash(s[5])
add("T3/t3-017", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-TAIL"],
    "The teardown claims last_seq 7 while the highest event is 5; its hash is recomputed so only the tail check can "
    "catch it (T3-TAIL). Models a teardown that misstates how many events the stream held. Expected FAIL.")

s = stream("s1"); s[1]["data"] = "s1 event 2 caf" + "é"; relink(s, 1)
add("T3/t3-018", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T2-NFC"],
    "Event 2 holds a string in decomposed form (e followed by a combining acute accent), which is not NFC. The chain "
    "is otherwise valid. C2 requires the verifier to reject non-NFC input rather than normalise it, so the result is "
    "FAIL with proposed code T2-NFC. Expected FAIL.")

g = [{"stream_id": "s1", "from_seq": 3, "to_seq": 3, "action_type": "payment",
      "reason": "capture point restarted; record not captured"}]
s = stream("s1"); del s[2]; s[2]["prev_hash"] = s[1]["hash"]; relink(s, 2)
add("T3/t3-019", "T3", {"declaration": decl(gaps=g), "records": s}, "HOLD", ["DECLARED-GAP"],
    "The declaration lists stream s1 seq 3 as a declared gap, and the capture point skipped seq 3, linking seq 4 "
    "straight to seq 2. The missing seq is reported as a DECLARED GAP, not an UNDECLARED GAP. Under V2.3 a declared "
    "gap is never PASS for its scope, so the result is HOLD with proposed code DECLARED-GAP. Compare t3-003, where seq "
    "4 still points at a deleted record. Expected HOLD.")

s = stream("s1"); del s[3]
add("T3/t3-020", "T3", {"declaration": decl(gaps=g), "records": s}, "FAIL", ["DECLARED-GAP", "T3-GAP", "T3-LINK"],
    "Same declaration as t3-019 (seq 3 declared as a gap), but the record actually missing is seq 4, deleted with "
    "nothing recomputed. The declared range does not excuse a different gap: T3-GAP and T3-LINK fire, seq 4 is listed "
    "as an UNDECLARED GAP, and the declared entry is still reported. Expected FAIL.")

s = stream("s1")
txt = json.dumps({"declaration": decl(), "records": s}, indent=2, ensure_ascii=True) + "\n"
txt = txt.replace('"seq": 2,', '"seq": 2,\n      "seq": 2,', 1)
add("T3/t3-021", "T3", txt, "FAIL", ["INPUT-DUPKEY"],
    "Event 2 carries the key \"seq\" twice. Python's json module would silently keep the last one, so two readers "
    "could see different records. Vector profile v0 rejects duplicate keys (proposed code INPUT-DUPKEY, FAIL) and does "
    "not walk the chain. Expected FAIL.")

s = stream("s1"); s[1]["hash"] = s[1]["hash"].upper(); s[2]["prev_hash"] = s[1]["hash"]
add("T3/t3-022", "T3", {"declaration": decl(), "records": s}, "HOLD", ["T3-MALFORMED"],
    "Event 2 stores its hash in uppercase hex. Vector profile v0 requires 64 lowercase hex characters, so the record is "
    "malformed (proposed T3-MALFORMED, HOLD) and its stream is not walked. Accepting either case would let two "
    "different byte strings stand for one hash. Expected HOLD.")

s = stream("s1"); s[2]["seq"] = "3"
add("T3/t3-023", "T3", {"declaration": decl(), "records": s}, "HOLD", ["T3-MALFORMED"],
    "Event 3 gives its seq as the string \"3\" instead of an integer. Malformed under vector profile v0 (T3-MALFORMED, "
    "HOLD). A lax reader that coerced strings to numbers would walk a different chain. Expected HOLD.")

s = stream("s1"); s.append(rec("s1", 7, s[5]["hash"], "s1 event after teardown"))
add("T3/t3-024", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-TAIL"],
    "An event at seq 7 follows the teardown at seq 6 and links to it. Hashes and links are valid, but a stream must "
    "end with its teardown, so T3-TAIL fires. Models activity recorded after an agent was declared torn down. Expected FAIL.")

s = stream("s1"); s.append(rec("s1", 7, s[5]["hash"], "s1 second teardown", "teardown", 5))
add("T3/t3-025", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-TAIL"],
    "Two teardowns in one stream (seq 6 and seq 7, both with last_seq 5). T3-TAIL fires because a stream has exactly "
    "one teardown. Expected FAIL.")

a, b = stream("s1"), stream("s2"); moved = dict(a[2]); moved["stream_id"] = "s2"; b[2] = moved
add("T3/t3-026", "T3", {"declaration": decl(), "records": a + b}, "FAIL", ["T3-HASH", "T3-LINK"],
    "Splice: event 3 of stream s1 is copied into stream s2 with only stream_id changed, replacing s2's own event 3. "
    "Because stream_id is inside the hash, the moved record fails recomputation (T3-HASH); its link points into s1 and "
    "s2's seq 4 points at the replaced record (T3-LINK). Stream s1 is untouched. Expected FAIL.")

s = stream("s1"); s[5]["prev_hash"] = s[3]["hash"]; rehash(s[5])
add("T3/t3-027", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-LINK"],
    "The teardown's hash is valid but its prev_hash points at seq 4 instead of seq 5 (T3-LINK). Models a teardown "
    "written without the final event in view. Expected FAIL.")

s = stream("s1"); s[0]["prev_hash"] = hashlib.sha256(b"an earlier record not in this export").hexdigest()
rehash(s[0]); relink(s, 1)
add("T3/t3-028", "T3", {"declaration": decl(), "records": s}, "FAIL", ["T3-START"],
    "Added after the mutation run (mutant M-T3-04 survived without it). Seq 1 has a valid hash but its prev_hash "
    "points at some earlier record instead of the zero value, and the rest of the chain is consistent. This is what a "
    "stream looks like when its true beginning was cut off and the remainder renumbered from 1. T3-START fires. Expected FAIL.")

# T14a vectors

add("T14a/t14a-001", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 100, 0)]}, "PASS", [],
    "One checkpoint, received 100, accepted 100, dropped 0, fail-closed. Counters balance. The PASS carries the "
    "SOURCE-LOCAL line: it is arithmetic on numbers the capture point produced. Expected PASS.")

add("T14a/t14a-002", "T14a", {"declaration": decl("fail-open"), "checkpoints": [cp("cp-1", 100, 95, 5, "fail-open")]},
    "PASS", [],
    "Under a declared fail-open policy the checkpoint shows received 100, accepted 95, dropped 5. Counters balance and "
    "the drops are counted, so per A1 they are reported and do not fail. The verdict lists them as a DECLARED GAP. "
    "Primary reading: PASS. See alt-d-001 for the reading where this scope is HOLD. Expected PASS.")

add("T14a/t14a-003", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 90, 5)]}, "FAIL", ["T14A-IMBALANCE"],
    "Hidden drops: received 100, accepted 90, dropped 5. Five records vanished without being counted (T14A-IMBALANCE, "
    "listed as an UNDECLARED GAP of 5). Expected FAIL.")

add("T14a/t14a-004", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 95, 10)]}, "FAIL", ["T14A-IMBALANCE"],
    "Padding: received 100, accepted 95, dropped 10, so accepted plus dropped exceed received by 5. T14A-IMBALANCE "
    "fires. This is not a gap (nothing is missing), so it is not listed as one. Expected FAIL.")

five = [cp("cp-%d" % i, 100 * i, 100 * i - i, i) for i in range(1, 6)]
add("T14a/t14a-005", "T14a", {"declaration": decl(), "checkpoints": five}, "PASS", [],
    "Five cumulative checkpoints, all balanced, with a few counted drops under fail-closed. PASS, with the line noting "
    "that T14b (drops under fail-closed) was not run. Expected PASS.")

five = [cp("cp-%d" % i, 100 * i, 100 * i - i, i) for i in range(1, 6)]; five[3]["accepted"] -= 4
add("T14a/t14a-006", "T14a", {"declaration": decl(), "checkpoints": five}, "FAIL", ["T14A-IMBALANCE"],
    "Five checkpoints; the fourth (cp-4) is short by 4. The detail line names cp-4 only. Expected FAIL.")

add("T14a/t14a-007", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 97, 3)]}, "PASS", [],
    "Fail-closed policy with 3 counted drops and balanced counters. T14a only checks arithmetic, so PASS, with the line "
    "\"dropped greater than zero under fail-closed: T14b not run\". T14b would decide whether these drops fail. Expected PASS.")

add("T14a/t14a-008", "T14a", {"declaration": decl(), "checkpoints": []}, "HOLD", ["T14A-NONE"],
    "No checkpoints. Nothing to balance, so HOLD with T14A-NONE, never PASS. Expected HOLD.")

c1 = cp("cp-1", 100, 100, 0); del c1["dropped"]
add("T14a/t14a-009", "T14a", {"declaration": decl(), "checkpoints": [c1]}, "HOLD", ["T14A-MALFORMED"],
    "The dropped counter is missing. HOLD with T14A-MALFORMED; the verifier does not assume zero. Expected HOLD.")

add("T14a/t14a-010", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 105, -5)]}, "HOLD", ["T14A-MALFORMED"],
    "A negative dropped counter (-5) that would otherwise make the arithmetic balance. Negative counters are malformed "
    "(T14A-MALFORMED, HOLD). Expected HOLD.")

add("T14a/t14a-011", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 800, 800, 0)]}, "PASS", [],
    "Known limit vector. Suppose the capture point really received 1,000 records and dropped 200, but reports received "
    "800, accepted 800, dropped 0. The counters balance, so T14a returns PASS with the SOURCE-LOCAL line. T14a cannot "
    "detect consistent under-reporting; that needs T14c, reconciliation against a count the operator does not control. "
    "This vector must stay in the package. Expected PASS.")

add("T14a/t14a-012", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", True, 1, 0)]}, "HOLD", ["T14A-MALFORMED"],
    "The received counter is the JSON value true. Python treats true as the integer 1, so a naive check would balance "
    "1 = 1 + 0. Vector profile v0 rejects booleans as counters (T14A-MALFORMED). Expected HOLD.")

t13 = json.dumps({"declaration": decl(), "checkpoints": [cp("cp-1", 100, 100, 0)]}, indent=2, ensure_ascii=True) + "\n"
t13 = t13.replace('"accepted": 100,', '"accepted": 100.0,', 1)
add("T14a/t14a-013", "T14a", t13, "HOLD", ["T14A-MALFORMED"],
    "The accepted counter is written 100.0. Profile v0 has no floats; a counter written with a fraction is malformed "
    "(T14A-MALFORMED), even though its value equals an integer. Expected HOLD.")

big = 2 ** 53
add("T14a/t14a-014", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", big, big, 0)]}, "HOLD", ["T14A-MALFORMED"],
    "Counters of 2^53 (9007199254740992), one above the largest integer a JSON reader using IEEE 754 doubles holds "
    "exactly. Profile v0 bounds integers at 2^53 minus 1, so this is malformed. A reader in another language could "
    "silently round these numbers and reach a different result. Expected HOLD.")

add("T14a/t14a-015", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 100, 0), cp("cp-1", 200, 200, 0)]},
    "HOLD", ["T14A-MALFORMED"],
    "Two checkpoints share the id cp-1. The second is malformed (T14A-MALFORMED) and set aside; the first is checked "
    "and balances. Expected HOLD.")

add("T14a/t14a-016", "T14a", {"declaration": decl("fail-closed"), "checkpoints": [cp("cp-1", 100, 98, 2, "fail-open")]},
    "FAIL", ["T14A-POLICY"],
    "The declaration says fail-closed but the checkpoint says fail-open, and two records were dropped. C1 lists a "
    "retroactive policy change as an attack case. Proposed code T14A-POLICY, FAIL. Expected FAIL.")

add("T14a/t14a-017", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 100, 0, provenance="UNVERIFIED")]},
    "HOLD", ["T14A-UNVERIFIED"],
    "Balanced counters labelled UNVERIFIED (for example a copy of an outside count delivered inside the operator's own "
    "export). Spec Conventions: a check resting on an UNVERIFIED source can return FAIL but never PASS. HOLD with "
    "proposed code T14A-UNVERIFIED. Expected HOLD.")

add("T14a/t14a-018", "T14a",
    {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 100, 0, provenance="INDEPENDENTLY-RECONCILED")]}, "PASS", [],
    "The operator's own input labels its counters INDEPENDENTLY-RECONCILED. That label is the operator's assertion; "
    "T14a has no reconciliation evidence, so it prints the label as claimed and not checked, and the PASS still carries "
    "the SOURCE-LOCAL line. Expected PASS.")

add("T14a/t14a-019", "T14a", {"declaration": decl(), "checkpoints": [cp("cp-1", 100, 99, 0)]}, "FAIL", ["T14A-IMBALANCE"],
    "Added after the mutation run (mutant M-T14-06, tolerate an imbalance of 1, survived without it). Received 100, "
    "accepted 99, dropped 0: one record lost without being counted. The declared maximum gap is 0, so a loss of one "
    "is a FAIL. Expected FAIL.")

# Alternative readings (not the primary reading)

inc = [cp("cp-1", 100, 100, 0), cp("cp-2", 200, 199, 1), cp("cp-3", 300, 298, 2)]
add("alt-readings/alt-b-001", "T14a", {"declaration": decl(), "checkpoints": inc}, "PASS", [],
    "Reading B (counters never decrease between checkpoints). Three cumulative checkpoints, each counter rising or "
    "level. Expected PASS under Reading B.", reading="B")

reg = [cp("cp-1", 100, 100, 0), cp("cp-2", 200, 199, 1), cp("cp-3", 150, 150, 0)]
add("alt-readings/alt-b-002", "T14a", {"declaration": decl(), "checkpoints": reg}, "FAIL", ["T14A-REGRESS"],
    "Reading B. Checkpoint cp-3 reports lower received, accepted and dropped counts than cp-2 while each checkpoint "
    "balances on its own. A counter reset like this hides what happened in between. Under the primary reading this "
    "vector passes. Expected FAIL with proposed T14A-REGRESS under Reading B.", reading="B")

chain = stream("s1")
ok_c = {"declaration": decl(), "records": chain,
        "checkpoints": [cp("cp-1", 3, 3, 0, upto_seq=3), cp("cp-2", 6, 6, 0, upto_seq=6)]}
add("alt-readings/alt-c-001", "T14a", ok_c, "PASS", [],
    "Reading C (accepted equals the number of records in the chain up to the checkpoint). The chain holds 6 records "
    "(5 events and a teardown); cp-1 covers seq 1 to 3 and cp-2 covers seq 1 to 6, matching accepted. Expected PASS "
    "under Reading C.", reading="C")

chain = stream("s1"); del chain[3]
bad_c = {"declaration": decl(), "records": chain,
         "checkpoints": [cp("cp-1", 3, 3, 0, upto_seq=3), cp("cp-2", 6, 6, 0, upto_seq=6)]}
add("alt-readings/alt-c-002", "T14a", bad_c, "FAIL", ["T14A-CHAIN"],
    "Reading C. The chain lost seq 4, so only 5 records exist up to seq 6 while cp-2 claims 6 accepted. Counters balance "
    "on their own, so the primary reading passes; Reading C ties them to the chain and fails with proposed T14A-CHAIN.",
    reading="C")

add("alt-readings/alt-d-001", "T14a",
    {"declaration": decl("fail-open"), "checkpoints": [cp("cp-1", 100, 95, 5, "fail-open")]}, "HOLD", ["DECLARED-GAP"],
    "Reading D (V2.3 read strictly: a declared gap is never PASS for its scope). Same input as t14a-002. Counted drops "
    "under fail-open do not fail (A1) but the scope they cover is not PASS either, so the result is HOLD with "
    "DECLARED-GAP. Expected HOLD under Reading D.", reading="D")


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data.encode("utf-8"))


def main(argv):
    if len(argv) not in (2, 3) or (len(argv) == 3 and argv[2] != "--expected"):
        sys.stderr.write("usage: gen_vectors.py OUTDIR [--expected]\n")
        return 3
    out = argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    bad = 0
    for folder, test, reading, obj, result, codes, about in V:
        d = os.path.join(out, "vectors", folder)
        text = obj if isinstance(obj, str) else json.dumps(obj, indent=2, ensure_ascii=True) + "\n"
        write(os.path.join(d, "input.json"), text)
        write(os.path.join(d, "about.txt"), about + "\n")
        cmd = "python verify.py %s vectors/%s/input.json%s" % (test, folder, (" --reading " + reading) if reading else "")
        write(os.path.join(d, "intent.txt"),
              "command: %s\nintended result: %s\nintended reason codes: %s\n"
              % (cmd, result, ", ".join(codes) if codes else "none"))
        if len(argv) == 3:
            args = [sys.executable, "-I", os.path.join(here, "verify.py"), test, os.path.join(d, "input.json")]
            if reading:
                args += ["--reading", reading]
            p = subprocess.run(args, capture_output=True)
            stdout = p.stdout.decode("utf-8")
            write(os.path.join(d, "expected.txt"), stdout)
            write(os.path.join(d, "expected_exit.txt"), "%d\n" % p.returncode)
            got_res = [l for l in stdout.splitlines() if l.startswith("Result: ")][0][8:]
            got_codes = [l for l in stdout.splitlines() if l.startswith("Reason codes")][0].split(": ", 1)[1]
            got_codes = [] if got_codes == "none" else got_codes.split(", ")
            if got_res != result or got_codes != codes:
                bad += 1
                sys.stderr.write("MISMATCH %s: intended %s %s, verifier gave %s %s\n" % (folder, result, codes, got_res, got_codes))
    sys.stderr.write("%d vectors written, %d mismatches against intent\n" % (len(V), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
