#!/usr/bin/env python3
# Copyright 2026 Gareth Wong
# SPDX-License-Identifier: Apache-2.0
#
# Reference verifier for O4M Record Tests 2026 v1.0, tests T3 and T14a,
# under vector profile v0 (a set of choices made for these vectors, not normative).
# Python 3 standard library only. No network, no clock, no randomness.
#
# Usage:
#   python verify.py T3 path/to/input.json
#   python verify.py T14a path/to/input.json
#   python verify.py T14a path/to/input.json --reading B   (alternative readings B, C, D)
# Exit code: 0 PASS, 1 FAIL, 2 HOLD, 3 usage error, unreadable file or internal error.
# Exit code 1 is only ever a FAIL verdict: a crash must never look like a FAIL (added 7 Nov 2026, package 2026-11-07b).

import hashlib
import json
import sys
import unicodedata

SUITE = "O4M Record Tests 2026 v1.0 (vector profile v0)"
ZERO_HASH = "0" * 64
MAX_INT = 2 ** 53 - 1
HEX = set("0123456789abcdef")

FAIL_CODES = {
    "INPUT-DUPKEY", "T2-NFC",
    "T3-HASH", "T3-START", "T3-GAP", "T3-FORK", "T3-LINK", "T3-TAIL",
    "T14A-IMBALANCE", "T14A-POLICY", "T14A-REGRESS", "T14A-CHAIN",
}
HOLD_CODES = {
    "INPUT-UNPARSEABLE", "INPUT-MALFORMED", "DECL-MALFORMED", "DECLARED-GAP",
    "T3-OPEN", "T3-EMPTY", "T3-MALFORMED",
    "T14A-NONE", "T14A-MALFORMED", "T14A-UNVERIFIED",
}

V24 = ("Unsigned result. This is the output of the O4M Record Tests, published as plain text "
       "with the SHA-256 of the evidence it was run on. It is not a certificate, seal or approval. "
       "No certificates are issued.")
SCOPE = [
    "Scope 1: records of AI system operation at inference and action time only; not training, model internals or behavioural tests.",
    "Scope 2: policy adequacy is out of scope.",
    "Scope 3: no claim to any assurance level of any other scheme; any mapping is informative only.",
    "Scope 4: evidence after the fact; these tests prevent nothing.",
    "Scope 5: integrity is not truth; an intact record of false content is still false content.",
]


class DupKey(Exception):
    pass


class Float:
    """Marks a JSON number written with a fraction or exponent; profile v0 has no floats."""
    def __init__(self, text):
        self.text = text


def pairs_hook(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise DupKey(k)
        obj[k] = v
    return obj


def canonical(obj):
    # JCS (RFC 8785) for the subset profile v0 allows: ASCII keys, integers within
    # plus or minus (2^53 - 1), strings, booleans. For that subset Python's
    # json.dumps with these settings gives the same bytes.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(canonical(body)).hexdigest()


def is_int(v):
    return type(v) is int and -MAX_INT <= v <= MAX_INT


def is_nonneg_int(v):
    return is_int(v) and v >= 0


def is_hex64(v):
    return isinstance(v, str) and len(v) == 64 and set(v) <= HEX


def walk_strings(obj, path, out):
    if isinstance(obj, str):
        out.append((path, obj))
    elif isinstance(obj, dict):
        for k in sorted(obj):
            out.append((path + "/" + k + " (key)", k))
            walk_strings(obj[k], path + "/" + k, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            walk_strings(v, path + "/" + str(i), out)


class Verdict:
    def __init__(self):
        self.findings = []      # (code, detail)
        self.notes = []
        self.counters = []
        self.declared = []
        self.undeclared = []

    def add(self, code, detail):
        self.findings.append((code, detail))

    def result(self):
        codes = {c for c, _ in self.findings}
        if codes & FAIL_CODES:
            return "FAIL"
        if codes & HOLD_CODES:
            return "HOLD"
        return "PASS"


# Declaration

def check_declaration(top, v):
    d = top.get("declaration") if isinstance(top, dict) else None
    ok = isinstance(d, dict) and set(d) == {
        "consequential_action_types", "tolerances", "fail_mode", "monitors", "declared_gaps"}
    if ok:
        cat = d["consequential_action_types"]
        tol = d["tolerances"]
        ok = (isinstance(cat, list) and all(isinstance(x, str) for x in cat)
              and isinstance(tol, dict)
              and set(tol) == {"max_gap", "max_clock_skew_s", "max_unsealed_window_s"}
              and all(is_nonneg_int(tol[k]) for k in tol)
              and d["fail_mode"] in ("fail-open", "fail-closed")
              and isinstance(d["monitors"], list) and all(isinstance(x, str) for x in d["monitors"])
              and isinstance(d["declared_gaps"], list))
    if ok:
        for g in d["declared_gaps"]:
            if not (isinstance(g, dict)
                    and set(g) == {"stream_id", "from_seq", "to_seq", "action_type", "reason"}
                    and isinstance(g["stream_id"], str) and isinstance(g["action_type"], str)
                    and isinstance(g["reason"], str)
                    and is_nonneg_int(g["from_seq"]) and is_nonneg_int(g["to_seq"])
                    and g["from_seq"] <= g["to_seq"]):
                ok = False
    if not ok:
        v.add("DECL-MALFORMED", "declaration missing or not in the vector profile v0 shape")
        return None, "Declaration: missing or malformed; T1b: not run"
    cat = d["consequential_action_types"]
    tol = d["tolerances"]
    gaps = d["declared_gaps"]
    if gaps:
        glist = "; ".join("stream %s seq %d to %d (%s)" % (g["stream_id"], g["from_seq"], g["to_seq"], g["action_type"])
                          for g in gaps)
    else:
        glist = "none"
    covered = len({g["action_type"] for g in gaps} & set(cat))
    mons = ", ".join(d["monitors"]) if d["monitors"] else "none declared"
    line = ("Declaration: consequential action types declared: %d; tolerances: max gap %d, max clock skew %d s, "
            "max unsealed window %d s; fail mode: %s; monitors: %s; declared gaps: %s, covering %d of %d "
            "consequential action types; T1b: not run"
            % (len(cat), tol["max_gap"], tol["max_clock_skew_s"], tol["max_unsealed_window_s"],
               d["fail_mode"], mons, glist, covered, len(cat)))
    return d, line


# T3

T3_EVENT_KEYS = {"stream_id", "seq", "prev_hash", "type", "data", "hash"}
T3_TEARDOWN_KEYS = T3_EVENT_KEYS | {"last_seq"}


def t3_record_ok(r):
    if not isinstance(r, dict):
        return False
    t = r.get("type")
    if t == "event":
        keys = T3_EVENT_KEYS
    elif t == "teardown":
        keys = T3_TEARDOWN_KEYS
    else:
        return False
    if set(r) != keys:
        return False
    if not (isinstance(r["stream_id"], str) and r["stream_id"]):
        return False
    if not is_nonneg_int(r["seq"]):
        return False
    if not (is_hex64(r["prev_hash"]) and is_hex64(r["hash"])):
        return False
    if not isinstance(r["data"], str):
        return False
    if t == "teardown" and not is_nonneg_int(r["last_seq"]):
        return False
    return True


def run_t3(top, decl, v):
    if not isinstance(top, dict) or set(top) != {"declaration", "records"} or not isinstance(top.get("records"), list):
        v.add("INPUT-MALFORMED", "top level must hold exactly 'declaration' and 'records' (a list)")
        return
    recs = top["records"]
    streams = {}
    bad_streams = set()
    for i, r in enumerate(recs):
        sid = r.get("stream_id") if isinstance(r, dict) and isinstance(r.get("stream_id"), str) else None
        if not t3_record_ok(r):
            where = "stream %s" % sid if sid else "stream unknown"
            seq = r.get("seq") if isinstance(r, dict) else None
            v.add("T3-MALFORMED", "%s, record number %d in file order (seq field %r): fields or types outside vector profile v0"
                  % (where, i + 1, seq))
            if sid:
                bad_streams.add(sid)
            continue
        streams.setdefault(sid, []).append(r)
    if not recs:
        v.add("T3-EMPTY", "input holds no streams")
        return
    declared = {}
    if decl:
        for g in decl["declared_gaps"]:
            declared.setdefault(g["stream_id"], set()).update(range(g["from_seq"], g["to_seq"] + 1))
            v.declared.append("stream %s seq %d to %d (%s): %s"
                              % (g["stream_id"], g["from_seq"], g["to_seq"], g["action_type"], g["reason"]))
            v.add("DECLARED-GAP", "stream %s seq %d to %d declared as not captured; reported as DECLARED GAP, never PASS for that scope"
                  % (g["stream_id"], g["from_seq"], g["to_seq"]))
    for sid in sorted(streams):
        if sid in bad_streams:
            continue
        t3_stream(sid, streams[sid], declared.get(sid, set()), v)


def t3_stream(sid, rs, declared_seqs, v):
    # (a) hash
    for r in sorted(rs, key=lambda x: (x["seq"], x["hash"])):
        if record_hash(r) != r["hash"]:
            v.add("T3-HASH", "stream %s seq %d: stored hash does not match recomputation" % (sid, r["seq"]))
    by_seq = {}
    for r in rs:
        by_seq.setdefault(r["seq"], []).append(r)
    seqs = sorted(by_seq)
    lowest, highest = seqs[0], seqs[-1]
    # (b) start
    if lowest != 1:
        v.add("T3-START", "stream %s: lowest seq is %d, expected 1" % (sid, lowest))
    else:
        for r in by_seq[1]:
            if r["prev_hash"] != ZERO_HASH:
                v.add("T3-START", "stream %s seq 1: prev_hash is not the zero value" % sid)
    # (c) gaps
    missing = [s for s in range(1, highest + 1) if s not in by_seq]
    und = [s for s in missing if s not in declared_seqs]
    if und:
        v.add("T3-GAP", "stream %s: missing seq %s" % (sid, ", ".join(str(s) for s in und)))
        v.undeclared.append("stream %s: missing seq %s" % (sid, ", ".join(str(s) for s in und)))
    # (d) forks
    for s in seqs:
        if len(by_seq[s]) > 1:
            v.add("T3-FORK", "stream %s seq %d: %d records share this seq" % (sid, s, len(by_seq[s])))
    # (e) links: each record must link to the record at seq minus one; where that seq is
    # absent, to the nearest lower record present (the walk's predecessor).
    for idx, s in enumerate(seqs):
        if idx == 0:
            continue
        pred = seqs[idx - 1]
        pred_hashes = {p["hash"] for p in by_seq[pred]}
        for r in by_seq[s]:
            if r["prev_hash"] not in pred_hashes:
                v.add("T3-LINK", "stream %s seq %d: prev_hash does not match the record at seq %d" % (sid, s, pred))
    # (f) tail
    tds = [r for r in rs if r["type"] == "teardown"]
    events = [r for r in rs if r["type"] == "event"]
    if not tds:
        v.add("T3-OPEN", "stream %s: no teardown; tail completeness not established" % sid)
        return
    if len(tds) > 1:
        v.add("T3-TAIL", "stream %s: %d teardown records" % (sid, len(tds)))
        return
    td = tds[0]
    max_event = max((e["seq"] for e in events), default=0)
    if td["seq"] != highest or any(e["seq"] > td["seq"] for e in events):
        v.add("T3-TAIL", "stream %s: records follow the teardown at seq %d" % (sid, td["seq"]))
    elif td["last_seq"] != max_event or td["seq"] != td["last_seq"] + 1:
        v.add("T3-TAIL", "stream %s: teardown at seq %d carries last_seq %d; highest event seq is %d"
              % (sid, td["seq"], td["last_seq"], max_event))


# T14a

CP_KEYS = {"checkpoint_id", "received", "accepted", "dropped", "policy"}
CP_OPTIONAL = {"provenance"}
PROVENANCE = ("SOURCE-LOCAL", "INDEPENDENTLY-RECONCILED", "UNVERIFIED")


def run_t14a(top, decl, v, reading):
    allowed_top = {"declaration", "checkpoints"} | ({"records"} if reading == "C" else set())
    if not isinstance(top, dict) or not ({"declaration", "checkpoints"} <= set(top) <= allowed_top):
        v.add("INPUT-MALFORMED", "top level must hold 'declaration' and 'checkpoints'")
        return
    cps = top["checkpoints"]
    if not isinstance(cps, list):
        v.add("T14A-MALFORMED", "'checkpoints' is not a list")
        return
    if not cps:
        v.add("T14A-NONE", "input holds no checkpoints")
        return
    optional = CP_OPTIONAL | ({"upto_seq"} if reading == "C" else set())
    seen = set()
    good = []
    for i, c in enumerate(cps):
        cid = c.get("checkpoint_id") if isinstance(c, dict) else None
        name = cid if isinstance(cid, str) and cid else "number %d in file" % (i + 1)
        ok = (isinstance(c, dict) and CP_KEYS <= set(c) <= CP_KEYS | optional
              and isinstance(cid, str) and cid
              and all(is_nonneg_int(c[k]) for k in ("received", "accepted", "dropped"))
              and c["policy"] in ("fail-open", "fail-closed")
              and c.get("provenance", "SOURCE-LOCAL") in PROVENANCE
              and (reading != "C" or is_nonneg_int(c.get("upto_seq"))))
        if ok and cid in seen:
            v.add("T14A-MALFORMED", "checkpoint %s: checkpoint_id used more than once" % cid)
            continue
        if not ok:
            v.add("T14A-MALFORMED", "checkpoint %s: missing, non-integer, negative or out-of-range counter, or a field outside vector profile v0" % name)
            continue
        seen.add(cid)
        good.append(c)
    fail_mode = decl["fail_mode"] if decl else None
    for c in good:
        cid = c["checkpoint_id"]
        r, a, d = c["received"], c["accepted"], c["dropped"]
        prov = c.get("provenance", "SOURCE-LOCAL")
        label = prov if prov != "INDEPENDENTLY-RECONCILED" else "INDEPENDENTLY-RECONCILED (claimed in input, not checked)"
        v.counters.append("Checkpoint %s: received %d, accepted %d, dropped %d, policy %s, provenance %s"
                          % (cid, r, a, d, c["policy"], label))
        diff = r - (a + d)
        if diff != 0:
            if diff > 0:
                v.add("T14A-IMBALANCE", "checkpoint %s: received %d, accepted %d, dropped %d, difference %d (uncounted loss)"
                      % (cid, r, a, d, diff))
                v.undeclared.append("checkpoint %s: uncounted drop of %d" % (cid, diff))
            else:
                v.add("T14A-IMBALANCE", "checkpoint %s: received %d, accepted %d, dropped %d, difference %d (padding: accepted plus dropped exceed received; not a gap)"
                      % (cid, r, a, d, diff))
        if fail_mode and c["policy"] != fail_mode:
            v.add("T14A-POLICY", "checkpoint %s: policy %s differs from declared fail mode %s" % (cid, c["policy"], fail_mode))
        if prov == "UNVERIFIED":
            v.add("T14A-UNVERIFIED", "checkpoint %s: counters labelled UNVERIFIED; a check resting on them can FAIL but never PASS" % cid)
        if d > 0 and c["policy"] == "fail-open" and fail_mode == "fail-open" and diff == 0:
            v.declared.append("DECLARED GAP: drops counted under fail-open policy (checkpoint %s, dropped %d)" % (cid, d))
            if reading == "D":
                v.add("DECLARED-GAP", "checkpoint %s: %d drops counted under fail-open; Reading D reports this scope as HOLD" % (cid, d))
        if d > 0 and c["policy"] == "fail-closed" and diff == 0:
            v.notes.append("dropped greater than zero under fail-closed: T14b not run (checkpoint %s)" % cid)
    if reading == "B":
        for prev, cur in zip(good, good[1:]):
            for k in ("received", "accepted", "dropped"):
                if cur[k] < prev[k]:
                    v.add("T14A-REGRESS", "checkpoint %s: %s %d is lower than %d at checkpoint %s"
                          % (cur["checkpoint_id"], k, cur[k], prev[k], prev["checkpoint_id"]))
    if reading == "C":
        recs = top.get("records")
        if not isinstance(recs, list) or not all(isinstance(x, dict) and is_nonneg_int(x.get("seq")) for x in recs):
            v.add("INPUT-MALFORMED", "Reading C needs a 'records' list with integer seq values")
            return
        for c in good:
            n = sum(1 for x in recs if x["seq"] <= c["upto_seq"])
            if n != c["accepted"]:
                v.add("T14A-CHAIN", "checkpoint %s: accepted %d but the chain holds %d records up to seq %d"
                      % (c["checkpoint_id"], c["accepted"], n, c["upto_seq"]))


# Output

def render(test, evidence_hash, decl_line, v, reading):
    res = v.result()
    out = [decl_line,
           "Clock grade: no ordering claims made by this test",
           "Sampling: none, every record checked",
           "Test: %s | Suite: %s%s | Evidence SHA-256: %s"
           % (test, SUITE, (" | Alternative reading %s, not the primary reading" % reading) if reading else "", evidence_hash),
           "Profile: F (vector profile v0 assumes sequence numbers assigned at the source)",
           "Result: %s" % res]
    codes = sorted({c for c, _ in v.findings})
    out.append("Reason codes (proposed, not normative): %s" % (", ".join(codes) if codes else "none"))
    for c in codes:
        for code, detail in v.findings:
            if code == c:
                out.append("  %s: %s" % (code, detail))
    out.extend(v.counters)
    out.extend(v.notes)
    if test == "T14a" and res == "PASS":
        out.append("counters are SOURCE-LOCAL: arithmetic on numbers the capture point produced; not independently reconciled")
    out.append("Declared gaps: %s" % ("none" if not v.declared else ""))
    out[-1] = out[-1].rstrip()
    out.extend("  " + x for x in v.declared)
    out.append("Undeclared gaps: %s" % ("none" if not v.undeclared else ""))
    out[-1] = out[-1].rstrip()
    out.extend("  UNDECLARED GAP: " + x for x in v.undeclared)
    out.append("Coverage windows (C22 item 6): not run")
    out.append("T14e-SHADOW: not run")
    out.append("Verifier disclosure: no fee, volunteer run, no financial relationship with the operator")
    out.append(V24)
    out.append("T6c: OPEN (demo time sources sign the operator clock)")
    out.extend(SCOPE)
    return res, "\n".join(out) + "\n"


def main(argv):
    if len(argv) not in (3, 5) or argv[1] not in ("T3", "T14a"):
        sys.stderr.write("usage: verify.py T3|T14a input.json [--reading B|C|D]\n")
        return 3
    test, path = argv[1], argv[2]
    reading = None
    if len(argv) == 5:
        if argv[3] != "--reading" or argv[4] not in ("B", "C", "D") or test != "T14a":
            sys.stderr.write("alternative readings B, C and D apply to T14a only\n")
            return 3
        reading = argv[4]
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        sys.stderr.write("cannot read input file: %s\n" % e)
        return 3
    evidence_hash = hashlib.sha256(raw).hexdigest()
    v = Verdict()
    top = None
    try:
        top = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_hook,
                         parse_float=Float, parse_constant=Float)
    except DupKey as e:
        v.add("INPUT-DUPKEY", "duplicate key %r; vector profile v0 rejects duplicate keys" % str(e))
    except (ValueError, UnicodeDecodeError):
        v.add("INPUT-UNPARSEABLE", "input is not valid UTF-8 JSON")
    except RecursionError:
        v.add("INPUT-UNPARSEABLE", "input is nested too deeply to read")
    decl_line = "Declaration: not read (input rejected); T1b: not run"
    if top is not None:
        strings = []
        walk_strings(top, "", strings)
        for p, s in strings:
            if any(0xD800 <= ord(ch) <= 0xDFFF for ch in s):
                v.add("INPUT-MALFORMED", "string at %s holds a lone surrogate" % (p or "/"))
            elif unicodedata.normalize("NFC", s) != s:
                v.add("T2-NFC", "string at %s is not NFC; rejected, not normalised" % (p or "/"))
        if not any(c == "INPUT-MALFORMED" for c, _ in v.findings):
            decl, decl_line = check_declaration(top, v)
            if test == "T3":
                run_t3(top, decl, v)
            else:
                run_t14a(top, decl, v, reading)
    res, text = render(test, evidence_hash, decl_line, v, reading)
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stdout.write(text)
    return {"PASS": 0, "FAIL": 1, "HOLD": 2}[res]


if __name__ == "__main__":
    try:
        code = main(sys.argv)
    except RecursionError:
        sys.stderr.write("internal error: input nested too deeply to check; no verdict\n")
        code = 3
    except Exception as e:  # never let a crash exit with 1, which means FAIL
        sys.stderr.write("internal error, no verdict: %s: %s\n" % (type(e).__name__, e))
        code = 3
    sys.exit(code)
