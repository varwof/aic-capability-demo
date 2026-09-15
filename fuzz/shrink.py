#!/usr/bin/env python3
"""CLC differential fuzz: finding minimizer (ddmin over raw structure).

Usage: shrink.py <cases.jsonl> <py.jsonl> <ts.jsonl> <go.jsonl> <case_id>

Reproduces the divergence recorded for <case_id> in the compare output, then
minimizes the *raw* params text while the divergence class (and its impl set /
verdict-reason tuple) still reproduces.  Strategy is axis-aware:
  - object-ish raws (a01/a02/a05/a06/a09): ddmin over the key set
  - array raws (a07/a08): ddmin over the element spine + strip array wrappers
  - number raws (a04): truncate digits on the offending literal
  - string raws (a03): shorten value / strip surrounding object keys

Every candidate is re-evaluated by actually re-running all three runners and
re-classifying (compare logic), so the report only contains genuinely
reproducing minimals.

Emits one JSON object:
  {"id", "axis", "raw" (original), "raw_min" (minimal), "note", "class",
   "signature", "steps", "impls"}
"""

import json
import os
import subprocess
import sys
import tempfile

FUZZ = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(FUZZ)
RUNNERS = {
    "py": [sys.executable, os.path.join(FUZZ, "run_py.py")],
    "ts": ["npx", "--yes", "tsx", os.path.join(FUZZ, "run_ts.ts")],
    "go": ["go", "run", os.path.join(REPO, "..", "register", "semantics", "fuzz_runner")],
}


def load(path):
    out = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line)
                out[r["id"]] = r
    return out


def run_all(cases_path, tmpdir):
    """Run the three impls over cases file; return {impl: {id: row}}."""
    out = {}
    for name, cmd in RUNNERS.items():
        rp = os.path.join(tmpdir, "res_%s.jsonl" % name)
        try:
            with open(rp, "wb") as fh:
                subprocess.run(cmd + [cases_path], cwd=REPO, check=True,
                               stdout=fh, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            with open(rp, "w") as fh:
                pass
        out[name] = load(rp)
    return out


def signature(cid, impls, compare_classes):
    """The divergence that makes this finding; None if not reproduced."""
    for cls in ("cross_impl", "cross_path", "unstable"):
        for item in compare_classes.get(cls, []):
            if item["id"] != cid:
                continue
            if cls == "cross_impl":
                return (cls, item["path"], tuple(sorted(
                    (k, tuple(v)) for k, v in item["keys"].items())))
            if cls == "cross_path":
                return (cls, item["impl"], item["raw"], item["decoded"])
            return (cls, tuple(item["impls"]), tuple(
                sorted((k, str(v)) for k, v in item["detail"].items())))
    return None


def classify(cases, impls):
    """Minimal re-implementation of compare.py's grouping over given impls."""
    cross_impl, cross_path, unstable = [], [], []
    for cid in cases:
        rows = {name: impls[name].get(cid) for name in impls}
        crashed = [n for n, r in rows.items() if r is None or r.get("error")]
        if crashed:
            unstable.append({"id": cid, "impls": crashed,
                             "detail": {n: (rows[n] or {}).get("error") or "missing"
                                        for n in crashed}})
            continue
        for name, r in rows.items():
            k1, k2 = (r["raw_path"]["verdict"], r["raw_path"]["reason"]), \
                     (r["decoded_path"]["verdict"], r["decoded_path"]["reason"])
            if k1 != k2:
                cross_path.append({"id": cid, "impl": name})
        for p in ("raw_path", "decoded_path"):
            keys = {n: (rows[n][p]["verdict"], rows[n][p]["reason"]) for n in impls}
            if len(set(keys.values())) > 1:
                cross_impl.append({"id": cid, "path": p, "keys": keys})
    return {"cross_impl": cross_impl, "cross_path": cross_path,
            "unstable": unstable}


def ddmin(inputs, pred):
    """Delta-debugging: return lexicographically-small truthy member removing
    1-config granularity greedily (1-minimal is enough for a shrink report)."""
    cur = list(inputs)
    n = 2
    while len(cur) >= 2:
        chunks = [cur[i * len(cur) // n: (i + 1) * len(cur) // n]
                  for i in range(n)]
        reduced = False
        for grp in range(n):
            cand = cur[:grp * len(cur) // n] + cur[(grp + 1) * len(cur) // n:]
            if pred(cand):
                cur = cand
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(cur):
                break
            n = min(len(cur), n * 2)
    return cur


def parse(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None


def serialize(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def strip_wrappers(raw):
    v = parse(raw)
    depth = 0
    while isinstance(v, list) and len(v) == 1:
        v = v[0]
        depth += 1
    return v, depth


def minimize_case(case, orig_sig, impls, cases, tmpdir):
    raw = case.get("raw", "")
    axis = case.get("axis", "unknown")
    op_id = case["op_id"]
    grant = case.get("grant")
    steps = 0
    best = raw

    def check(candidate_raw):
        nonlocal steps
        steps += 1
        if candidate_raw == raw:
            return False
        c = cases[case["id"]].copy()
        if "raw_b64" in c:
            c.pop("raw_b64")
        c["raw"] = candidate_raw
        cp = os.path.join(tmpdir, "cand.jsonl")
        with open(cp, "w") as fh:
            fh.write(json.dumps(c) + "\n")
        r_impls = run_all(cp, tmpdir)
        cc = classify({case["id"]: c}, r_impls)
        return signature(case["id"], impls, cc) == orig_sig

    v, depth = strip_wrappers(raw)

    # 1) strip array wrappers (a07/a08 deep-spine cases)
    if depth > 0:
        for d in range(depth, 0, -1):
            inner = v
            for _ in range(d):
                inner = [inner]
            if check(serialize(inner)):
                best = serialize(inner)
                raw = best

    cur = parse(raw)
    if isinstance(cur, dict) and axis in ("a01", "a02", "a05", "a06", "a09"):
        keys = list(cur.keys())
        kept = ddmin(keys, lambda ks: check(serialize({k: cur[k] for k in ks})))
        if kept != keys and kept:
            cand = serialize({k: cur[k] for k in kept})
            raw = cand
            best = cand

    # 2) number-truncation for a04
    if axis == "a04":
        import re
        for m in re.finditer(r"-?\d+\.?\d*[eE]?-?\d*", raw):
            lit = m.group(0)
            for cut in range(1, len(lit)):
                cand = raw[:m.start()] + lit[:cut] + raw[m.end():]
                if check(cand):
                    best = cand
                    break

    # 3) string de-trucation for a03
    if axis == "a03":
        import re
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', raw):
            val = m.group(1)
            for cut in list(range(len(val) // 2, 0, -1)) + [1]:
                repl = '"' + val[:cut] + '"'
                cand = raw[:m.start()] + repl + raw[m.end():]
                if check(cand):
                    best = cand
                    break

    return best, steps


def main():
    if len(sys.argv) < 6:
        sys.stderr.write(
            "usage: shrink.py <cases.jsonl> <py.jsonl> <ts.jsonl> <go.jsonl> <case_id>\n")
        return 2
    cases = load(sys.argv[1])
    impls = {"py": load(sys.argv[2]), "ts": load(sys.argv[3]),
             "go": load(sys.argv[4])}
    cid = sys.argv[5]
    if cid not in cases:
        sys.stderr.write("case %s not found\n" % cid)
        return 2
    case = cases[cid]

    cc = classify({cid: case}, impls)
    sig = signature(cid, impls, cc)
    if sig is None:
        sys.stderr.write("case %s: no divergence in provided results\n" % cid)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        raw_min, steps = minimize_case(case, sig, impls, cases, tmp)
        print(json.dumps({
            "id": cid,
            "axis": case.get("axis", "unknown"),
            "op_id": case["op_id"],
            "grant": case.get("grant"),
            "raw": case.get("raw", ""),
            "raw_min": raw_min,
            "note": case.get("note", ""),
            "signature": [sig[0], list(sig[1:])],
            "reduced_bytes": len(case.get("raw", "")) - len(raw_min),
            "steps": steps,
        }, indent=1, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())