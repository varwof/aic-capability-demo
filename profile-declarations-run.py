#!/usr/bin/env python3
"""Validate §13.8.1 obligations 6/7 declarations (Python mirror of the Go
runner): the declarations conform, they cover exactly the profiles the two
cross-walk corpora use, and every negative case produces its declared code."""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("CLC_CAPABILITY_DIR", os.path.join(HERE, "..", "capability"))
DECLS = os.environ.get("CLC_PROFILE_DECLARATIONS", os.path.join(CAP, "data", "_vectors", "clc-v1", "profile-declarations.json"))
CORPORA = [
    os.path.join(CAP, "data", "_vectors", "clc-v1", "crosswalk-vectors.json"),
    os.path.join(CAP, "data", "_vectors", "clc-d", "containment-crosswalk-vectors.json"),
]
BASES = {"definition-derived", "mechanically-checkable", "asserted"}


def issues(d: dict) -> list[str]:
    out: list[str] = []
    cc = d.get("chain_check") or {}
    basis = cc.get("basis", "")
    if cc.get("relies_on_transitivity"):
        if not cc.get("iterates_hops"):
            out.append("transitivity-without-iteration")
        if not basis:
            out.append("basis-missing")
        elif basis not in BASES:
            out.append("unknown-basis")
        elif basis == "definition-derived" and not (cc.get("domain") and cc.get("argument")):
            out.append("domain-or-argument-missing")
        elif basis == "mechanically-checkable" and not (cc.get("domain") and cc.get("procedure")):
            out.append("domain-or-procedure-missing")
    elif basis:
        out.append("basis-without-claim")
    ua = d.get("union_axis") or {}
    routed, fields = ua.get("routed_to"), ua.get("fields") or []
    if routed in ("constraint-union", "carrier-enforced"):
        if not fields:
            out.append("union-axis-fields-mismatch")
    elif routed == "not-applicable":
        if fields:
            out.append("union-axis-fields-mismatch")
    else:
        out.append("union-axis-misrouted")
    return out


def main() -> int:
    doc = json.load(open(DECLS, encoding="utf-8"))
    failures = 0
    print("CLC profile declarations (Python)")
    print("-" * 96)
    if doc.get("schema") != "clc-profile-declarations-v1":
        print("schema mismatch")
        return 1
    for d in doc.get("declarations", []):
        got = issues(d)
        ok = not got
        failures += 0 if ok else 1
        print(f"{d.get('profile','?'):<40} {'PASS' if ok else 'FAIL ' + ','.join(got)}")
    used = set()
    for p in CORPORA:
        for e in json.load(open(p, encoding="utf-8")):
            if e.get("profile"):
                used.add(e["profile"])
    declared = {d.get("profile") for d in doc.get("declarations", [])}
    cov = used == declared
    if not cov:
        failures += 1
    print(f"coverage: used={len(used)} declared={len(declared)} {'PASS' if cov else 'FAIL missing=' + str(sorted(used-declared)) + ' orphan=' + str(sorted(declared-used))}")
    for ex in doc.get("examples", []):
        got = issues(ex)
        ok = not got
        failures += 0 if ok else 1
        print(f"example {ex.get('profile','?'):<32} {'PASS' if ok else 'FAIL ' + ','.join(got)}")
    for nc in doc.get("negative_cases", []):
        got = issues(nc.get("declaration", {}))
        ok = nc.get("want") in got
        failures += 0 if ok else 1
        print(f"{nc.get('id','?'):<40} want {nc.get('want'):<32} {'PASS' if ok else 'FAIL ' + str(got)}")
    print("-" * 96)
    print(f"Failures: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
