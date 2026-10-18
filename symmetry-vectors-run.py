#!/usr/bin/env python3
"""Run the symmetry corpus (authorization + action identity) in Python.

The evidence-block vectors are evaluated with evidence_semantics.py (four
constraint types plus the AND/OR requirement grammar).
"""

from __future__ import annotations

import json
import os
import sys

import clc_semantics as clc
import evidence_semantics as ev

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("CLC_CAPABILITY_DIR", os.path.join(HERE, "..", "capability"))
VECTORS = os.environ.get("CLC_SYMMETRY_VECTORS", os.path.join(CAP, "data", "_vectors", "clc-v1", "symmetry-vectors.json"))


def action_match(v, op_params):
    t = v["type"]
    suite = v["suite"]
    if v.get("observed_type") and v["observed_type"] != t["name"]:
        return "INDETERMINATE"
    if v.get("observed_suite") and v["observed_suite"] != suite:
        return "INDETERMINATE"
    try:
        op_id = clc.compute_action_id(t["name"], t["material"], suite, op_params)
        obs_id = clc.compute_action_id(t["name"], t["material"], suite, v["observed"])
    except Exception:
        return "action_not_matchable"
    return "MATCH" if op_id == obs_id else "NOT_EQUIVALENT"


def main() -> int:
    with open(VECTORS, encoding="utf-8") as f:
        vectors = json.load(f)
    ran = skipped = failures = 0
    print("CLC symmetry corpus")
    print("-" * 96)
    for v in vectors:
        ran += 1
        auth = v["authorization"]
        if auth.get("chain"):
            dec = clc.authorize_with_chain(auth["grants"], auth["operation"])
        else:
            dec = clc.authorize_set(auth["grants"], auth["operation"])
        ok = dec.get("verdict") == auth["verdict"] and (
            not auth.get("reason") or dec.get("reason", "").startswith(auth["reason"]))
        if v.get("no_evidence"):
            got = "NO_EVIDENCE"
        else:
            got = action_match(v, auth["operation"].get("params", {}))
        ok = ok and got == v["expect"]["match"]
        shown = got
        if "evidence" in v:
            e = v["evidence"]
            ctx = e.get("context", {})
            facts = e.get("facts", [])
            try:
                if "requirement" in e:
                    verdict, reason = ev.evaluate_requirement(e["requirement"], facts, ctx)
                else:
                    verdict, reason = ev.evaluate_constraint(e["constraint"], facts, ctx)
                ok = ok and verdict == e["verdict"] and (
                    not e.get("reason") or reason.startswith(e["reason"]))
                shown = got + " / " + verdict
            except Exception as ex:
                ok = ok and bool(e.get("error")) and str(ex).startswith(e["error"])
                shown = got + " / error"
        if not ok:
            failures += 1
        print(f"{v['id']:<7} auth={dec.get('verdict','?'):<16} match={shown:<28} {'PASS' if ok else 'FAIL'}")
    print("-" * 96)
    print(f"Ran: {ran} | Skipped (evidence side): {skipped} | Fail: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
