#!/usr/bin/env python3
"""
CLC-D containment forward-closure property runner.

For each case (parent P, child C) in containment-property-cases.json and every
operation o in the shared `ops` sample:
  * Contains(P, C) MUST NOT raise, and
  * Contains(P, C) true AND Entails(C, o) true  ==>  Entails(P, o) true.

Also asserts antisymmetry on semantic equivalence classes (CL 13.10.8, core
§13.3): Contains(P, C) and Contains(C, P) both true is allowed only when P and
C fall in the same semantic class (same id, params with `params:{}` ≡ absent),
never across two distinct classes.

Usage:
  python3 contain-property-run.py [--all]
"""
import json
import os
import sys

from clc_semantics import canonical_json, contains, entails


def semantic_class(g):
    params = g.get("params")
    if params in (None, {}):
        params = None
    return canonical_json({"id": g["id"], "params": params})


def main():
    path = os.environ.get("CLC_D_PROPERTY_CASES") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "capability", "data", "_vectors", "clc-d",
        "containment-property-cases.json")
    with open(path) as f:
        doc = json.load(f)

    ops = doc["ops"]
    cases = doc["cases"]
    show_all = "--all" in sys.argv

    checked = 0
    contained_pairs = 0
    violations = 0
    raised = 0
    antisym_mutual = 0
    antisym_violations = 0
    for c in cases:
        try:
            r = contains(c["parent"], c["child"])
        except Exception as e:  # noqa: BLE001 — the property is "never raises"
            raised += 1
            print("RAISED %s: %r" % (c["id"], e))
            continue
        if r.get("contains"):
            contained_pairs += 1
        if r.get("contains") and contains(c["child"], c["parent"]).get("contains"):
            antisym_mutual += 1
            if semantic_class(c["parent"]) != semantic_class(c["child"]):
                antisym_violations += 1
                if antisym_violations <= 5:
                    print("ANTISYM VIOLATION %s parent=%s child=%s" % (
                        c["id"], json.dumps(c["parent"]), json.dumps(c["child"])))
        for o in ops:
            checked += 1
            if not entails(c["child"], o)["entails"]:
                continue
            if r.get("contains") and not entails(c["parent"], o)["entails"]:
                violations += 1
                if violations <= 5:
                    print("VIOLATION %s parent=%s child=%s op=%s" % (
                        c["id"], json.dumps(c["parent"]), json.dumps(c["child"]), json.dumps(o)))

    print("property: %d cases, %d contained pairs, %d op-checks, %d raises, %d violations, "
          "%d mutual pairs, %d antisymmetry violations" %
          (len(cases), contained_pairs, checked, raised, violations,
           antisym_mutual, antisym_violations))
    return 1 if (violations or raised or antisym_violations) else 0


if __name__ == "__main__":
    sys.exit(main())