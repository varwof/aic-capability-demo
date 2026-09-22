#!/usr/bin/env python3
"""
CLC-D containment forward-closure property runner.

For each case (parent P, child C) in containment-property-cases.json and every
operation o in the shared `ops` sample:
  * Contains(P, C) MUST NOT raise, and
  * Contains(P, C) true AND Entails(C, o) true  ==>  Entails(P, o) true.

Usage:
  python3 contain-property-run.py [--all]
"""
import json
import os
import sys

from clc_semantics import contains, entails


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
    for c in cases:
        try:
            r = contains(c["parent"], c["child"])
        except Exception as e:  # noqa: BLE001 — the property is "never raises"
            raised += 1
            print("RAISED %s: %r" % (c["id"], e))
            continue
        if r.get("contains"):
            contained_pairs += 1
        for o in ops:
            checked += 1
            if not entails(c["child"], o)["entails"]:
                continue
            if r.get("contains") and not entails(c["parent"], o)["entails"]:
                violations += 1
                if violations <= 5:
                    print("VIOLATION %s parent=%s child=%s op=%s" % (
                        c["id"], json.dumps(c["parent"]), json.dumps(c["child"]), json.dumps(o)))

    print("property: %d cases, %d contained pairs, %d op-checks, %d raises, %d violations" % (
        len(cases), contained_pairs, checked, raised, violations))
    return 1 if (violations or raised) else 0


if __name__ == "__main__":
    sys.exit(main())