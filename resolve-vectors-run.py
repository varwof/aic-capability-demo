#!/usr/bin/env python3
"""Run the CLC-v1 §8.5 Resolve vectors (rev CLC-1.11) against clc_semantics."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clc_semantics import resolve  # noqa: E402


def canonical_reason(s):
    if not s:
        return ""
    return s.split(":", 1)[0]


def main():
    path = os.environ.get("CLC_RESOLVE_VECTORS")
    if not path:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "capability", "data", "_vectors", "clc-v1", "resolve-vectors.json")
    with open(path) as f:
        vectors = json.load(f)

    passed = failed = 0
    print("%-12s %-10s %-24s %-24s %s" % ("ID", "GOT", "EXP-REASON", "GOT-REASON", "RESULT"))
    print("-" * 96)
    for v in vectors:
        got = resolve(v["decision"], v.get("resolutions", []), v.get("now"))
        exp_reason = canonical_reason(v["expect"].get("reason"))
        got_reason = canonical_reason(got.get("reason"))
        ok = got["verdict"] == v["expect"]["verdict"] and got_reason == exp_reason
        if ok and "unresolved" in v["expect"]:
            # exact manifest order (UTF-8 byte sequence, §7.1/§8.4; CLC-1.15)
            ok = got.get("unresolved", []) == v["expect"]["unresolved"]
        if ok:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FAIL (got %s / %s / %s)" % (got["verdict"], got_reason, got.get("unresolved", []))
        print("%-12s %-10s %-24s %-24s %s" % (v["id"], got["verdict"], exp_reason, got_reason, status))
    print("-" * 96)
    print("Total: %d | Pass: %d | Fail: %d" % (len(vectors), passed, failed))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
