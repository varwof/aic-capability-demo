#!/usr/bin/env python3
"""
CLC-D containment vectors runner - reads containment-vectors.json
(draft-wei-clc-ext-00 §7) and runs them against the Python contains().

Asserts BOTH contains and the resolved reason code (canonical, code before
the first ':').
"""
import json
import os
import sys

from clc_semantics import contains


def canonical_reason(s):
    if not s:
        return ""
    return s.split(":", 1)[0] if ":" in s else s


def main():
    path = os.environ.get("CLC_D_VECTORS") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "capability", "data", "_vectors", "clc-d", "containment-vectors.json")
    with open(path) as f:
        vectors = json.load(f)

    show_all = "--all" in sys.argv
    pass_count = 0
    fail_count = 0
    for v in vectors:
        r = contains(v["parent"], v["child"])
        got_contains = r["contains"]
        got_reason = canonical_reason(r.get("reason", ""))
        want_reason = v["expect"].get("reason") or ""
        ok = got_contains == v["expect"]["contains"] and (
            got_contains or not want_reason or got_reason == want_reason)
        if ok:
            pass_count += 1
            if show_all:
                print("%-14s contains=%-5s reason=%-24s derivation=%s" % (
                    v["id"], got_contains, got_reason, v["derivation"]))
        else:
            fail_count += 1
            print("%-14s FAIL  want.contains=%-5s want.reason=%s got.contains=%-5s got.reason=%s derivation=%s" % (
                v["id"], v["expect"]["contains"], want_reason, got_contains, got_reason, v["derivation"]))

    print("Total: %d | Pass: %d | Fail: %d" % (len(vectors), pass_count, fail_count))
    return 1 if fail_count else 0


if __name__ == "__main__":
    sys.exit(main())