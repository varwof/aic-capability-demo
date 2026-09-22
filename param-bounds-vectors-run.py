#!/usr/bin/env python3
"""
CLC-v1 §6.5 extended parameter-bound vectors runner (rev CLC-1.10) - reads
param-bounds-vectors.json and runs them against the Python entails().

Asserts BOTH the verdict and the resolved reason code (canonical, code before
the first ':').  kind=param-defaults applies the scheme-default rule first.
"""
import json
import os
import sys

from clc_semantics import entails, materialize_defaults


def canonical_reason(s):
    if not s:
        return ""
    return s.split(":", 1)[0] if ":" in s else s


def main():
    path = os.environ.get("CLC_PARAM_BOUNDS_VECTORS") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "capability", "data", "_vectors", "clc-v1", "param-bounds-vectors.json")
    with open(path) as f:
        vectors = json.load(f)

    pass_count = 0
    fail_count = 0
    for v in vectors:
        grant = v.get("grant") or {}
        op = v.get("request") or {}
        if v["kind"] == "param-defaults":
            op = materialize_defaults(grant, op, v.get("scheme_defaults"))
        r = entails(grant, op)
        got = "allow" if r["entails"] else "deny"
        got_reason = canonical_reason(r.get("reason", ""))
        want = v["expect"]["verdict"]
        want_reason = v["expect"].get("reason") or ""
        ok = got == want and got_reason == want_reason
        if ok:
            pass_count += 1
        else:
            fail_count += 1
            print("%-10s FAIL want=%s/%s got=%s/%s derivation=%s" % (
                v["id"], want, want_reason, got, got_reason, v["derivation"]))

    print("Total: %d | Pass: %d | Fail: %d" % (len(vectors), pass_count, fail_count))
    return 1 if fail_count else 0


if __name__ == "__main__":
    sys.exit(main())
