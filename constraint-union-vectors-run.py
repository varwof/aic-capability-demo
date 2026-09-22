#!/usr/bin/env python3
"""Run the CLC-v1 §7.1 ConstraintUnion vectors (rev CLC-1.12)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clc_semantics import constraint_union, CLCError  # noqa: E402


def main():
    path = os.environ.get("CLC_CONSTRAINT_UNION_VECTORS")
    if not path:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "capability", "data", "_vectors", "clc-v1", "constraint-union-vectors.json")
    with open(path) as f:
        vectors = json.load(f)

    passed = failed = 0
    for v in vectors:
        want_reason = v["expect"].get("reason")
        try:
            got = constraint_union(v["chain"])
            err = None
        except CLCError as e:
            got = None
            err = str(e)
        if want_reason:
            ok = err is not None and err.split(":", 1)[0] == want_reason
        else:
            ok = err is None and got == v["expect"]["union"]
        if ok:
            passed += 1
        else:
            failed += 1
            print("%-8s FAIL want=%s/%s got=%s err=%s" % (
                v["id"], v["expect"].get("union"), want_reason, got, err))
    print("Total: %d | Pass: %d | Fail: %d" % (len(vectors), passed, failed))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
