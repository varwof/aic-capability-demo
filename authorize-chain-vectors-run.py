#!/usr/bin/env python3
"""Run the CLC-D §13.11 AuthorizeWithChain vectors (rev CLC-1.13)."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clc_semantics import authorize_with_chain  # noqa: E402


def canonical_reason(s):
    if not s:
        return ""
    return s.split(":", 1)[0]


def main():
    path = os.environ.get("CLC_AUTHORIZE_CHAIN_VECTORS")
    if not path:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "capability", "data", "_vectors", "clc-d", "authorize-chain-vectors.json")
    with open(path) as f:
        vectors = json.load(f)

    passed = failed = 0
    for v in vectors:
        got = authorize_with_chain(v["chain"], v.get("request", {}))
        exp_reason = canonical_reason(v["expect"].get("reason"))
        got_reason = canonical_reason(got.get("reason"))
        ok = got["verdict"] == v["expect"]["verdict"] and got_reason == exp_reason
        if ok and "unresolved" in v["expect"]:
            ok = sorted(got.get("unresolved", [])) == sorted(v["expect"]["unresolved"])
        if ok:
            passed += 1
        else:
            failed += 1
            print("%-8s FAIL want=%s/%s got=%s/%s/%s" % (
                v["id"], v["expect"]["verdict"], exp_reason, got["verdict"], got_reason, got.get("unresolved", [])))
    print("Total: %d | Pass: %d | Fail: %d" % (len(vectors), passed, failed))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
