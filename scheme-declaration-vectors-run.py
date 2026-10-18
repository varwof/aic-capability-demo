#!/usr/bin/env python3
"""Run the shared valid/invalid scheme-declaration corpus."""

from __future__ import annotations

import json
import os
import sys

import scheme_decl

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("CLC_CAPABILITY_DIR", os.path.join(HERE, "..", "capability"))
VECTORS = os.environ.get("CLC_SCHEME_DECLARATION_VECTORS", os.path.join(CAP, "data", "_vectors", "clc-v1", "scheme-declaration-vectors.json"))


def main() -> int:
    with open(VECTORS, encoding="utf-8") as f:
        cases = json.load(f)
    failures = 0
    print("CLC scheme declaration corpus")
    print("-" * 96)
    for c in cases:
        try:
            scheme_decl.validate(c["declaration"])
            got, code = "accept", ""
        except scheme_decl.DeclarationError as e:
            got, code = "reject", e.code
        ok = got == c["expect"] and (got == "accept" or not c.get("code") or code == c["code"])
        if not ok:
            failures += 1
        print(f"{c['id']:<7} want {c['expect']:<7} got {got:<7} {code:<28} {'PASS' if ok else 'FAIL'}")
    print("-" * 96)
    print(f"Total: {len(cases)} | Pass: {len(cases)-failures} | Fail: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
