#!/usr/bin/env python3
"""Run the structured OCMP offline corpus (12 vectors)."""

from __future__ import annotations

import json
import os
import sys

import ocmp

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = os.environ.get("CLC_CAPABILITY_DIR", os.path.join(HERE, "..", "capability"))
VECTORS = os.environ.get("CLC_OCMP_VECTORS", os.path.join(CAP, "data", "_vectors", "clc-v1", "offline-vectors.json"))


def main() -> int:
    with open(VECTORS, encoding="utf-8") as f:
        vectors = json.load(f)["vectors"]
    failures = 0
    print("OCMP offline profile")
    print("-" * 96)
    for v in vectors:
        verdict, reason = ocmp.evaluate(v["inputs"])
        ok = verdict == v["expect"]["verdict"] and reason == v["expect"]["reason"]
        if not ok:
            failures += 1
        want = f"{v['expect']['verdict']}/{v['expect']['reason']}"
        got = f"{verdict}/{reason}"
        print(f"{v['id']:<12} want {want:<28} got {got:<28} {'PASS' if ok else 'FAIL'}")
    print("-" * 96)
    print(f"Total: {len(vectors)} | Pass: {len(vectors)-failures} | Fail: {failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
